"""
Explicit resolution of WARC ``revisit`` records.

A revisit record does not carry its own payload: for the
``identical-payload-digest`` profile it points at another record that does.
This module resolves that reference (possibly through a chain of further
revisits), verifies every ``WARC-Payload-Digest`` on the chain against the
*stored* WARC payload bytes (not against de-chunked or decompressed text) and
exposes the body through the same HTTP de-chunking / decompression surface
that a regular ``response`` record provides.
"""

from collections import namedtuple

from warcio.exceptions import ArchiveLoadFailed
from warcio.recordbuilder import RecordBuilder
from warcio.recordloader import ArcWarcRecord, ArcWarcRecordLoader
from warcio.digestverifyingreader import (
    DigestChecker,
    DigestVerifyingReader,
    _parse_digest,
    _to_b32,
)
from warcio.limitreader import LimitReader
from warcio.utils import Digester


# ============================================================================
# Supported profiles: WARC 1.0 and 1.1 identical-payload-digest only.
# ============================================================================
SUPPORTED_REVISIT_PROFILES = (
    RecordBuilder.REVISIT_PROFILE,
    RecordBuilder.REVISIT_PROFILE_1_1,
)

DEFAULT_MAX_HOPS = 10

READ_SIZE = 16384


# ============================================================================
class RevisitResolutionError(ArchiveLoadFailed):
    """Raised when a revisit reference cannot be fully resolved.

    :ivar list[RevisitChainLink] chain: the reference chain walked before the
        failure, starting with the original revisit.
    """

    def __init__(self, reason, chain):
        self.chain = list(chain)
        msg = '{0}\nReference chain:\n{1}'.format(
            reason, format_chain(self.chain))
        super(RevisitResolutionError, self).__init__(msg)


# ============================================================================
class RevisitChainLink(
        namedtuple('RevisitChainLink',
                   ['record_id', 'target_uri', 'date', 'payload_digest',
                    'via', 'rec_type', 'profile'])):
    """One hop of a revisit reference chain.

    ``via`` is ``'record-id'`` when the hop was made through
    ``WARC-Refers-To`` or ``'uri-date'`` when it was made through the
    ``WARC-Refers-To-Target-URI`` / ``WARC-Refers-To-Date`` pair.
    """
    pass


# ============================================================================
class ResolvedRevisitRecord(ArcWarcRecord):
    """A revisit whose payload has been resolved to a concrete source record.

    The current record's own WARC metadata (``rec_headers``) and HTTP headers
    are retained unchanged; only ``raw_stream`` is replaced with the verified
    payload stream of the terminal source record.

    :ivar list[RevisitChainLink] source_chain: every record walked while
        resolving the revisit, including the original revisit and the
        terminal source.
    """

    def __init__(self, record, payload_stream, source_chain, digest_checker):
        super(ResolvedRevisitRecord, self).__init__(
            record.format, record.rec_type, record.rec_headers,
            payload_stream, record.http_headers, record.content_type,
            record.length,
            payload_length=record.payload_length,
            digest_checker=digest_checker)
        self.source_chain = list(source_chain)

    @property
    def verified(self):
        """True only if the whole payload was read and the digest matched."""
        return bool(self.digest_checker and self.digest_checker.passed)

    def verify(self):
        """Read the remaining payload and assert digest verification.

        Raises :class:`RevisitResolutionError` on mismatch or when the digest
        could not be fully checked; verification never passes silently.
        """
        stream = self.content_stream()
        while stream.read(READ_SIZE):
            pass

        if not self.verified:
            digest = self.source_chain[-1].payload_digest
            raise RevisitResolutionError(
                'payload digest verification failed or incomplete: '
                '{0}'.format(digest), self.source_chain)
        return True


# ============================================================================
class RevisitResolver(object):
    """Resolve revisit records with a caller supplied lookup callback.

    :param callable lookup: called as ``lookup(record_id=...)`` or as
        ``lookup(target_uri=..., date=...)``.  It must return an independent,
        binary, file-like stream positioned at the start of the target
        record, or ``None`` when no record is found.
    :param int max_hops: maximum number of reference hops followed before the
        chain is considered too deep.
    :param ArcWarcRecordLoader loader: record parser used for the streams
        returned by ``lookup``.
    """

    def __init__(self, lookup, max_hops=DEFAULT_MAX_HOPS, loader=None):
        if not callable(lookup):
            raise TypeError('lookup must be callable')
        self.lookup = lookup
        self.max_hops = max_hops
        self.loader = loader or ArcWarcRecordLoader(verify_http=False)
        self._streams = []

    # -- session / resource management -------------------------------------
    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def close(self):
        """Close every stream handed out by ``lookup`` still held open."""
        streams = list(self._streams)
        self._streams = []
        for stream in streams:
            try:
                stream.close()
            except Exception:
                pass

    # -- public entry point -------------------------------------------------
    def resolve(self, record):
        """Resolve ``record`` (a ``revisit``) to its payload source.

        :rtype: ResolvedRevisitRecord
        :raises RevisitResolutionError: on any failure; the error carries the
            reference chain walked so far.
        """
        chain = []
        try:
            return self._resolve(record, chain)
        except RevisitResolutionError:
            self.close()
            raise
        except Exception as exc:
            self.close()
            raise RevisitResolutionError(str(exc), chain)

    # -- internals ----------------------------------------------------------
    def _resolve(self, record, chain):
        self._check_revisit_profile(record, chain)

        current = record
        seen_ids = set()
        seen_uri_dates = set()

        while True:
            via = self._via_for(current, chain)
            chain.append(self._link_for(current, via))
            link = chain[-1]

            if link.record_id:
                if link.record_id in seen_ids:
                    raise RevisitResolutionError(
                        'cyclic revisit reference detected at record '
                        '{0}'.format(link.record_id), chain)
                seen_ids.add(link.record_id)
            else:
                cycle_key = (link.target_uri, link.date)
                if cycle_key in seen_uri_dates:
                    raise RevisitResolutionError(
                        'cyclic revisit reference detected at {0} '
                        '{1}'.format(link.target_uri, link.date), chain)
                seen_uri_dates.add(cycle_key)

            if not link.payload_digest:
                raise RevisitResolutionError(
                    'revisit record is missing WARC-Payload-Digest', chain)

            # chain length minus one is the number of hops about to be made
            if len(chain) > self.max_hops:
                raise RevisitResolutionError(
                    'revisit reference chain exceeded max depth of {0} '
                    'hops'.format(self.max_hops), chain)

            target_stream, target_via = self._lookup_target(current, chain)
            self._streams.append(target_stream)
            try:
                target = self.loader.parse_record_stream(target_stream)

                self._check_identity(target, current, target_via, chain)

                target_digest = target.rec_headers.get_header(
                    'WARC-Payload-Digest')
                self._check_declared_digest(link.payload_digest,
                                            target_digest, target, chain)

                if target.rec_type == 'revisit':
                    self._check_revisit_profile(target, chain)
                    self._drain(target.raw_stream)
                    self._close_owned(target_stream)
                    current = target
                    continue

                if target.rec_type != 'response':
                    raise RevisitResolutionError(
                        'revisit target must be a response or revisit '
                        'record, got: {0}'.format(target.rec_type), chain)

                # the terminal source is part of the provenance chain
                chain.append(self._link_for(target, target_via))

                payload_stream, digest_checker = \
                    self._verify_target_payload(target, target_digest, chain)

                # ownership of the callback stream moves to the resolved
                # record's payload stream; the resolver no longer owns it
                self._streams.remove(target_stream)
                return ResolvedRevisitRecord(record, payload_stream, chain,
                                             digest_checker)
            except Exception:
                self._close_owned(target_stream)
                raise

    def _lookup_target(self, current, chain):
        record_id = current.rec_headers.get_header('WARC-Refers-To')
        if record_id:
            stream = self._call_lookup(chain, record_id=record_id)
            if stream is None:
                raise RevisitResolutionError(
                    'lookup could not find record {0}'.format(record_id),
                    chain)
            return stream, 'record-id'

        target_uri = current.rec_headers.get_header(
            'WARC-Refers-To-Target-URI')
        date = current.rec_headers.get_header('WARC-Refers-To-Date')
        if target_uri and date:
            stream = self._call_lookup(chain, target_uri=target_uri,
                                       date=date)
            if stream is None:
                raise RevisitResolutionError(
                    'lookup could not find record for {0} at '
                    '{1}'.format(target_uri, date), chain)
            return stream, 'uri-date'

        raise RevisitResolutionError(
            'revisit has neither WARC-Refers-To nor a complete '
            'WARC-Refers-To-Target-URI / WARC-Refers-To-Date pair', chain)

    def _call_lookup(self, chain, **kwargs):
        try:
            return self.lookup(**kwargs)
        except RevisitResolutionError:
            raise
        except Exception as exc:
            raise RevisitResolutionError(
                'lookup callback failed: {0}'.format(exc), chain)

    def _check_identity(self, target, current, via, chain):
        if via == 'record-id':
            expected = current.rec_headers.get_header('WARC-Refers-To')
            actual = target.rec_headers.get_header('WARC-Record-ID')
            if actual != expected:
                raise RevisitResolutionError(
                    'target record identity mismatch: lookup for {0} '
                    'returned {1}'.format(expected, actual), chain)
            return

        expected_uri = current.rec_headers.get_header(
            'WARC-Refers-To-Target-URI')
        expected_date = current.rec_headers.get_header('WARC-Refers-To-Date')
        actual_uri = target.rec_headers.get_header('WARC-Target-URI')
        actual_date = target.rec_headers.get_header('WARC-Date')
        if actual_uri != expected_uri or actual_date != expected_date:
            raise RevisitResolutionError(
                'target record identity mismatch: lookup for {0} {1} '
                'returned {2} {3}'.format(expected_uri, expected_date,
                                          actual_uri, actual_date), chain)

    def _check_declared_digest(self, expected_digest, actual_digest, target,
                               chain):
        if not actual_digest:
            raise RevisitResolutionError(
                'target record {0} is missing '
                'WARC-Payload-Digest'.format(
                    target.rec_headers.get_header('WARC-Record-ID')), chain)

        if not digests_match(expected_digest, actual_digest):
            raise RevisitResolutionError(
                'payload digest mismatch: revisit declares {0}, target '
                'record declares {1}'.format(expected_digest,
                                             actual_digest), chain)

    def _verify_target_payload(self, target, payload_digest, chain):
        """Wrap the target payload so its stored WARC payload bytes are
        hashed and verification only succeeds once the full stream was read.
        """
        # payload_length excludes the parsed HTTP status line and headers,
        # matching the WARC definition of the payload digest
        payload_length = target.payload_length
        if payload_length is None or payload_length < 0:
            payload_length = target.length
        if payload_length is None or payload_length < 0:
            raise RevisitResolutionError(
                'target record has no usable Content-Length for payload '
                'verification', chain)

        try:
            algo, _ = _parse_digest(payload_digest)
            Digester(algo)
        except ValueError:
            raise RevisitResolutionError(
                'could not parse payload digest: {0}'.format(payload_digest),
                chain)

        digest_checker = DigestChecker()
        # target.raw_stream is already positioned after the HTTP headers and
        # limited to the remaining payload bytes.  Unwrap any LimitReader so
        # the verifying reader owns a single, correctly-sized limit: nesting
        # two LimitReaders over the same bytes makes them double-count.
        raw_stream = target.raw_stream
        remaining_limit = payload_length
        if isinstance(raw_stream, LimitReader):
            remaining_limit = raw_stream.limit
            raw_stream = raw_stream.stream

        stream = DigestVerifyingReader(
            raw_stream, remaining_limit, digest_checker,
            record_type=target.rec_type,
            payload_digest=payload_digest,
            # block digest covers HTTP headers + payload; this stream starts
            # after the HTTP headers, so only the payload digest is checkable
            block_digest=None,
            segment_number=target.rec_headers.get_header(
                'WARC-Segment-Number'))
        stream.begin_payload()
        return stream, digest_checker

    def _check_revisit_profile(self, record, chain):
        if record.rec_type != 'revisit':
            raise RevisitResolutionError(
                'expected a revisit record, got: {0}'.format(
                    record.rec_type), chain)

        profile = record.rec_headers.get_header('WARC-Profile')
        if profile not in SUPPORTED_REVISIT_PROFILES:
            raise RevisitResolutionError(
                'unsupported WARC revisit profile: {0}; only the WARC 1.0/1.1 '
                'identical-payload-digest profiles are '
                'supported'.format(profile), chain)

    @staticmethod
    def _via_for(current, chain):
        if not chain:
            return None
        if current.rec_headers.get_header('WARC-Refers-To'):
            return 'record-id'
        return 'uri-date'

    @staticmethod
    def _link_for(record, via):
        return RevisitChainLink(
            record_id=record.rec_headers.get_header('WARC-Record-ID'),
            target_uri=record.rec_headers.get_header('WARC-Target-URI'),
            date=record.rec_headers.get_header('WARC-Date'),
            payload_digest=record.rec_headers.get_header(
                'WARC-Payload-Digest'),
            via=via,
            rec_type=record.rec_type,
            profile=record.rec_headers.get_header('WARC-Profile'))

    def _close_owned(self, stream):
        try:
            self._streams.remove(stream)
        except ValueError:
            pass
        try:
            stream.close()
        except Exception:
            pass

    @staticmethod
    def _drain(stream):
        while stream.read(READ_SIZE):
            pass


# ============================================================================
def digests_match(digest_a, digest_b):
    """Compare two ``algo:value`` payload digests independently of the RFC
    3548 base encoding (base16, base32 or base64) used for the value."""
    try:
        algo_a, value_a = _parse_digest(digest_a)
        algo_b, value_b = _parse_digest(digest_b)
    except ValueError:
        return False

    if algo_a.lower() != algo_b.lower():
        return False

    # _to_b32 expects the base32-encoded length as its first argument
    raw_size = len(Digester(algo_a).digester.digest())
    b32_length = (raw_size * 8 + 4) // 5
    try:
        return _to_b32(b32_length, value_a) == _to_b32(
            b32_length, value_b)
    except Exception:
        return False


# ============================================================================
def format_chain(chain):
    lines = []
    for index, link in enumerate(chain):
        via = ' via {0}'.format(link.via) if link.via else ''
        lines.append(
            '  [{index}] {rec_type} {record_id} {uri} {date}{via}'.format(
                index=index, rec_type=link.rec_type,
                record_id=link.record_id or '<no-id>',
                uri=link.target_uri or '', date=link.date or '', via=via))
    return '\n'.join(lines)
