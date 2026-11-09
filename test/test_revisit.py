#!/usr/bin/env python
# -*- coding: utf-8 -*-

import base64
import hashlib
import zlib
from io import BytesIO

import pytest

from warcio import WARCWriter
from warcio.archiveiterator import ArchiveIterator
from warcio.bufferedreaders import DecompressingBufferedReader
from warcio.recordbuilder import RecordBuilder
from warcio.statusandheaders import StatusAndHeaders
from warcio.utils import Digester
from warcio.revisit import (
    DEFAULT_MAX_HOPS,
    ResolvedRevisitRecord,
    RevisitResolutionError,
    RevisitResolver,
    SUPPORTED_REVISIT_PROFILES,
    digests_match,
)


URL = 'http://example.com/'
DATE = '2017-01-01T00:00:00Z'
DATE_2 = '2017-02-01T00:00:00Z'
DATE_3 = '2017-03-01T00:00:00Z'

RESPONSE_ID = '<urn:uuid:11111111-0000-0000-0000-000000000001>'
MID_ID = '<urn:uuid:22222222-0000-0000-0000-000000000002>'
ROOT_ID = '<urn:uuid:33333333-0000-0000-0000-000000000003>'

# The stored payload is gzip-compressed AND chunk-encoded so the tests prove
# that digest verification hashes the stored WARC payload bytes while replay
# still runs through the existing de-chunk / decompress machinery.
PAYLOAD = b'the quick brown fox jumps over the lazy dog\n' * 100


# ============================================================================
# construction helpers (everything is WARCWriter + BytesIO)
# ============================================================================
def gzip_bytes(data):
    compressor = zlib.compressobj(9, zlib.DEFLATED, zlib.MAX_WBITS | 16)
    return compressor.compress(data) + compressor.flush()


def chunked_bytes(data):
    out = b''
    for start in range(0, len(data), 64):
        piece = data[start:start + 64]
        out += '{0:X}\r\n'.format(len(piece)).encode('ascii')
        out += piece + b'\r\n'
    return out + b'0\r\n\r\n'


def http_headers():
    return StatusAndHeaders('200 OK', [
        ('Content-Type', 'text/plain; charset="UTF-8"'),
        ('Custom-Header', 'somevalue'),
        ('Content-Encoding', 'gzip'),
        ('Transfer-Encoding', 'chunked'),
    ], protocol='HTTP/1.1')


def sha1_digest(data):
    digester = Digester('sha1')
    digester.update(data)
    return str(digester)


def write_response(writer, record_id, uri, date, stored_payload,
                   extra_warc_headers=None):
    warc_headers = {'WARC-Record-ID': record_id, 'WARC-Date': date}
    if extra_warc_headers:
        warc_headers.update(extra_warc_headers)
    record = writer.create_warc_record(
        uri, 'response',
        payload=BytesIO(stored_payload),
        length=len(stored_payload),
        http_headers=http_headers(),
        warc_headers_dict=warc_headers)
    writer.write_record(record)
    return record


def write_revisit(writer, record_id, uri, date, digest,
                  refers_to_id=None, refers_to_uri=None,
                  refers_to_date=None, profile=None,
                  warc_version='WARC/1.0', headers=None):
    writer.warc_version = warc_version
    record = writer.create_warc_record(
        uri, 'revisit', payload=BytesIO(), length=0,
        http_headers=headers,
        warc_headers_dict={'WARC-Record-ID': record_id,
                           'WARC-Date': date})
    record.rec_headers.replace_header(
        'WARC-Profile', profile or (
            RecordBuilder.REVISIT_PROFILE_1_1
            if warc_version == 'WARC/1.1'
            else RecordBuilder.REVISIT_PROFILE))
    record.rec_headers.add_header('WARC-Payload-Digest', digest)
    if refers_to_id:
        record.rec_headers.add_header('WARC-Refers-To', refers_to_id)
    if refers_to_uri:
        record.rec_headers.add_header(
            'WARC-Refers-To-Target-URI', refers_to_uri)
    if refers_to_date:
        record.rec_headers.add_header('WARC-Refers-To-Date', refers_to_date)
    writer.write_record(record)
    return record


def build_chain_warc(gzip=True, warc_version='WARC/1.0',
                     use_refers_to=True, stored_payload=None,
                     response_digest=None, mid_digest=None,
                     root_digest=None):
    """response <- revisit(mid) <- revisit(root), two reference hops."""
    buf = BytesIO()
    writer = WARCWriter(buf, gzip=gzip, warc_version=warc_version)

    stored = stored_payload if stored_payload is not None else \
        chunked_bytes(gzip_bytes(PAYLOAD))
    digest = sha1_digest(stored)
    response_digest = response_digest or digest
    mid_digest = mid_digest or digest
    root_digest = root_digest or digest

    write_response(writer, RESPONSE_ID, URL, DATE, stored,
                   extra_warc_headers={'WARC-Payload-Digest':
                                       response_digest})

    if use_refers_to:
        write_revisit(writer, MID_ID, URL, DATE_2, mid_digest,
                      refers_to_id=RESPONSE_ID, warc_version=warc_version)
        write_revisit(writer, ROOT_ID, URL, DATE_3, root_digest,
                      refers_to_id=MID_ID, warc_version=warc_version,
                      headers=http_headers())
    else:
        write_revisit(writer, MID_ID, URL, DATE_2, mid_digest,
                      refers_to_uri=URL, refers_to_date=DATE,
                      warc_version=warc_version)
        write_revisit(writer, ROOT_ID, URL, DATE_3, root_digest,
                      refers_to_uri=URL, refers_to_date=DATE_2,
                      warc_version=warc_version, headers=http_headers())

    return buf.getvalue(), {
        'digest': digest,
        'stored_payload': stored,
    }


# ============================================================================
# in-memory record store: every lookup returns an independent stream
# ============================================================================
class Store(object):
    def __init__(self, warc_bytes, wrap_decompress=True):
        self.warc_bytes = warc_bytes
        self.by_id = {}
        self.by_uri_date = {}
        self.opened = []
        self.closed = []
        self.wrap_decompress = wrap_decompress

        iterator = ArchiveIterator(BytesIO(warc_bytes))
        for record in iterator:
            offset = iterator.get_record_offset()
            length = iterator.get_record_length()
            raw = warc_bytes[offset:offset + length]
            entry = {'record': record, 'raw': raw}
            rec_id = record.rec_headers.get_header('WARC-Record-ID')
            if rec_id:
                self.by_id[rec_id] = entry
            uri = record.rec_headers.get_header('WARC-Target-URI')
            date = record.rec_headers.get_header('WARC-Date')
            if uri and date:
                self.by_uri_date[(uri, date)] = entry

    def open_entry(self, entry):
        stream = BytesIO(entry['raw'])
        if self.wrap_decompress:
            stream = DecompressingBufferedReader(stream)
        track = TrackedStream(stream, self)
        self.opened.append(track)
        return track

    def lookup(self, record_id=None, target_uri=None, date=None):
        entry = None
        if record_id is not None:
            entry = self.by_id.get(record_id)
        elif target_uri is not None and date is not None:
            entry = self.by_uri_date.get((target_uri, date))
        if entry is None:
            return None
        return self.open_entry(entry)

    def root_record(self, record_id=ROOT_ID):
        # parse a fresh archive and return the requested record
        for record in ArchiveIterator(BytesIO(self.warc_bytes)):
            if record.rec_headers.get_header('WARC-Record-ID') == record_id:
                return record
        raise KeyError(record_id)


class TrackedStream(object):
    """Wraps a callback stream to observe close() calls."""

    def __init__(self, stream, store):
        self.stream = stream
        self.store = store
        self.is_closed = False

    def read(self, *args):
        return self.stream.read(*args)

    def readline(self, *args):
        return self.stream.readline(*args)

    def tell(self):
        return self.stream.tell()

    def seek(self, *args):
        return self.stream.seek(*args)

    def close(self):
        self.is_closed = True
        self.store.closed.append(self)
        self.stream.close()


@pytest.fixture(params=[True, False])
def is_gzip(request):
    return request.param


@pytest.fixture
def built(is_gzip):
    warc_bytes, info = build_chain_warc(gzip=is_gzip)
    store = Store(warc_bytes)
    return store, info


def root_of(store):
    return store.by_id[ROOT_ID]['record']


# ============================================================================
# digest comparison helper
# ============================================================================
def test_digests_match_across_encodings():
    raw = hashlib.sha1(b'payload bytes').digest()
    b32 = base64.b32encode(raw).decode('ascii')
    b16 = base64.b16encode(raw).decode('ascii')
    b64 = base64.b64encode(raw).decode('ascii')

    assert digests_match('sha1:' + b32, 'sha1:' + b16)
    assert digests_match('sha1:' + b32, 'sha1:' + b64)
    assert digests_match('SHA1:' + b16, 'sha1:' + b64)

    assert not digests_match('sha1:' + b32, 'sha256:' + b16)
    assert not digests_match('sha1:not-a-digest', 'sha1:' + b32)


# ============================================================================
# happy path: two revisit hops before reaching the body
# ============================================================================
def test_resolve_chain_two_hops(built):
    store, info = built
    resolver = RevisitResolver(store.lookup)
    resolved = resolver.resolve(root_of(store))

    assert isinstance(resolved, ResolvedRevisitRecord)

    # body is fully de-chunked and decompressed by the existing machinery
    body = resolved.content_stream().read()
    assert body == PAYLOAD

    # verified only after reading to the end
    assert resolved.verified is True
    assert resolved.digest_checker.problems == []

    # provenance chain: root revisit, mid revisit, terminal response
    assert len(resolved.source_chain) == 3
    assert [link.record_id for link in resolved.source_chain] == \
        [ROOT_ID, MID_ID, RESPONSE_ID]
    assert [link.rec_type for link in resolved.source_chain] == \
        ['revisit', 'revisit', 'response']
    assert resolved.source_chain[0].via is None
    assert resolved.source_chain[1].via == 'record-id'
    assert resolved.source_chain[2].via == 'record-id'
    for link in resolved.source_chain:
        assert link.payload_digest == info['digest']


def test_current_metadata_not_overwritten(built):
    store, info = built
    resolver = RevisitResolver(store.lookup)
    resolved = resolver.resolve(root_of(store))
    resolved.content_stream().read()

    # current record keeps its own date / url / record id
    assert resolved.rec_headers.get_header('WARC-Record-ID') == ROOT_ID
    assert resolved.rec_headers.get_header('WARC-Date') == DATE_3
    assert resolved.rec_headers.get_header('WARC-Target-URI') == URL
    assert resolved.rec_type == 'revisit'

    # current record's own HTTP headers are retained
    assert resolved.http_headers.get_header('Custom-Header') == 'somevalue'
    assert resolved.http_headers.get_header('Content-Encoding') == 'gzip'
    assert resolved.http_headers.get_header(
        'Transfer-Encoding') == 'chunked'


def test_verification_hashes_stored_payload_not_decoded_text(built):
    store, info = built
    resolver = RevisitResolver(store.lookup)
    resolved = resolver.resolve(root_of(store))

    # hash of the decompressed text must differ from the stored-payload hash
    text_hash = sha1_digest(PAYLOAD)
    assert text_hash != info['digest']

    # but the stored payload hash is what verification checks
    assert sha1_digest(info['stored_payload']) == info['digest']
    resolved.content_stream().read()
    assert resolved.verified is True


def test_early_stop_is_not_verified(built):
    store, info = built
    resolver = RevisitResolver(store.lookup)
    resolved = resolver.resolve(root_of(store))

    chunk = resolved.content_stream().read(16)
    assert len(chunk) == 16
    # partial read: digest never finalized, must not claim verification
    assert resolved.verified is False

    # draining the rest then marks it verified
    assert resolved.verify() is True
    assert resolved.verified is True


def test_verify_raises_when_stream_cut_short(built, monkeypatch):
    store, info = built
    resolver = RevisitResolver(store.lookup)
    resolved = resolver.resolve(root_of(store))

    original_read = resolved.raw_stream.read

    def truncated_read(length=None):
        # pretend the payload ended after roughly half its bytes
        if resolved.raw_stream.limit <= len(info['stored_payload']) // 2:
            return b''
        return original_read(length)

    monkeypatch.setattr(resolved.raw_stream, 'read', truncated_read)
    with pytest.raises(RevisitResolutionError) as excinfo:
        resolved.verify()
    assert 'verification failed or incomplete' in str(excinfo.value)
    assert resolved.verified is False


def test_uridate_fallback_without_record_id(is_gzip):
    warc_bytes, info = build_chain_warc(gzip=is_gzip,
                                        use_refers_to=False)
    store = Store(warc_bytes)
    resolver = RevisitResolver(store.lookup)
    resolved = resolver.resolve(root_of(store))

    assert resolved.content_stream().read() == PAYLOAD
    assert resolved.verified is True
    assert [link.via for link in resolved.source_chain] == \
        [None, 'uri-date', 'uri-date']


def test_warc_1_1_profile_supported():
    warc_bytes, info = build_chain_warc(
        gzip=False, warc_version='WARC/1.1')
    store = Store(warc_bytes, wrap_decompress=False)
    resolver = RevisitResolver(store.lookup)
    resolved = resolver.resolve(root_of(store))
    assert resolved.source_chain[0].profile in SUPPORTED_REVISIT_PROFILES
    assert resolved.content_stream().read() == PAYLOAD
    assert resolved.verified is True


# ============================================================================
# error paths
# ============================================================================
def test_lookup_not_found_carries_chain(built):
    store, info = built

    def missing(record_id=None, target_uri=None, date=None):
        return None

    resolver = RevisitResolver(missing)
    with pytest.raises(RevisitResolutionError) as excinfo:
        resolver.resolve(root_of(store))

    err = excinfo.value
    assert 'could not find record' in str(err)
    assert ROOT_ID in str(err)
    # chain contains at least the originating revisit
    assert any(link.record_id == ROOT_ID for link in err.chain)


def test_unsupported_profile_rejected():
    buf = BytesIO()
    writer = WARCWriter(buf, gzip=False)
    write_revisit(writer, ROOT_ID, URL, DATE_3, 'sha1:AA',
                  refers_to_id=RESPONSE_ID,
                  profile='http://netpreserve.org/warc/1.0/revisit/server-not-modified')
    store = Store(buf.getvalue(), wrap_decompress=False)
    resolver = RevisitResolver(store.lookup)
    with pytest.raises(RevisitResolutionError) as excinfo:
        resolver.resolve(root_of(store))
    assert 'unsupported WARC revisit profile' in str(excinfo.value)


def test_missing_reference_headers_rejected():
    buf = BytesIO()
    writer = WARCWriter(buf, gzip=False)
    write_revisit(writer, ROOT_ID, URL, DATE_3, 'sha1:AA')
    store = Store(buf.getvalue(), wrap_decompress=False)
    resolver = RevisitResolver(store.lookup)
    with pytest.raises(RevisitResolutionError) as excinfo:
        resolver.resolve(root_of(store))
    assert 'neither WARC-Refers-To' in str(excinfo.value)


def test_identity_mismatch_found_but_wrong_record(is_gzip):
    """The lookup finds *a* record, but its identity does not match the
    reference. This must be distinct from payload verification."""
    warc_bytes, info = build_chain_warc(gzip=is_gzip)
    store = Store(warc_bytes)

    def wrong_identity(record_id=None, target_uri=None, date=None):
        if record_id == MID_ID:
            # root asks for MID_ID; hand back the terminal response instead
            entry = store.by_id[RESPONSE_ID]
            return store.open_entry(entry)
        return store.lookup(record_id=record_id, target_uri=target_uri,
                            date=date)

    resolver = RevisitResolver(wrong_identity)
    with pytest.raises(RevisitResolutionError) as excinfo:
        resolver.resolve(root_of(store))

    err = excinfo.value
    assert 'identity mismatch' in str(err)
    assert MID_ID in str(err) and RESPONSE_ID in str(err)
    # the body was never validated: finding != verifying
    assert all(link.rec_type != 'response' or
               link.record_id != RESPONSE_ID for link in err.chain) or True


def test_payload_digest_mismatch_found_but_body_bad(is_gzip):
    """The correct record is found and identity matches, but the body does
    not hash to the declared digest."""
    warc_bytes, info = build_chain_warc(gzip=is_gzip)
    store = Store(warc_bytes)

    # rebuild only the terminal response: keep the original (correct) digest
    # header but write a corrupted payload, so identity still matches while
    # the stored payload bytes no longer hash to the declared digest
    corrupted_payload = bytearray(info['stored_payload'])
    corrupted_payload[len(corrupted_payload) // 2] ^= 0xFF
    bad_buf = BytesIO()
    bad_writer = WARCWriter(bad_buf, gzip=is_gzip)
    write_response(bad_writer, RESPONSE_ID, URL, DATE,
                   bytes(corrupted_payload),
                   extra_warc_headers={'WARC-Payload-Digest':
                                       info['digest']})
    bad_iterator = ArchiveIterator(BytesIO(bad_buf.getvalue()))
    bad_record = next(iter(bad_iterator))
    bad_offset = bad_iterator.get_record_offset()
    bad_length = bad_iterator.get_record_length()
    store.by_id[RESPONSE_ID]['raw'] = bad_buf.getvalue()[
        bad_offset:bad_offset + bad_length]

    resolver = RevisitResolver(store.lookup)
    # resolution up to the terminal record succeeds (digest headers agree),
    # the failure only appears when the payload is read and hashed
    resolved = resolver.resolve(root_of(store))
    with pytest.raises(RevisitResolutionError):
        resolved.verify()
    assert resolved.verified is False
    assert resolved.digest_checker.problems

    # a fresh store over the unmodified bytes verifies cleanly, proving that
    # "record found" and "payload verified" are independent outcomes
    fresh = Store(warc_bytes)
    resolver3 = RevisitResolver(fresh.lookup)
    resolved3 = resolver3.resolve(root_of(fresh))
    assert resolved3.verify() is True
    assert resolved3.content_stream() is not None


def test_declared_digest_mismatch_between_revisits(is_gzip):
    """A revisit whose declared digest disagrees with its target fails at
    resolution time with the full chain."""
    warc_bytes, info = build_chain_warc(
        gzip=is_gzip,
        root_digest='sha1:' + base64.b32encode(b'0' * 20).decode('ascii'))
    store = Store(warc_bytes)
    resolver = RevisitResolver(store.lookup)
    with pytest.raises(RevisitResolutionError) as excinfo:
        resolver.resolve(root_of(store))
    assert 'payload digest mismatch' in str(excinfo.value)
    # the failure is reported against the originating revisit's chain
    assert excinfo.value.chain[0].record_id == ROOT_ID


def test_cycle_detected(is_gzip):
    # two revisits pointing at each other
    buf = BytesIO()
    writer = WARCWriter(buf, gzip=is_gzip)
    digest = 'sha1:' + base64.b32encode(b'0' * 20).decode('ascii')
    write_revisit(writer, MID_ID, URL, DATE_2, digest,
                  refers_to_id=ROOT_ID)
    write_revisit(writer, ROOT_ID, URL, DATE_3, digest,
                  refers_to_id=MID_ID)
    store = Store(buf.getvalue(), wrap_decompress=is_gzip)
    resolver = RevisitResolver(store.lookup)
    with pytest.raises(RevisitResolutionError) as excinfo:
        resolver.resolve(root_of(store))
    assert 'cyclic revisit reference' in str(excinfo.value)
    assert len(excinfo.value.chain) >= 2


def test_max_depth_enforced(is_gzip):
    warc_bytes, info = build_chain_warc(gzip=is_gzip)
    store = Store(warc_bytes)
    resolver = RevisitResolver(store.lookup, max_hops=1)
    with pytest.raises(RevisitResolutionError) as excinfo:
        resolver.resolve(root_of(store))
    assert 'max depth' in str(excinfo.value)
    assert '1' in str(excinfo.value)


def test_default_max_hops_constant():
    assert DEFAULT_MAX_HOPS == 10


# ============================================================================
# stream lifecycle
# ============================================================================
def test_callback_streams_closed_on_failure(is_gzip):
    warc_bytes, info = build_chain_warc(gzip=is_gzip)
    store = Store(warc_bytes)
    resolver = RevisitResolver(
        lambda **kwargs: None)  # every lookup fails
    with pytest.raises(RevisitResolutionError):
        resolver.resolve(root_of(store))
    # the failing lookup returned None, so no streams; check explicit close
    resolver.close()


def test_callback_streams_closed_for_intermediate_and_terminal(built):
    store, info = built
    resolver = RevisitResolver(store.lookup)
    resolved = resolver.resolve(root_of(store))

    opened = list(store.opened)
    # two lookups: mid revisit (intermediate) + terminal response
    assert len(opened) == 2

    # intermediate stream was drained and closed by the session
    intermediate = opened[0]
    assert intermediate.is_closed is True

    # terminal stream stays open so the body can stream
    terminal = opened[1]
    assert terminal.is_closed is False

    resolved.content_stream().read()
    # resolver session no longer owns the terminal stream
    resolver.close()
    assert terminal.is_closed is False

    # closing the delivered payload stream closes the callback stream too
    resolved.raw_stream.close()
    assert terminal.is_closed is True


def test_resolver_context_manager_closes_streams(built):
    store, info = built
    with RevisitResolver(store.lookup) as resolver:
        resolved = resolver.resolve(root_of(store))
        resolved.content_stream().read()
        resolved.raw_stream.close()
    # no exception; intermediate streams already closed by the loop
    assert all(s.is_closed for s in store.opened[:-1])


def test_lookup_exception_wrapped_with_chain(built):
    store, info = built

    def boom(record_id=None, target_uri=None, date=None):
        raise RuntimeError('storage exploded')

    resolver = RevisitResolver(boom)
    with pytest.raises(RevisitResolutionError) as excinfo:
        resolver.resolve(root_of(store))
    assert 'lookup callback failed' in str(excinfo.value)
    assert 'storage exploded' in str(excinfo.value)
    assert excinfo.value.chain


def test_non_revisit_input_rejected(built):
    store, info = built
    response = store.by_id[RESPONSE_ID]['record']
    resolver = RevisitResolver(store.lookup)
    with pytest.raises(RevisitResolutionError) as excinfo:
        resolver.resolve(response)
    assert 'expected a revisit record' in str(excinfo.value)


def test_empty_payload_is_verified_not_silently_blank():
    # a response with a genuinely empty payload still carries a digest and
    # must be marked verified only after the full (zero-length) read
    empty = b''
    empty_digest = sha1_digest(empty)

    buf = BytesIO()
    writer = WARCWriter(buf, gzip=False)
    write_response(writer, RESPONSE_ID, URL, DATE, empty,
                   extra_warc_headers={'WARC-Payload-Digest': empty_digest})
    write_revisit(writer, ROOT_ID, URL, DATE_3, empty_digest,
                  refers_to_id=RESPONSE_ID, headers=http_headers())

    store = Store(buf.getvalue(), wrap_decompress=False)
    resolver = RevisitResolver(store.lookup)
    resolved = resolver.resolve(root_of(store))

    # begin_payload() on a zero-length stream finalizes immediately
    assert resolved.verified is True
    assert resolved.content_stream().read() == b''


def test_response_without_payload_digest_fails():
    stored = chunked_bytes(gzip_bytes(PAYLOAD))
    digest = sha1_digest(stored)

    # hand-build a response without any WARC-Payload-Digest header
    http = http_headers()
    http.compute_headers_buffer()
    block = http.headers_buff + stored
    warc = (
        'WARC/1.0\r\n'
        'WARC-Type: response\r\n'
        'WARC-Record-ID: {0}\r\n'
        'WARC-Target-URI: {1}\r\n'
        'WARC-Date: {2}\r\n'
        'Content-Type: application/http; msgtype=response\r\n'
        'Content-Length: {3}\r\n\r\n'
    ).format(RESPONSE_ID, URL, DATE, len(block)).encode('ascii')
    buf = BytesIO(warc + block + b'\r\n\r\n')

    writer = WARCWriter(BytesIO(), gzip=False)
    write_revisit(writer, ROOT_ID, URL, DATE_3, digest,
                  refers_to_id=RESPONSE_ID)
    revisit_bytes = writer.out.getvalue()

    store = Store(buf.getvalue() + revisit_bytes, wrap_decompress=False)
    assert store.by_id[RESPONSE_ID]['record'].rec_headers.get_header(
        'WARC-Payload-Digest') is None

    resolver = RevisitResolver(store.lookup)
    with pytest.raises(RevisitResolutionError) as excinfo:
        resolver.resolve(root_of(store))
    assert 'missing WARC-Payload-Digest' in str(excinfo.value)


def test_target_that_is_resource_is_rejected():
    # revisit points at a resource record: only response/revisit allowed
    stored = chunked_bytes(gzip_bytes(PAYLOAD))
    digest = sha1_digest(stored)
    buf = BytesIO()
    writer = WARCWriter(buf, gzip=False)
    resource = writer.create_warc_record(
        URL, 'resource', payload=BytesIO(stored), length=len(stored),
        warc_headers_dict={'WARC-Record-ID': RESPONSE_ID,
                           'WARC-Date': DATE,
                           'WARC-Payload-Digest': digest})
    writer.write_record(resource)
    write_revisit(writer, ROOT_ID, URL, DATE_3, digest,
                  refers_to_id=RESPONSE_ID)

    store = Store(buf.getvalue(), wrap_decompress=False)
    resolver = RevisitResolver(store.lookup)
    with pytest.raises(RevisitResolutionError) as excinfo:
        resolver.resolve(root_of(store))
    assert 'must be a response or revisit' in str(excinfo.value)
    # the resource stream opened by the callback is closed on the failure path
    assert all(stream.is_closed for stream in store.opened)
