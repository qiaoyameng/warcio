"""
Offline integrity verification for plain and gzipped WARC files.

This module is deliberately independent of the digest machinery used while
reading/writing records (``warcio.digestverifyingreader`` /
``warcio.recordbuilder``).  It re-implements WARC framing and the HTTP
transfer/encoding layers directly on top of the standard library so that it
can:

* report the physical offset of every record and every gzip member;
* verify the WARC framing length, the gzip CRC/trailer, chunked transfer
  coding, HTTP ``Content-Encoding`` and both WARC digests as *separate*
  invariants, each with its own byte-range definition;
* keep four explicit states - ``PASS``, ``FAIL``, ``NOT_PROVIDED`` and
  ``INCOMPLETE`` - so a record whose body was only half read can never be
  reported as passing;
* stream the whole file in bounded chunks without buffering a record body.

Byte layers (documented here and in the report):

* gzip CRC32/ISIZE ........ compressed member bytes on disk;
* WARC block digest ...... the exact ``Content-Length`` block bytes
  (HTTP status line + HTTP headers + HTTP body as stored);
* payload digest, stored layer . the HTTP body bytes exactly as stored in the
  block (still chunked / still content-encoded);
* payload digest, entity layer  the HTTP entity body after removing HTTP
  transfer coding (``Transfer-Encoding: chunked``) and HTTP content coding
  (``Content-Encoding: gzip`` / ``deflate``).

The WARC 1.1 specification defines the payload digest over the entity layer.
The warcio writer has historically computed it over the stored layer, so a
declared payload digest passes when it matches either independently computed
value; the report always states which layer matched.
"""

import base64
import hashlib
import json
import zlib

from warcio.integrity_gzip import (
    GzipMemberStream, GzipFormatError, GZIP_MAGIC)


PASS = 'pass'
FAIL = 'fail'
NOT_PROVIDED = 'not_provided'
INCOMPLETE = 'incomplete'

STATES = (PASS, FAIL, NOT_PROVIDED, INCOMPLETE)

READ_SIZE = 65536
CRLF = b'\r\n'
BLANK = b'\r\n\r\n'


class IntegrityError(Exception):
    """Fatal framing error that prevents further parsing of a record."""


# ---------------------------------------------------------------------------
# digest helpers (independent implementation, stdlib only)
# ---------------------------------------------------------------------------

def _b32(raw):
    return base64.b32encode(raw).decode('ascii')


def format_digest(algorithm, raw_digest):
    """Render a digest the way WARC headers store it: ``algo:BASE32``."""
    return '{0}:{1}'.format(algorithm, _b32(raw_digest))


def parse_declared_digest(declared):
    """
    Split a ``WARC-*-Digest`` header into ``(algorithm, normalised_b32)``.

    Accepts base32 (WARC convention), base16/hex and standard/url-safe
    base64 payload encodings.  Raises :class:`ValueError` on anything that
    cannot be interpreted.
    """
    algo, sep, value = declared.partition(':')
    if not sep or not algo or not value:
        raise ValueError('malformed digest header: {0!r}'.format(declared))
    algo = algo.strip().lower()
    value = value.strip()
    if algo not in hashlib.algorithms_available:
        raise ValueError('unknown digest algorithm: {0}'.format(algo))

    candidates = [value]
    try:
        pad = '=' * (-len(value) % 8)
        candidates.append(base64.b32decode(value.upper() + pad))
    except Exception:
        pass
    try:
        candidates.append(base64.b16decode(value.upper()))
    except Exception:
        pass
    try:
        alt = value.replace('-', '+').replace('_', '/')
        pad = '=' * (-len(alt) % 4)
        candidates.append(base64.b64decode(alt + pad))
    except Exception:
        pass

    for candidate in candidates:
        if isinstance(candidate, bytes):
            try:
                return algo, _b32(candidate)
            except Exception:
                continue
    raise ValueError('undecodable digest value: {0!r}'.format(declared))


class StreamingHash(object):
    """Incremental hash that never holds the data it is fed."""

    __slots__ = ('algorithm', '_hash')

    def __init__(self, algorithm):
        self.algorithm = algorithm
        self._hash = hashlib.new(algorithm)

    def update(self, data):
        self._hash.update(data)

    def value(self):
        return _b32(self._hash.digest())

    def raw_digest(self):
        return self._hash.digest()


# ---------------------------------------------------------------------------
# report structures
# ---------------------------------------------------------------------------

class InvariantResult(object):
    """Status of one independently checked invariant."""

    __slots__ = ('name', 'status', 'detail', 'expected', 'computed')

    def __init__(self, name, status, detail='', expected=None, computed=None):
        self.name = name
        self.status = status
        self.detail = detail
        self.expected = expected
        self.computed = computed

    def as_dict(self):
        return {
            'name': self.name,
            'status': self.status,
            'detail': self.detail,
            'expected': self.expected,
            'computed': self.computed,
        }


class RecordReport(object):
    """
    Full per-record result.  ``invariants`` always carries one entry per
    check (in a stable order), so callers never have to guess what ran.
    """

    def __init__(self, index, record_id, record_type, target_uri,
                 offset, header_end_offset, gzip_member):
        self.index = index
        self.record_id = record_id
        self.record_type = record_type
        self.target_uri = target_uri
        self.offset = offset
        self.header_end_offset = header_end_offset
        self.gzip_member = gzip_member
        self.declared_length = None
        self.bytes_read = 0
        self.invariants = []
        self.notes = []

    def get(self, name):
        for invariant in self.invariants:
            if invariant.name == name:
                return invariant
        return None

    @property
    def status(self):
        # "not_provided" means the check does not apply (e.g. an optional
        # digest header is absent), so it never makes a record fail on its own.
        order = {FAIL: 3, INCOMPLETE: 2, NOT_PROVIDED: 0, PASS: 0}
        worst = PASS
        for invariant in self.invariants:
            if order[invariant.status] > order[worst]:
                worst = invariant.status
        return worst

    def add(self, invariant):
        self.invariants.append(invariant)

    def as_dict(self):
        return {
            'record_index': self.index,
            'record_id': self.record_id,
            'record_type': self.record_type,
            'target_uri': self.target_uri,
            'physical_offset': self.offset,
            'header_end_offset': self.header_end_offset,
            'gzip_member': self.gzip_member,
            'declared_content_length': self.declared_length,
            'block_bytes_read': self.bytes_read,
            'overall_status': self.status,
            'invariants': [item.as_dict() for item in self.invariants],
            'notes': list(self.notes),
        }


class IntegrityReport(object):
    def __init__(self, path, container):
        self.path = path
        self.container = container
        self.records = []
        self.gzip_members = []
        self.fatal_errors = []

    @property
    def status(self):
        if self.fatal_errors:
            return FAIL
        if not self.records:
            return INCOMPLETE
        order = {FAIL: 3, INCOMPLETE: 2, NOT_PROVIDED: 0, PASS: 0}
        worst = PASS
        for record in self.records:
            if order[record.status] > order[worst]:
                worst = record.status
        return worst

    def as_dict(self):
        return {
            'path': self.path,
            'container': self.container,
            'overall_status': self.status,
            'record_count': len(self.records),
            'gzip_members': self.gzip_members,
            'fatal_errors': list(self.fatal_errors),
            'records': [record.as_dict() for record in self.records],
        }

    def to_json(self, indent=2):
        return json.dumps(self.as_dict(), indent=indent, sort_keys=False)


# ---------------------------------------------------------------------------
# HTTP transfer/content coding pipeline
# ---------------------------------------------------------------------------

class PipelineError(Exception):
    """Distinct error type so callers can tell fail vs. incomplete apart."""

    def __init__(self, message, fatal=True):
        super(PipelineError, self).__init__(message)
        self.fatal = fatal


class Dechunker(object):
    """
    RFC 7230 chunked transfer decoder, fed arbitrary byte chunks.

    A malformed chunk size line or trailer raises a fatal
    :class:`PipelineError` (``fail``).  Running out of bytes mid-chunk or
    before the terminating zero chunk raises a non-fatal one
    (``incomplete``).
    """

    def __init__(self):
        self._buf = b''
        self._reading_size = True
        self._remaining = 0
        self._finished = False

    def feed(self, data):
        self._buf += data
        out = []
        while self._buf:
            if self._finished:
                raise PipelineError(
                    'chunked body contains bytes after last-chunk trailer')
            if self._reading_size:
                line_end = self._buf.find(CRLF)
                if line_end < 0:
                    break
                size_line = self._buf[:line_end]
                self._buf = self._buf[line_end + 2:]
                try:
                    token = size_line.split(b';', 1)[0].strip()
                    self._remaining = int(token, 16)
                except ValueError:
                    raise PipelineError(
                        'invalid chunk size line: {0!r}'.format(size_line))
                self._reading_size = False
                if self._remaining == 0:
                    if not self._buf.startswith(CRLF):
                        if len(self._buf) < 2:
                            break
                        raise PipelineError(
                            'missing CRLF after last chunk (got {0!r})'
                            .format(self._buf[:2]))
                    self._buf = self._buf[2:]
                    self._finished = True
                    if self._buf:
                        raise PipelineError(
                            'chunked body contains bytes after last chunk')
                    break
            else:
                if not self._buf:
                    break
                take = min(self._remaining, len(self._buf))
                out.append(self._buf[:take])
                self._buf = self._buf[take:]
                self._remaining -= take
                if self._remaining == 0:
                    if len(self._buf) < 2:
                        break
                    if not self._buf.startswith(CRLF):
                        raise PipelineError(
                            'missing CRLF at end of data chunk')
                    self._buf = self._buf[2:]
                    self._reading_size = True
        return b''.join(out)

    def finish(self):
        if not self._finished or self._buf:
            raise PipelineError(
                'chunked body ended before last chunk / trailer', fatal=False)


class Gunzipper(object):
    """Streaming gzip/deflate decoder for an HTTP content coding."""

    def __init__(self, encoding):
        wbits = 31 if encoding == 'gzip' else 15
        self._decomp = zlib.decompressobj(wbits)
        self._encoding = encoding

    def feed(self, data):
        try:
            return self._decomp.decompress(data)
        except zlib.error as exc:
            raise PipelineError(
                'HTTP Content-Encoding {0} decode error: {1}'
                .format(self._encoding, exc))

    def finish(self):
        try:
            tail = self._decomp.flush()
        except zlib.error as exc:
            raise PipelineError(
                'HTTP Content-Encoding {0} decode error: {1}'
                .format(self._encoding, exc))
        if not self._decomp.eof:
            raise PipelineError(
                'HTTP Content-Encoding {0} stream is truncated'
                .format(self._encoding), fatal=False)
        return tail


def _parse_http_headers(headers_bytes):
    """
    Parse the HTTP message header block.  Returns
    ``(status_line, headers, duplicate_names)`` preserving header order and
    duplicates.
    """
    lines = headers_bytes.split(CRLF)
    status_line = lines[0].decode('iso-8859-1')
    headers = []
    seen = set()
    duplicate_names = []
    for line in lines[1:]:
        if not line:
            continue
        name, sep, value = line.partition(b':')
        if not sep:
            raise PipelineError('malformed HTTP header line: {0!r}'.format(line))
        name_text = name.decode('iso-8859-1').strip()
        value_text = value.decode('iso-8859-1').strip()
        headers.append((name_text, value_text))
        key = name_text.lower()
        if key in seen and key not in duplicate_names:
            duplicate_names.append(key)
        seen.add(key)
    return status_line, headers, duplicate_names


def _header_value(headers, name):
    name = name.lower()
    for header_name, value in headers:
        if header_name.lower() == name:
            return value
    return None


class PayloadPipeline(object):
    """
    Streaming, layer-aware processor for one WARC block.

    Inbound data is the raw block (HTTP status line, headers and body, as
    stored).  The same bytes fan out to independent hashes for the block, the
    stored payload and - after de-chunking / content decoding - the entity
    payload.  Only small bounded chunks ever exist at once.
    """

    def __init__(self, record_type, declared_block_digest,
                 declared_payload_digest):
        self.record_type = record_type
        self.declared_block_digest = declared_block_digest
        self.declared_payload_digest = declared_payload_digest

        self.block_hash = None
        self.stored_hash = None
        self.entity_hash = None
        self._algorithm = self._pick_algorithm(
            declared_block_digest, declared_payload_digest)
        if self._algorithm:
            self.block_hash = StreamingHash(self._algorithm)
            self.stored_hash = StreamingHash(self._algorithm)
            self.entity_hash = StreamingHash(self._algorithm)

        self.is_http = record_type in ('response', 'request', 'revisit')
        self._phase = 'http_header'
        self._header_buf = b''
        self.http_headers = []
        self.status_line = None
        self.duplicate_headers = []
        self._dechunker = None
        self._decoder = None
        self.transfer_chunked = False
        self.content_encoding = None

    @staticmethod
    def _pick_algorithm(*declared):
        for value in declared:
            if not value:
                continue
            try:
                algo, _ = parse_declared_digest(value)
                return algo
            except ValueError:
                continue
        return 'sha1'

    def _enter_body(self):
        header_bytes = self._header_buf[:-len(CRLF)]
        self.status_line, self.http_headers, self.duplicate_headers = \
            _parse_http_headers(header_bytes)
        te = _header_value(self.http_headers, 'transfer-encoding')
        self.transfer_chunked = bool(te) and 'chunked' in te.lower()
        encoding = _header_value(self.http_headers, 'content-encoding')
        if encoding:
            encoding = encoding.strip().lower()
            if encoding == 'x-gzip':
                encoding = 'gzip'
        if encoding in ('gzip', 'deflate'):
            self.content_encoding = encoding
        if self.transfer_chunked:
            self._dechunker = Dechunker()
        if self.content_encoding:
            self._decoder = Gunzipper(self.content_encoding)
        self._phase = 'body'

    def feed(self, data):
        if self.block_hash:
            self.block_hash.update(data)

        if not self.is_http:
            # No HTTP envelope: stored payload == entity payload == block.
            if self.stored_hash:
                self.stored_hash.update(data)
                self.entity_hash.update(data)
            return

        if self._phase == 'http_header':
            self._header_buf += data
            marker = self._header_buf.find(BLANK)
            if marker < 0:
                return
            header_block = self._header_buf[:marker + len(BLANK)]
            body = self._header_buf[marker + len(BLANK):]
            self._header_buf = header_block
            self._enter_body()
            data = body

        if self.stored_hash:
            self.stored_hash.update(data)

        layer = data
        if self._dechunker:
            layer = self._dechunker.feed(layer)
        if self._decoder:
            layer = self._decoder.feed(layer)
        if self.entity_hash and layer:
            self.entity_hash.update(layer)

    def finish(self):
        """Validate end-of-stream invariants; raises PipelineError on failure."""
        if not self.is_http:
            return
        if self._phase == 'http_header':
            raise PipelineError('block ended inside HTTP header', fatal=False)
        if self._dechunker:
            self._dechunker.finish()
        if self._decoder:
            tail = self._decoder.finish()
            if self.entity_hash and tail:
                self.entity_hash.update(tail)

    def digest_invariants(self):
        """
        Build block/payload :class:`InvariantResult` objects from the hashes
        accumulated while streaming.
        """
        results = []
        if not self.declared_block_digest:
            results.append(InvariantResult(
                'block_digest', NOT_PROVIDED,
                'no WARC-Block-Digest header present'))
        else:
            try:
                algo, expected = parse_declared_digest(
                    self.declared_block_digest)
            except ValueError as exc:
                results.append(InvariantResult(
                    'block_digest', FAIL, str(exc),
                    expected=self.declared_block_digest))
            else:
                computed = self.block_hash.value()
                if computed == expected:
                    results.append(InvariantResult(
                        'block_digest', PASS,
                        'hash of all {0} stored block bytes matches '
                        'WARC-Block-Digest'.format(algo),
                        expected=self.declared_block_digest,
                        computed=format_digest(algo,
                                               self.block_hash.raw_digest())))
                else:
                    results.append(InvariantResult(
                        'block_digest', FAIL,
                        'stored block hash {0} != declared {1}'.format(
                            computed, expected),
                        expected=self.declared_block_digest,
                        computed=format_digest(algo,
                                               self.block_hash.raw_digest())))

        if not self.declared_payload_digest:
            results.append(InvariantResult(
                'payload_digest', NOT_PROVIDED,
                'no WARC-Payload-Digest header present'))
            return results

        if self.stored_hash is None:
            results.append(InvariantResult(
                'payload_digest', INCOMPLETE,
                'declared digest uses an unsupported algorithm'))
            return results

        try:
            algo, expected = parse_declared_digest(
                self.declared_payload_digest)
        except ValueError as exc:
            results.append(InvariantResult(
                'payload_digest', FAIL, str(exc),
                expected=self.declared_payload_digest))
            return results

        stored = self.stored_hash.value()
        entity = self.entity_hash.value()
        if expected == stored and expected == entity:
            detail = 'matches stored and entity payload bytes'
            status = PASS
        elif expected == stored:
            detail = ('matches stored HTTP body (pre transfer/content coding); '
                      'warcio-style payload digest')
            status = PASS
        elif expected == entity:
            detail = ('matches decoded entity body (post chunked/content '
                      'coding); WARC 1.1 payload digest')
            status = PASS
        else:
            detail = ('matches neither stored payload {0} nor entity payload '
                      '{1}').format(stored, entity)
            status = FAIL
        results.append(InvariantResult(
            'payload_digest', status, detail,
            expected=self.declared_payload_digest,
            computed={
                'stored_layer': format_digest(algo,
                                              self.stored_hash.raw_digest()),
                'entity_layer': format_digest(algo,
                                              self.entity_hash.raw_digest()),
                'matched_layer': (
                    'stored' if expected == stored else
                    'entity' if expected == entity else None),
            }))
        return results


# ---------------------------------------------------------------------------
# WARC framing scanner
# ---------------------------------------------------------------------------

def _read_header_block(stream):
    """
    Read one WARC header block (ending in CRLFCRLF) in bounded pieces.
    Returns ``(header_bytes, physical_start_offset)``.
    """
    start = stream.tell()
    chunks = []
    buffered = b''
    while BLANK not in buffered:
        piece = stream.read(READ_SIZE)
        if not piece:
            if not buffered:
                return None, start
            raise IntegrityError(
                'stream ended in the middle of a WARC header at offset {0}'
                .format(start))
        chunks.append(piece)
        buffered += piece
        if len(buffered) > 1024 * 1024:
            raise IntegrityError(
                'WARC header block exceeds 1 MiB near offset {0}'.format(start))
    raw = b''.join(chunks)
    marker = raw.find(BLANK)
    header_bytes = raw[:marker + len(BLANK)]
    stream.push_back(raw[marker + len(BLANK):])
    return header_bytes, start


def _parse_warc_headers(header_bytes):
    text = header_bytes.decode('iso-8859-1')
    lines = text.split('\r\n')
    version = lines[0]
    if not version.startswith('WARC/'):
        raise IntegrityError(
            'expected WARC version line, got {0!r}'.format(lines[0]))
    headers = []
    duplicate_names = []
    seen = set()
    for line in lines[1:]:
        if not line:
            continue
        name, sep, value = line.partition(':')
        if not sep:
            raise IntegrityError('malformed WARC header line: {0!r}'.format(line))
        name = name.strip()
        value = value.strip()
        headers.append((name, value))
        key = name.lower()
        if key in seen and key not in duplicate_names:
            duplicate_names.append(key)
        seen.add(key)
    return version, headers, duplicate_names


def _warc_header(headers, name, default=None):
    name = name.lower()
    for header_name, value in headers:
        if header_name.lower() == name:
            return value
    return default


class _PushbackStream(object):
    """Adds bounded push-back and physical offset tracking to a raw stream."""

    def __init__(self, stream):
        self._stream = stream
        self._push = b''
        self._offset = 0

    def tell(self):
        return self._offset

    def push_back(self, data):
        if data:
            self._push = data + self._push
            self._offset -= len(data)

    def read(self, size=-1):
        if size is None or size < 0:
            size = READ_SIZE
        if self._push:
            piece = self._push[:size]
            self._push = self._push[size:]
            size -= len(piece)
        else:
            piece = b''
        if size > 0:
            piece += self._stream.read(size)
        self._offset += len(piece)
        return piece


class _GzipPushbackAdapter(object):
    """
    Presents the decompressed gzip stream with the same read/push-back/tell
    surface as :class:`_PushbackStream`.  ``tell`` reports the decompressed
    offset; compressed offsets come from the member stream itself.
    """

    def __init__(self, member_stream):
        self._member = member_stream
        self._push = b''
        self._offset = 0

    def tell(self):
        return self._offset

    def push_back(self, data):
        if data:
            self._push = data + self._push
            self._offset -= len(data)

    def read(self, size=-1):
        if size is None or size < 0:
            size = READ_SIZE
        if self._push:
            piece = self._push[:size]
            self._push = self._push[size:]
            size -= len(piece)
        else:
            piece = b''
        if size > 0:
            piece += self._member.read(size)
        self._offset += len(piece)
        return piece

    def current_member(self):
        # Use the adapter's logical offset: bytes pushed back after an
        # over-long header read must not count as delivered.
        return self._member.member_at_position(self._offset)

    def active_member(self):
        """Member the underlying pump is currently writing into."""
        return self._member.current_member()


def _gzip_member_snapshot(member):
    if member is None:
        return None
    return {
        'member_index': member.index,
        'compressed_start': member.comp_start,
    }


def verify_stream(stream, path='<stream>'):
    """
    Verify a seekable binary WARC stream (plain or gzip).  Returns a fully
    populated :class:`IntegrityReport`; raises nothing for per-record failures
    (those live in the report), only for unrecoverable top-level errors.
    """
    first = stream.read(2)
    is_gzip = first == GZIP_MAGIC
    stream.seek(0)

    if is_gzip:
        member_stream = GzipMemberStream(stream)
        source = _GzipPushbackAdapter(member_stream)
        container = 'warc.gz'
    else:
        member_stream = None
        source = _PushbackStream(stream)
        container = 'warc'

    report = IntegrityReport(path, container)
    record_index = 0

    while True:
        try:
            header_bytes, record_offset = _read_header_block(source)
        except GzipFormatError as exc:
            record_index += 1
            owner = source.current_member() if is_gzip else None
            broken = RecordReport(
                index=record_index,
                record_id=None,
                record_type='unknown',
                target_uri=None,
                offset=source.tell(),
                header_end_offset=source.tell(),
                gzip_member=_gzip_member_snapshot(owner))
            broken.declared_length = None
            broken.bytes_read = 0
            broken.add(InvariantResult(
                'gzip_member_crc', FAIL, str(exc),
                expected='CRC32 + ISIZE trailer',
                computed=owner.crc_status if owner is not None else None))
            broken.add(InvariantResult(
                'warc_content_length', INCOMPLETE,
                'record framing unreadable due to gzip failure'))
            broken.add(InvariantResult(
                'warc_record_terminator', INCOMPLETE,
                'not evaluated because the gzip layer failed'))
            broken.add(InvariantResult(
                'http_transfer_coding', NOT_PROVIDED,
                'record has no readable HTTP envelope'))
            broken.add(InvariantResult(
                'block_digest', INCOMPLETE,
                'block bytes unavailable due to gzip failure'))
            broken.add(InvariantResult(
                'payload_digest', INCOMPLETE,
                'payload bytes unavailable due to gzip failure'))
            report.records.append(broken)
            report.fatal_errors.append(
                'record {0}: {1}'.format(record_index, exc))
            break
        except IntegrityError as exc:
            report.fatal_errors.append(str(exc))
            break
        if header_bytes is None:
            break

        record_index += 1
        member_at_start = (source.current_member()
                           if is_gzip else None)
        member_snapshot = _gzip_member_snapshot(member_at_start)
        try:
            version, headers, duplicate_warc_headers = \
                _parse_warc_headers(header_bytes)
        except IntegrityError as exc:
            report.fatal_errors.append(
                'record {0} at offset {1}: {2}'.format(
                    record_index, record_offset, exc))
            break

        record = RecordReport(
            index=record_index,
            record_id=_warc_header(headers, 'WARC-Record-ID'),
            record_type=_warc_header(headers, 'WARC-Type', 'unknown'),
            target_uri=_warc_header(headers, 'WARC-Target-URI'),
            offset=record_offset,
            header_end_offset=source.tell(),
            gzip_member=member_snapshot)
        for name in duplicate_warc_headers:
            record.notes.append('duplicate WARC header: {0}'.format(name))

        length_raw = _warc_header(headers, 'Content-Length')
        try:
            declared_length = int(length_raw)
            if declared_length < 0:
                raise ValueError
        except (TypeError, ValueError):
            declared_length = None
            record.add(InvariantResult(
                'warc_content_length', FAIL,
                'missing or non-integer Content-Length: {0!r}'.format(length_raw)))
        record.declared_length = declared_length

        block_digest_header = _warc_header(headers, 'WARC-Block-Digest')
        payload_digest_header = _warc_header(headers, 'WARC-Payload-Digest')

        pipeline = PayloadPipeline(
            record.record_type, block_digest_header, payload_digest_header)

        bytes_read = 0
        truncated = False
        pipeline_error = None
        gzip_error = None
        if declared_length is not None:
            remaining = declared_length
            while remaining > 0:
                try:
                    piece = source.read(min(READ_SIZE, remaining))
                except GzipFormatError as exc:
                    gzip_error = exc
                    break
                if not piece:
                    truncated = True
                    break
                bytes_read += len(piece)
                remaining -= len(piece)
                try:
                    pipeline.feed(piece)
                except PipelineError as exc:
                    pipeline_error = exc
                    break
        record.bytes_read = bytes_read

        # WARC block length invariant
        if declared_length is not None:
            if pipeline_error is None and not truncated:
                if bytes_read == declared_length:
                    record.add(InvariantResult(
                        'warc_content_length', PASS,
                        'all {0} declared block bytes consumed'.format(
                            declared_length),
                        expected=declared_length, computed=bytes_read))
                else:
                    record.add(InvariantResult(
                        'warc_content_length', FAIL,
                        'block byte count differs from declaration',
                        expected=declared_length, computed=bytes_read))
            else:
                detail = ('only {0} of {1} declared block bytes read'
                          .format(bytes_read, declared_length))
                record.add(InvariantResult(
                    'warc_content_length', INCOMPLETE, detail,
                    expected=declared_length, computed=bytes_read))

        # Block terminator (CRLFCRLF) only meaningful when the block itself
        # was fully read.
        terminator_status = None
        if not truncated and pipeline_error is None and declared_length is not None:
            terminator = source.read(4)
            if terminator == BLANK:
                terminator_status = PASS
                record.add(InvariantResult(
                    'warc_record_terminator', PASS,
                    'block followed by CRLFCRLF'))
            elif len(terminator) < 4:
                terminator_status = INCOMPLETE
                record.add(InvariantResult(
                    'warc_record_terminator', INCOMPLETE,
                    'stream ended before record terminator'))
            else:
                terminator_status = FAIL
                record.add(InvariantResult(
                    'warc_record_terminator', FAIL,
                    'expected CRLFCRLF after block, got {0!r}'.format(
                        terminator)))
        else:
            terminator_status = INCOMPLETE
            record.add(InvariantResult(
                'warc_record_terminator', INCOMPLETE,
                'not evaluated because the block was not fully read'))

        # HTTP transfer / content coding layer
        if pipeline.is_http and pipeline._phase == 'body':
            for name in pipeline.duplicate_headers:
                record.notes.append('duplicate HTTP header: {0}'.format(name))
            coding_status = PASS
            coding_detail = []
            if pipeline_error is not None:
                coding_status = FAIL if pipeline_error.fatal else INCOMPLETE
                coding_detail.append(str(pipeline_error))
            else:
                try:
                    pipeline.finish()
                except PipelineError as exc:
                    coding_status = FAIL if exc.fatal else INCOMPLETE
                    coding_detail.append(str(exc))
            if pipeline.transfer_chunked:
                coding_detail.append('Transfer-Encoding: chunked decoded')
            if pipeline.content_encoding:
                coding_detail.append(
                    'Content-Encoding: {0} decoded'.format(
                        pipeline.content_encoding))
            if not coding_detail:
                coding_detail.append('identity HTTP body, no coding')
            record.add(InvariantResult(
                'http_transfer_coding', coding_status,
                '; '.join(coding_detail)))
        else:
            record.add(InvariantResult(
                'http_transfer_coding', NOT_PROVIDED,
                'record has no HTTP message envelope'))

        # gzip member CRC/trailer
        if is_gzip:
            member_now = source.active_member()
            if member_now is not member_at_start:
                record.notes.append(
                    'record spans gzip member boundary {0} -> {1}'.format(
                        member_at_start.index, member_now.index))
            # The record's own member is the one it started on; the pump may
            # have run ahead into a later member, so evaluate that member.
            owner = member_at_start
            if gzip_error is not None:
                status = FAIL
                detail = str(gzip_error)
            elif owner.crc_status == 'pass':
                status = PASS
                detail = 'gzip member {0} CRC32/ISIZE verified'.format(
                    owner.index)
            elif owner.crc_status == 'fail':
                status = FAIL
                detail = owner.error or 'gzip CRC/trailer mismatch'
            else:
                status = INCOMPLETE
                detail = 'gzip member {0} truncated before trailer'.format(
                    owner.index)
            record.add(InvariantResult(
                'gzip_member_crc', status, detail,
                expected='CRC32 + ISIZE trailer',
                computed=owner.crc_status))

        # Digests.  If upstream layers were incomplete/failed, a hash can only
        # be reported as incomplete - never as pass.
        upstream_bad = (
            truncated or pipeline_error is not None or gzip_error is not None or
            terminator_status != PASS or
            (is_gzip and member_at_start.crc_status != 'pass'))
        if upstream_bad:
            if block_digest_header:
                record.add(InvariantResult(
                    'block_digest', INCOMPLETE,
                    'block bytes not fully and reliably available'))
            else:
                record.add(InvariantResult(
                    'block_digest', NOT_PROVIDED,
                    'no WARC-Block-Digest header present'))
            if payload_digest_header:
                record.add(InvariantResult(
                    'payload_digest', INCOMPLETE,
                    'payload bytes not fully and reliably available'))
            else:
                record.add(InvariantResult(
                    'payload_digest', NOT_PROVIDED,
                    'no WARC-Payload-Digest header present'))
        else:
            for invariant in pipeline.digest_invariants():
                if invariant.name == 'block_digest' and not block_digest_header:
                    record.add(InvariantResult(
                        'block_digest', NOT_PROVIDED,
                        'no WARC-Block-Digest header present'))
                elif invariant.name == 'payload_digest' and \
                        not payload_digest_header:
                    record.add(InvariantResult(
                        'payload_digest', NOT_PROVIDED,
                        'no WARC-Payload-Digest header present'))
                else:
                    record.add(invariant)

        report.records.append(record)

        if truncated or pipeline_error is not None or gzip_error is not None or \
                (is_gzip and source.active_member().crc_status in
                 ('fail', 'incomplete')):
            # Cannot reliably locate any later record once the framing or
            # gzip layer is broken; stop after recording this one.
            break

    if is_gzip:
        report.gzip_members = [info.as_dict()
                               for info in member_stream.members]
        reported = set()
        for record in report.records:
            if record.gzip_member:
                reported.add(record.gzip_member['member_index'])
        for info in member_stream.members:
            if info.index in reported:
                continue
            if info.crc_status == 'fail':
                report.fatal_errors.append(
                    'gzip member {0} CRC/trailer failure: {1}'.format(
                        info.index, info.error or 'CRC32/ISIZE mismatch'))
            elif info.crc_status == 'incomplete':
                report.fatal_errors.append(
                    'gzip member {0} is truncated before its trailer '
                    '(compressed byte {1})'.format(
                        info.index, info.comp_start))
    return report


def verify_file(path):
    """Open ``path`` in binary mode and run :func:`verify_stream` over it."""
    with open(path, 'rb') as stream:
        return verify_stream(stream, path=path)


# ---------------------------------------------------------------------------
# human-readable rendering
# ---------------------------------------------------------------------------

def render_text(report):
    """Render an :class:`IntegrityReport` as deterministic plain text."""
    lines = []
    lines.append('WARC integrity report: {0}'.format(report.path))
    lines.append('container: {0}'.format(report.container))
    if report.gzip_members:
        lines.append('gzip members: {0}'.format(len(report.gzip_members)))
        for member in report.gzip_members:
            lines.append('  member {0}: bytes {1}-{2} crc={3}{4}'.format(
                member['member_index'],
                member['compressed_start'],
                member['compressed_end'],
                member['crc_status'],
                (' ({0})'.format(member['error']) if member['error'] else '')))
    lines.append('records: {0}  overall: {1}'.format(
        len(report.records), report.status))
    for record in report.records:
        lines.append('')
        lines.append('record #{0} [{1}] {2}'.format(
            record.index, record.status, record.record_type))
        lines.append('  id:       {0}'.format(record.record_id))
        if record.target_uri:
            lines.append('  uri:      {0}'.format(record.target_uri))
        member = record.gzip_member
        if member:
            lines.append('  member:   gzip member {0} (compressed byte {1})'
                         .format(member['member_index'],
                                 member['compressed_start']))
        lines.append('  offset:   byte {0} (headers end {1})'.format(
            record.offset, record.header_end_offset))
        lines.append('  length:   declared={0} block_bytes_read={1}'.format(
            record.declared_length, record.bytes_read))
        for invariant in record.invariants:
            line = '  - {0}: {1}'.format(invariant.name, invariant.status)
            if invariant.detail:
                line += ' ({0})'.format(invariant.detail)
            lines.append(line)
        for note in record.notes:
            lines.append('  note: {0}'.format(note))
    for error in report.fatal_errors:
        lines.append('')
        lines.append('FATAL: {0}'.format(error))
    return '\n'.join(lines)
