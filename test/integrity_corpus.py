"""
Deterministic, in-memory WARC fixtures for the offline integrity checker.

Every fixture is generated from the standard library and warcio's own
``WARCWriter`` so the baseline is a *legitimate* WARC by construction; the
corruption helpers then flip exactly one layer at a time.  No binary fixture
files are checked in.
"""

import gzip
import hashlib
import base64
import re

from io import BytesIO

from warcio.warcwriter import BufferWARCWriter, WARCWriter
from warcio.statusandheaders import StatusAndHeaders


def b32_sha1(data):
    return base64.b32encode(hashlib.sha1(data).digest()).decode('ascii')


def chunked_wrap(payload):
    """Wrap bytes in a single HTTP/1.1 chunked body plus terminating chunk."""
    size = '{0:x}'.format(len(payload)).encode('ascii')
    return size + b'\r\n' + payload + b'\r\n0\r\n\r\n'


def http_response(headers, body):
    """Serialise an HTTP/1.1 response message from header pairs + body."""
    lines = [b'HTTP/1.1 200 OK']
    for name, value in headers:
        lines.append('{0}: {1}'.format(name, value).encode('iso-8859-1'))
    return b'\r\n'.join(lines) + b'\r\n\r\n' + body


def _add_response(writer, uri, http_headers, payload):
    record = writer.create_warc_record(
        uri, 'response', payload=BytesIO(payload), http_headers=http_headers)
    writer.write_record(record)
    return record


def build_plain_warc():
    """
    Plain WARC covering: warcinfo, identity body, empty body, chunked transfer
    coding over gzip content coding, and a non-HTTP resource record.
    """
    writer = BufferWARCWriter(gzip=False)

    writer.write_record(writer.create_warc_record(
        '', 'warcinfo', payload=BytesIO(b'software: integrity-corpus\r\n')))

    _add_response(
        writer, 'http://example.test/identity',
        StatusAndHeaders('200 OK', [('Content-Type', 'text/plain')],
                         protocol='HTTP/1.1'),
        b'identity payload ' * 32)

    _add_response(
        writer, 'http://example.test/empty',
        StatusAndHeaders('204 No Content', [('Content-Length', '0')],
                         protocol='HTTP/1.1'),
        b'')

    entity = b'{"k":"v"}\n' * 64
    encoded = gzip.compress(entity)
    _add_response(
        writer, 'http://example.test/chunked-gzip',
        StatusAndHeaders(
            '200 OK',
            [('Transfer-Encoding', 'chunked'),
             ('Content-Type', 'application/json')],
            protocol='HTTP/1.1'),
        chunked_wrap(encoded))

    resource = writer.create_warc_record(
        'http://example.test/resource', 'resource',
        payload=BytesIO(b'raw resource bytes ' * 16),
        warc_headers_dict={'Content-Type': 'application/octet-stream'})
    writer.write_record(resource)

    return writer.get_contents()


def build_gzip_warc(path, records_per_member=1):
    """
    Write a multi-record gzipped WARC to ``path``.  warcio emits one gzip
    member per ``write_record`` call, so passing several records yields a
    multi-member file.
    """
    with open(path, 'wb') as handle:
        writer = WARCWriter(handle, gzip=True)
        for index in range(records_per_member * 2):
            _add_response(
                writer,
                'http://example.test/member/{0}'.format(index),
                StatusAndHeaders('200 OK', [('Content-Type', 'text/plain')],
                                 protocol='HTTP/1.1'),
                ('member-{0}-body '.format(index)).encode() * 32)


def build_duplicate_header_warc():
    """WARC with duplicated WARC-level and HTTP-level header names."""
    body = http_response(
        [('Content-Type', 'text/plain'), ('X-Dup', 'one'), ('X-Dup', 'two')],
        b'duplicate header body')
    headers = (
        b'WARC/1.0\r\n'
        b'WARC-Type: response\r\n'
        b'WARC-Record-ID: <urn:uuid:duplicated>\r\n'
        b'WARC-Target-URI: http://example.test/dup\r\n'
        b'WARC-Date: 2026-01-01T00:00:00Z\r\n'
        b'Content-Type: application/http; msgtype=response\r\n'
        b'X-Warc-Dup: a\r\nX-Warc-Dup: b\r\n'
        b'Content-Length: ' + str(len(body)).encode('ascii') + b'\r\n\r\n')
    return headers + body + b'\r\n\r\n'


def build_entity_digest_warc():
    """
    A ``Content-Encoding: gzip`` response whose WARC-Payload-Digest is the
    WARC 1.1 *entity* digest (post content coding), proving the checker keeps
    the stored and entity layers independent.
    """
    entity = b'entity layer payload ' * 32
    encoded = gzip.compress(entity)
    writer = BufferWARCWriter(gzip=False)
    record = writer.create_warc_record(
        'http://example.test/entity-digest', 'response',
        payload=BytesIO(encoded),
        http_headers=StatusAndHeaders(
            '200 OK',
            [('Content-Encoding', 'gzip'), ('Content-Type', 'text/plain')],
            protocol='HTTP/1.1'))
    writer.write_record(record)
    raw = bytearray(writer.get_contents())
    replacement = b'WARC-Payload-Digest: sha1:' + b32_sha1(entity).encode()
    match = re.search(rb'WARC-Payload-Digest: sha1:[A-Z2-7]+', bytes(raw))
    raw[match.start():match.end()] = replacement
    return bytes(raw), entity, encoded


def build_deflate_warc():
    """A response whose HTTP body uses ``Content-Encoding: deflate``."""
    import zlib
    entity = b'deflate encoded entity ' * 24
    encoded = zlib.compress(entity)
    writer = BufferWARCWriter(gzip=False)
    record = writer.create_warc_record(
        'http://example.test/deflate', 'response',
        payload=BytesIO(encoded),
        http_headers=StatusAndHeaders(
            '200 OK',
            [('Content-Encoding', 'deflate'),
             ('Content-Type', 'text/plain')],
            protocol='HTTP/1.1'))
    writer.write_record(record)
    return writer.get_contents(), entity


# ---------------------------------------------------------------------------
# single-layer corruption helpers
# ---------------------------------------------------------------------------

def corrupt_warc_length(data, delta=-4):
    """Adjust the first Content-Length header without touching the block."""
    blob = bytearray(data)
    match = re.search(rb'Content-Length: (\d+)', bytes(blob))
    new_value = int(match.group(1)) + delta
    blob[match.start(1):match.end(1)] = str(new_value).encode('ascii')
    return bytes(blob), new_value


def corrupt_chunk_size_line(data):
    """Turn the first hex chunk size into a non-hex token."""
    blob = bytearray(data)
    # The HTTP chunk size line is immediately followed by a gzip member
    # (0x1f8b) in the chunked+gzip fixture; anchor on that to avoid matching
    # hex digits inside WARC base32 digest headers.
    match = re.search(rb'([0-9a-f]+)\r\n\x1f\x8b', bytes(blob))
    blob[match.start(1)] = ord('g')
    return bytes(blob)


def corrupt_chunk_terminator(data):
    """Break the CRLF that follows the terminating zero chunk."""
    blob = bytearray(data)
    marker = blob.rfind(b'0\r\n\r\n')
    blob[marker + 2] = ord('X')
    return bytes(blob)


def corrupt_payload_digest(data):
    """Flip one base32 character of the payload digest, keep block digest."""
    blob = bytearray(data)
    match = re.search(rb'WARC-Payload-Digest: sha1:([A-Z2-7]+)', bytes(blob))
    original = blob[match.start(1)]
    replacement = ord('B') if original == ord('A') else ord('A')
    blob[match.start(1)] = replacement
    return bytes(blob)


def _gzip_member_ranges(blob):
    """Return ``[(start, end), ...]`` for every gzip member in ``blob``."""
    import zlib
    ranges = []
    pos = 0
    while pos < len(blob):
        start = pos
        decomp = zlib.decompressobj(31)
        decomp.decompress(blob[pos:])
        consumed = len(blob[pos:]) - len(decomp.unused_data)
        ranges.append((start, start + consumed))
        if not decomp.unused_data:
            break
        pos = start + consumed
    return ranges


def corrupt_gzip_crc(path, member_index=0):
    """Flip a CRC32 trailer byte of the chosen gzip member on disk."""
    with open(path, 'rb') as handle:
        blob = bytearray(handle.read())
    start, end = _gzip_member_ranges(bytes(blob))[member_index]
    # The 8-byte gzip trailer is CRC32 (4 bytes) then ISIZE (4 bytes); the
    # third CRC byte sits at end - 6.
    blob[end - 6] ^= 0x01
    with open(path, 'wb') as handle:
        handle.write(bytes(blob))


def build_truncated_content_encoding_warc():
    """
    A ``Content-Encoding: gzip`` response whose encoded body is cut short.
    The WARC block itself stays intact, so only the HTTP content-coding layer
    is incomplete; the block digest must still verify.
    """
    entity = b'entity that will be truncated ' * 32
    encoded = gzip.compress(entity)[:-8]
    writer = BufferWARCWriter(gzip=False)
    record = writer.create_warc_record(
        'http://example.test/truncated-ce', 'response',
        payload=BytesIO(encoded),
        http_headers=StatusAndHeaders(
            '200 OK',
            [('Content-Encoding', 'gzip'),
             ('Content-Type', 'text/plain')],
            protocol='HTTP/1.1'))
    writer.write_record(record)
    return writer.get_contents()


def truncate_file(path, cut_bytes):
    with open(path, 'rb') as handle:
        blob = handle.read()
    with open(path, 'wb') as handle:
        handle.write(blob[:-cut_bytes])
