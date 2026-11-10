#!/usr/bin/env python
# -*- coding: utf-8 -*-

from warcio.archiveiterator import ArchiveIterator
from warcio.rawedit import (RawBlockEditor, RawBlockEditError,
                            DigestVerificationFailed, ComputedHeaderEditError,
                            apply_header_edits)
from warcio.statusandheaders import StatusAndHeaders
from warcio.utils import Digester

from io import BytesIO

import zlib

import pytest


# ============================================================================
def make_gzip_body(data):
    compressor = zlib.compressobj(9, zlib.DEFLATED, 16 + zlib.MAX_WBITS)
    return compressor.compress(data) + compressor.flush()


def make_chunk(data, ext=b''):
    return b'%x%s\r\n%s\r\n' % (len(data), ext, data)


# gzip content-encoded payload, sent in two chunks, the first with
# chunk extensions, plus a trailer after the zero chunk
GZIP_PAYLOAD = make_gzip_body(b'Hello, raw block!')

HTTP_BLOCK = (
    b'HTTP/1.1 200 OK\r\n'
    b'Content-Type: text/html; charset=UTF-8\r\n'
    b'Transfer-Encoding: chunked\r\n'
    b'Content-Encoding: gzip\r\n'
    b'X-Dup: one\r\n'
    b'x-dup: two\r\n'
    b'\r\n'
    + make_chunk(GZIP_PAYLOAD[:10], b';foo=bar;baz="qux"')
    + make_chunk(GZIP_PAYLOAD[10:])
    + b'0;last=yes\r\nX-Trailer: t\r\n\r\n'
)


def block_digest(block=HTTP_BLOCK, algo='sha1'):
    digester = Digester(algo)
    digester.update(block)
    return str(digester)


def make_warc_record(block=HTTP_BLOCK, extra_headers=(), with_digest=True):
    lines = [
        'WARC/1.0',
        'WARC-Type: response',
        'WARC-Record-ID: <urn:uuid:12345678-feb0-11e6-8f83-68a86d1772ce>',
        'WARC-Target-URI: http://example.com/old',
        'WARC-Date: 2000-01-01T00:00:00Z',
    ]
    if with_digest:
        lines.append('WARC-Block-Digest: ' + block_digest(block))
    lines.append('X-Dup-Warc: a')
    lines.append('X-Other: keep')
    lines.append('X-Dup-Warc: b')
    lines.extend(extra_headers)
    lines.append('Content-Type: application/http; msgtype=response')
    lines.append('Content-Length: ' + str(len(block)))
    head = '\r\n'.join(lines).encode('utf-8') + b'\r\n\r\n'
    return head + block + b'\r\n\r\n'


def gzip_member(data):
    compressor = zlib.compressobj(9, zlib.DEFLATED, 16 + zlib.MAX_WBITS)
    return compressor.compress(data) + compressor.flush()


def run_edit(src, edits=(), gzip_out=False, max_mem_size=512 * 1024):
    out = BytesIO()
    editor = RawBlockEditor(max_mem_size=max_mem_size)
    results = []
    for record in ArchiveIterator(src, no_record_parse=True):
        results.append(editor.write_record(record, out, edits=edits,
                                           gzip=gzip_out))
    return out.getvalue(), results


def read_raw_records(data):
    records = []
    for record in ArchiveIterator(BytesIO(data), no_record_parse=True):
        records.append((record.rec_headers, record.raw_stream.read()))
    return records


def header_values(rec_headers, name):
    name_lower = name.lower()
    return [value for curr_name, value in rec_headers.headers
            if curr_name.lower() == name_lower]


class ForwardOnly(object):
    def __init__(self, data):
        self.stream = BytesIO(data)

    def read(self, size=-1):
        return self.stream.read(size)


EDITS = [
    ('set', 'WARC-Target-URI', 'http://example.com/fixed'),
    ('add', 'X-Collection-Tag', 'crawl-2026'),
]


# ============================================================================
class TestRawBlockEdit(object):
    def check_edited_record(self, rec_headers, block):
        # raw block preserved byte-for-byte
        assert block == HTTP_BLOCK

        # outer length and digest recomputed from the actual block
        assert rec_headers.get_header('Content-Length') == str(len(HTTP_BLOCK))
        assert rec_headers.get_header('WARC-Block-Digest') == block_digest()

        # edits applied
        assert rec_headers.get_header('WARC-Target-URI') == 'http://example.com/fixed'
        assert rec_headers.get_header('X-Collection-Tag') == 'crawl-2026'

        # unmodified duplicate warc headers preserved, in order
        assert header_values(rec_headers, 'X-Dup-Warc') == ['a', 'b']
        assert rec_headers.get_header('X-Other') == 'keep'

    def test_plain_warc_block_preserved(self):
        src = make_warc_record()
        out, results = run_edit(BytesIO(src), EDITS)

        assert len(results) == 1
        assert results[0].verified is True
        assert results[0].length == len(HTTP_BLOCK)

        records = read_raw_records(out)
        assert len(records) == 1
        self.check_edited_record(*records[0])

    def test_gzip_warc_block_preserved(self):
        # per-record gzip container on the way in and out
        src = gzip_member(make_warc_record())
        out, results = run_edit(BytesIO(src), EDITS, gzip_out=True)

        assert len(results) == 1
        assert results[0].verified is True

        # unwrap the outer gzip container, then compare the raw block
        records = read_raw_records(out)
        assert len(records) == 1
        self.check_edited_record(*records[0])

        # output is a single well-formed gzip member
        assert zlib.decompress(out, 16 + zlib.MAX_WBITS).startswith(b'WARC/1.0')

    def test_http_details_byte_identical(self):
        src = make_warc_record()
        out, _ = run_edit(BytesIO(src), EDITS)
        _, block = read_raw_records(out)[0]

        # duplicate http headers and casing
        assert b'X-Dup: one\r\nx-dup: two\r\n' in block
        # chunk extension preserved
        assert b';foo=bar;baz="qux"\r\n' in block
        # compressed body still compressed, still decodable
        chunked = block.split(b'\r\n\r\n', 1)[1]
        assert GZIP_PAYLOAD[:10] in chunked
        assert zlib.decompress(GZIP_PAYLOAD, 16 + zlib.MAX_WBITS) == b'Hello, raw block!'

    def test_unseekable_input(self):
        src = make_warc_record()
        out, results = run_edit(ForwardOnly(src), EDITS)

        assert results[0].verified is True
        records = read_raw_records(out)
        self.check_edited_record(*records[0])

    def test_unseekable_gzip_input(self):
        src = gzip_member(make_warc_record())
        out, results = run_edit(ForwardOnly(src), EDITS, gzip_out=True)

        assert results[0].verified is True
        records = read_raw_records(out)
        self.check_edited_record(*records[0])

    def test_mem_threshold_spill_same_output(self):
        src = make_warc_record()
        out_mem, _ = run_edit(BytesIO(src), EDITS)
        # tiny in-memory threshold forces spooling to a temp file
        out_disk, _ = run_edit(BytesIO(src), EDITS, max_mem_size=1)

        assert out_mem == out_disk

    def test_truncated_record_writes_nothing(self):
        src = make_warc_record()
        truncated = src[:len(src) - 10]

        out = BytesIO()
        editor = RawBlockEditor()
        with pytest.raises(RawBlockEditError):
            for record in ArchiveIterator(BytesIO(truncated), no_record_parse=True):
                editor.write_record(record, out, edits=EDITS)

        # no partial record claiming to be complete
        assert out.getvalue() == b''

    def test_digest_mismatch_writes_nothing(self):
        src = make_warc_record().replace(
            ('WARC-Block-Digest: ' + block_digest()).encode('utf-8'),
            b'WARC-Block-Digest: sha1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')

        out = BytesIO()
        editor = RawBlockEditor()
        with pytest.raises(DigestVerificationFailed):
            for record in ArchiveIterator(BytesIO(src), no_record_parse=True):
                editor.write_record(record, out, edits=EDITS)

        assert out.getvalue() == b''

    def test_missing_digest_not_claimed_verified(self):
        src = make_warc_record(with_digest=False)
        out, results = run_edit(BytesIO(src), EDITS)

        # no original digest: verification is not claimed
        assert results[0].verified is None

        # a fresh digest is still computed for the output
        rec_headers, block = read_raw_records(out)[0]
        assert block == HTTP_BLOCK
        assert rec_headers.get_header('WARC-Block-Digest') == block_digest()

    def test_sha256_digest_verified(self):
        block = HTTP_BLOCK
        src = make_warc_record(block).replace(
            ('WARC-Block-Digest: ' + block_digest(block)).encode('utf-8'),
            ('WARC-Block-Digest: ' + block_digest(block, 'sha256')).encode('utf-8'))

        out, results = run_edit(BytesIO(src), EDITS)
        assert results[0].verified is True


# ============================================================================
class TestHeaderEdits(object):
    def make_headers(self):
        return StatusAndHeaders('', [
            ('WARC-Type', 'response'),
            ('X-Dup', 'a'),
            ('X-Other', 'keep'),
            ('X-Dup', 'b'),
        ], protocol='WARC/1.0')

    def names_values(self, headers):
        return list(headers.headers)

    def test_set_replaces_all_occurrences(self):
        headers = self.make_headers()
        apply_header_edits(headers, [('set', 'x-dup', 'only')])

        # single header, at the position of the first occurrence
        assert self.names_values(headers) == [
            ('WARC-Type', 'response'),
            ('x-dup', 'only'),
            ('X-Other', 'keep'),
        ]

    def test_set_all_replaces_with_multiple(self):
        headers = self.make_headers()
        apply_header_edits(headers, [('set_all', 'X-Dup', ['1', '2', '3'])])

        assert self.names_values(headers) == [
            ('WARC-Type', 'response'),
            ('X-Dup', '1'),
            ('X-Dup', '2'),
            ('X-Dup', '3'),
            ('X-Other', 'keep'),
        ]

    def test_set_at_replaces_single_occurrence(self):
        headers = self.make_headers()
        apply_header_edits(headers, [('set_at', 'X-Dup', 1, 'B')])

        assert self.names_values(headers) == [
            ('WARC-Type', 'response'),
            ('X-Dup', 'a'),
            ('X-Other', 'keep'),
            ('X-Dup', 'B'),
        ]

    def test_set_at_out_of_range(self):
        headers = self.make_headers()
        with pytest.raises(IndexError):
            apply_header_edits(headers, [('set_at', 'X-Dup', 2, 'C')])

    def test_add_appends_keeping_duplicates(self):
        headers = self.make_headers()
        apply_header_edits(headers, [('add', 'X-Dup', 'c')])

        assert header_values(headers, 'X-Dup') == ['a', 'b', 'c']

    def test_remove_all_occurrences(self):
        headers = self.make_headers()
        apply_header_edits(headers, [('remove', 'X-Dup')])

        assert self.names_values(headers) == [
            ('WARC-Type', 'response'),
            ('X-Other', 'keep'),
        ]

    def test_set_new_header_appended(self):
        headers = self.make_headers()
        apply_header_edits(headers, [('set', 'X-New', 'v')])

        assert headers.headers[-1] == ('X-New', 'v')

    @pytest.mark.parametrize('name', ['Content-Length', 'content-length',
                                      'WARC-Block-Digest', 'warc-block-digest'])
    def test_computed_headers_forbidden(self, name):
        headers = self.make_headers()
        with pytest.raises(ComputedHeaderEditError):
            apply_header_edits(headers, [('set', name, '1')])
        with pytest.raises(ComputedHeaderEditError):
            apply_header_edits(headers, [('remove', name)])

    def test_unknown_operation(self):
        headers = self.make_headers()
        with pytest.raises(ValueError):
            apply_header_edits(headers, [('bogus', 'X-Dup', 'v')])

    def test_forbidden_edit_writes_nothing(self):
        src = make_warc_record()
        out = BytesIO()
        editor = RawBlockEditor()
        with pytest.raises(ComputedHeaderEditError):
            for record in ArchiveIterator(BytesIO(src), no_record_parse=True):
                editor.write_record(record, out,
                                    edits=[('set', 'Content-Length', '1')])

        assert out.getvalue() == b''
