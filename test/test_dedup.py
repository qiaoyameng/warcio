#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os

from io import BytesIO

import pytest

from warcio.archiveiterator import ArchiveIterator
from warcio.dedup import RevisitDeduper, RevisitIndex, INDEX_SUFFIX
from warcio.exceptions import ArchiveLoadFailed
from warcio.recordbuilder import RecordBuilder
from warcio.statusandheaders import StatusAndHeaders
from warcio.utils import Digester
from warcio.warcwriter import WARCWriter


URI = 'http://example.com/'
OTHER_URI = 'http://other.com/'

BODY = b'example body\n'
OTHER_BODY = b'some other body\n'

RID_1 = '<urn:uuid:00000000-0000-0000-0000-000000000001>'
RID_2 = '<urn:uuid:00000000-0000-0000-0000-000000000002>'
RID_3 = '<urn:uuid:00000000-0000-0000-0000-000000000003>'
RID_4 = '<urn:uuid:00000000-0000-0000-0000-000000000004>'
RID_5 = '<urn:uuid:00000000-0000-0000-0000-000000000005>'

D1 = '2020-01-01T00:00:00Z'
D2 = '2020-02-01T00:00:00Z'
D3 = '2020-03-01T00:00:00Z'
D4 = '2020-04-01T00:00:00Z'
D5 = '2020-05-01T00:00:00Z'


# ============================================================================
def digest_of(body):
    digester = Digester('sha1')
    digester.update(body)
    return str(digester)


BODY_DIGEST = digest_of(BODY)


def make_response(date, body=BODY, uri=URI, statusline='200 OK',
                  headers=None, rid=None):
    if headers is None:
        headers = [('Content-Type', 'text/plain')]

    http_headers = StatusAndHeaders(statusline, headers, protocol='HTTP/1.1')

    warc_headers_dict = {'WARC-Date': date}
    if rid:
        warc_headers_dict['WARC-Record-ID'] = rid

    return RecordBuilder().create_warc_record(uri, 'response',
                                              payload=BytesIO(body),
                                              length=len(body),
                                              http_headers=http_headers,
                                              warc_headers_dict=warc_headers_dict)


def make_chunked_record(uri, date, rid, body):
    chunks = [body[:5], body[5:]]
    http = b'HTTP/1.1 200 OK\r\n'
    http += b'Content-Type: text/plain\r\n'
    http += b'Transfer-Encoding: chunked\r\n'
    http += b'\r\n'
    for chunk in chunks:
        http += b'%x\r\n' % len(chunk) + chunk + b'\r\n'
    http += b'0\r\n\r\n'

    headers = ('WARC/1.0\r\n'
               'WARC-Type: response\r\n'
               'WARC-Record-ID: {0}\r\n'
               'WARC-Target-URI: {1}\r\n'
               'WARC-Date: {2}\r\n'
               'Content-Type: application/http; msgtype=response\r\n'
               'Content-Length: {3}\r\n'
               '\r\n').format(rid, uri, date, len(http))

    return headers.encode('utf-8') + http + b'\r\n\r\n'


def write_records(path, records, append=False):
    mode = 'ab' if append else 'wb'
    with open(str(path), mode) as out:
        writer = WARCWriter(out, gzip=False)
        for record in records:
            writer.write_record(record)


def read_output(path):
    records = []
    with open(str(path), 'rb') as fh:
        for record in ArchiveIterator(fh):
            decoded = None
            if record.rec_type == 'response':
                decoded = record.content_stream().read()

            records.append((record, decoded))

    return records


def resolve_payloads(paths):
    """Resolve every capture to its decoded body, following revisits to
    the referred response.  Returns (records, resolved payloads).
    """
    payloads = {}
    ordered = []
    for path in paths:
        for record, decoded in read_output(path):
            ordered.append((record, decoded))
            if record.rec_type == 'response':
                record_id = record.rec_headers.get_header('WARC-Record-ID')
                payloads[record_id] = decoded

    resolved = []
    for record, decoded in ordered:
        if record.rec_type == 'response':
            resolved.append(decoded)
        elif record.rec_type == 'revisit':
            refers_to = record.rec_headers.get_header('WARC-Refers-To')
            resolved.append(payloads.get(refers_to))

    return [record for record, _ in ordered], resolved


def convert(tmp_path, inputs, allowed=(URI,), **kwargs):
    deduper = RevisitDeduper(str(tmp_path / 'index'), allowed, **kwargs)
    return deduper.convert([str(path) for path in inputs],
                           str(tmp_path / 'out'))


# ============================================================================
class TestDedup(object):
    def test_same_body_different_status_headers(self, tmp_path):
        """Identical decoded bodies dedupe even when the HTTP status line
        and headers differ; transfer-encoded (chunked) records compare by
        their decoded payload.  Revisits are never used as referents.
        """
        input_path = tmp_path / 'input1.warc'

        rec1 = make_response(D1, rid=RID_1)
        rec2 = make_response(D2, statusline='404 Not Found',
                             headers=[('Content-Type', 'text/html'),
                                      ('Server', 'test-server')],
                             rid=RID_2)
        # an existing revisit in the input: passed through, never a referent
        rec4 = RecordBuilder().create_revisit_record(
            URI, BODY_DIGEST,
            refers_to_uri=URI, refers_to_date=D1,
            warc_headers_dict={'WARC-Date': D4, 'WARC-Record-ID': RID_4})
        rec5 = make_response(D5, rid=RID_5)

        write_records(input_path, [rec1, rec2])
        with open(str(input_path), 'ab') as fh:
            fh.write(make_chunked_record(URI, D3, RID_3, BODY))
        write_records(input_path, [rec4, rec5], append=True)

        outputs = convert(tmp_path, [input_path])

        records, resolved = resolve_payloads(outputs)
        assert [rec.rec_type for rec in records] == \
            ['response', 'revisit', 'revisit', 'revisit', 'revisit']
        assert resolved == [BODY, BODY, BODY, None, BODY]

        # status line and HTTP headers of the current capture are kept
        out2 = records[1]
        assert out2.http_headers.statusline == '404 Not Found'
        assert out2.http_headers.get_header('Server') == 'test-server'
        assert out2.rec_headers.get_header('WARC-Profile') == \
            RecordBuilder.REVISIT_PROFILE
        assert out2.rec_headers.get_header('WARC-Payload-Digest') == BODY_DIGEST
        assert out2.rec_headers.get_header('WARC-Refers-To') == RID_1
        assert out2.rec_headers.get_header('WARC-Refers-To-Target-URI') == URI
        assert out2.rec_headers.get_header('WARC-Refers-To-Date') == D1
        assert out2.rec_headers.get_header('WARC-Date') == D2

        # chunked record deduped by its decoded payload
        out3 = records[2]
        assert out3.rec_headers.get_header('WARC-Refers-To') == RID_1
        assert out3.rec_headers.get_header('WARC-Payload-Digest') == BODY_DIGEST

        # pre-existing revisit passed through unchanged
        out4 = records[3]
        assert out4.rec_headers.get_header('WARC-Record-ID') == RID_4
        assert out4.rec_headers.get_header('WARC-Refers-To-Date') == D1
        assert out4.rec_headers.get_header('WARC-Refers-To') is None

        # later record refers to the first response, not to any revisit
        out5 = records[4]
        assert out5.rec_headers.get_header('WARC-Refers-To') == RID_1

    def test_forged_digest_not_trusted(self, tmp_path):
        """Stored WARC-Payload-Digest values are recomputed, never trusted:
        a forged digest neither prevents a real duplicate from deduping nor
        makes different bodies collide.
        """
        input_path = tmp_path / 'input1.warc'

        rec1 = make_response(D1, rid=RID_1)
        rec2 = make_response(D2, rid=RID_2)
        rec3 = make_response(D3, body=OTHER_BODY, rid=RID_3)

        rec1.rec_headers.replace_header('WARC-Payload-Digest',
                                        'sha1:' + 'A' * 32)
        rec2.rec_headers.replace_header('WARC-Payload-Digest',
                                        'sha1:' + 'B' * 32)
        # claims to have BODY's digest, actually carries OTHER_BODY
        rec3.rec_headers.replace_header('WARC-Payload-Digest', BODY_DIGEST)

        write_records(input_path, [rec1, rec2, rec3])

        outputs = convert(tmp_path, [input_path], gzip=False)

        records, resolved = resolve_payloads(outputs)
        assert [rec.rec_type for rec in records] == \
            ['response', 'revisit', 'response']
        assert resolved == [BODY, BODY, OTHER_BODY]

        # forged digest on the response is corrected
        assert records[0].rec_headers.get_header('WARC-Payload-Digest') == \
            BODY_DIGEST
        # revisit carries the recomputed digest and refers to the response
        assert records[1].rec_headers.get_header('WARC-Payload-Digest') == \
            BODY_DIGEST
        assert records[1].rec_headers.get_header('WARC-Refers-To') == RID_1
        # different body with a forged matching digest stays a full response
        assert records[2].rec_headers.get_header('WARC-Payload-Digest') == \
            digest_of(OTHER_BODY)

    def test_reverse_chronological_order(self, tmp_path):
        """A record may only refer to a capture that is not later than
        itself; ties are broken stably by (date, record-id).
        """
        input_path = tmp_path / 'input1.warc'

        rec1 = make_response('2020-06-01T00:00:00Z', rid=RID_1)
        rec2 = make_response('2020-01-01T00:00:00Z', rid=RID_2)
        rec3 = make_response('2020-12-01T00:00:00Z', rid=RID_3)

        write_records(input_path, [rec1, rec2, rec3])

        outputs = convert(tmp_path, [input_path], gzip=False)

        records, resolved = resolve_payloads(outputs)
        assert [rec.rec_type for rec in records] == \
            ['response', 'response', 'revisit']
        assert resolved == [BODY, BODY, BODY]

        # the earlier-dated rec2 can not refer to the later-dated rec1
        assert records[1].rec_headers.get_header('WARC-Record-ID') == RID_2

        # rec3 refers to the earliest qualified candidate
        out3 = records[2]
        assert out3.rec_headers.get_header('WARC-Refers-To') == RID_2
        assert out3.rec_headers.get_header('WARC-Refers-To-Date') == \
            '2020-01-01T00:00:00Z'

    def test_failed_conversion_publishes_no_index(self, tmp_path):
        """The index is published only after its output has landed; a
        failed conversion leaves nothing a retry could refer to.
        """
        index_dir = tmp_path / 'index'
        out_dir = tmp_path / 'out'
        input1 = tmp_path / 'input1.warc'
        input2 = tmp_path / 'input2.warc'

        write_records(input1, [make_response(D1, rid=RID_1)])

        deduper = RevisitDeduper(str(index_dir), [URI], gzip=False)
        outputs1 = deduper.convert([str(input1)], str(out_dir))
        assert sorted(os.listdir(str(index_dir))) == \
            ['input1.warc' + INDEX_SUFFIX]

        # second input is corrupt after its first record
        write_records(input2, [make_response(D2, rid=RID_2)])
        with open(str(input2), 'ab') as fh:
            fh.write(b'this is not a warc record\r\n\r\n')

        with pytest.raises(ArchiveLoadFailed):
            deduper.convert([str(input2)], str(out_dir))

        # nothing from the failed attempt remains
        assert not os.path.exists(str(out_dir / 'input2.warc'))
        assert not os.path.exists(str(out_dir / 'input2.warc.tmp'))
        assert sorted(os.listdir(str(index_dir))) == \
            ['input1.warc' + INDEX_SUFFIX]

        # retry with a fixed input in a fresh run: only records from
        # successfully published outputs can be referred to
        write_records(input2, [make_response(D2, rid=RID_2),
                               make_response(D3, rid=RID_3)])

        deduper = RevisitDeduper(str(index_dir), [URI], gzip=False)
        outputs2 = deduper.convert([str(input2)], str(out_dir))

        records, resolved = resolve_payloads(outputs1 + outputs2)
        assert [rec.rec_type for rec in records] == \
            ['response', 'revisit', 'revisit']
        assert resolved == [BODY, BODY, BODY]
        assert records[1].rec_headers.get_header('WARC-Refers-To') == RID_1
        assert records[2].rec_headers.get_header('WARC-Refers-To') == RID_1

        assert sorted(os.listdir(str(index_dir))) == \
            ['input1.warc' + INDEX_SUFFIX, 'input2.warc' + INDEX_SUFFIX]

    def test_allowed_uri_scope(self, tmp_path):
        """Responses outside the allowed URI range pass through in full
        and are never registered as referents.
        """
        input_path = tmp_path / 'input1.warc'

        write_records(input_path, [make_response(D1, uri=OTHER_URI, rid=RID_1),
                                   make_response(D2, rid=RID_2),
                                   make_response(D3, uri=OTHER_URI, rid=RID_3)])

        outputs = convert(tmp_path, [input_path], gzip=False)

        records, resolved = resolve_payloads(outputs)
        assert [rec.rec_type for rec in records] == \
            ['response', 'response', 'response']
        assert resolved == [BODY, BODY, BODY]

        index = RevisitIndex(str(tmp_path / 'index'))
        index.load()
        entries = list(index.iter_entries(URI, BODY_DIGEST))
        assert [entry['record_id'] for entry in entries] == [RID_2]
        assert list(index.iter_entries(OTHER_URI, BODY_DIGEST)) == []
