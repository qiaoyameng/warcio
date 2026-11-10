"""
Tests for WARC 1.1 segmented record reassembly.

The physical records (first segment + continuation records) are written
with the regular WARCWriter; SegmentedArchiveIterator must put them back
together into a single logical record while ArchiveIterator keeps
returning the individual physical records.
"""

import io
import os

import pytest

from warcio.archiveiterator import ArchiveIterator
from warcio.statusandheaders import StatusAndHeaders
from warcio.warcwriter import WARCWriter
from warcio.segmentedarchiveiterator import (
    SegmentedArchiveIterator,
    SegmentationError,
    SpoolLimitExceeded,
)


# ============================================================================
def http_headers():
    return StatusAndHeaders('200 OK', [('Content-Type', 'text/plain')],
                            protocol='HTTP/1.1')


def make_segmented_response(writer, label, uri, body_parts):
    """ Build the physical records of one split response.

    Returns the origin id and the ordered list of physical records.  The
    final record carries WARC-Segment-Total-Length set to the sum of every
    physical content block, as required by the WARC 1.1 specification.
    """
    origin_id = '<urn:uuid:origin-{}>'.format(label)
    records = []

    for index, part in enumerate(body_parts):
        number = index + 1
        if number == 1:
            record = writer.create_warc_record(
                uri, 'response',
                payload=io.BytesIO(part), length=len(part),
                http_headers=http_headers(),
                warc_headers_dict={'WARC-Segment-Number': '1'})
            record.rec_headers.replace_header('WARC-Record-ID', origin_id)
        else:
            record = writer.create_warc_record(
                '', 'continuation',
                payload=io.BytesIO(part), length=len(part),
                warc_headers_dict={
                    'WARC-Segment-Number': str(number),
                    'WARC-Segment-Origin-ID': origin_id})
        records.append(record)

    total_length = 0
    for record in records:
        if record.http_headers:
            record.http_headers.compute_headers_buffer()
            total_length += len(record.http_headers.headers_buff)
        total_length += record.length
    records[-1].rec_headers.add_header(
        'WARC-Segment-Total-Length', str(total_length))

    return origin_id, records


def build_warc(records, gzip=False):
    buffer = io.BytesIO()
    writer = WARCWriter(buffer, gzip=gzip, warc_version='WARC/1.1')
    for record in records:
        writer.write_record(record)
    return buffer.getvalue()


def logical_records(data, **kwargs):
    """ Consume the logical iterator, reading each body immediately. """
    result = []
    for record in SegmentedArchiveIterator(io.BytesIO(data), **kwargs):
        result.append((record, record.content_stream().read()))
    return result


# ============================================================================
def test_reassembles_single_segmented_response():
    origin_id, records = make_segmented_response(
        WARCWriter(io.BytesIO(), warc_version='WARC/1.1'),
        'a', 'http://a.example/', [b'AAAA', b'BBBB'])
    data = build_warc(records)

    out = logical_records(data)
    assert len(out) == 1
    record, body = out[0]

    assert record.rec_type == 'response'
    assert record.rec_headers.get_header('WARC-Record-ID') == origin_id
    assert record.rec_headers.get_header('WARC-Target-URI') == \
        'http://a.example/'
    assert record.http_headers.statusline == '200 OK'
    assert record.http_headers.get_header('Content-Type') == 'text/plain'
    assert body == b'AAAABBBB'

    # the delivered logical record no longer carries segmentation headers
    assert record.rec_headers.get_header('WARC-Segment-Number') is None
    assert record.rec_headers.get_header('WARC-Segment-Origin-ID') is None
    assert record.rec_headers.get_header('WARC-Segment-Total-Length') is None


def test_http_headers_come_only_from_first_segment():
    _, records = make_segmented_response(
        WARCWriter(io.BytesIO(), warc_version='WARC/1.1'),
        'a', 'http://a.example/', [b'AAAA', b'BBBB'])
    data = build_warc(records)

    record, body = logical_records(data)[0]
    # raw_stream spans the whole reassembled block: HTTP headers + body,
    # but never any continuation record's WARC headers
    record.http_headers.compute_headers_buffer()
    full_block = record.http_headers.headers_buff + body
    assert full_block.startswith(b'HTTP/1.1 200 OK')
    assert b'WARC-Type' not in full_block
    assert b'continuation' not in full_block
    assert b'WARC-Segment-Origin-ID' not in full_block


def test_archive_iterator_still_returns_physical_records():
    _, records = make_segmented_response(
        WARCWriter(io.BytesIO(), warc_version='WARC/1.1'),
        'a', 'http://a.example/', [b'AAAA', b'BBBB'])
    data = build_warc(records)

    physical = [(r.rec_type,
                 r.rec_headers.get_header('WARC-Segment-Number'),
                 r.rec_headers.get_header('WARC-Segment-Origin-ID'))
                for r in ArchiveIterator(io.BytesIO(data))]
    assert physical == [
        ('response', '1', None),
        ('continuation', '2', '<urn:uuid:origin-a>'),
    ]


def test_two_interleaved_responses_complete_independently():
    """ Two origins interleaved: one finishes in the middle, the other only
    at the end.  Logical records are delivered in completion order. """
    writer = WARCWriter(io.BytesIO(), warc_version='WARC/1.1')
    origin_a, recs_a = make_segmented_response(
        writer, 'a', 'http://a.example/', [b'A1', b'A2', b'A3'])
    origin_b, recs_b = make_segmented_response(
        writer, 'b', 'http://b.example/', [b'B1', b'B2'])

    # A1, B1, A2, B2 (B completes), A3 (A completes)
    interleaved = [recs_a[0], recs_b[0], recs_a[1], recs_b[1], recs_a[2]]
    data = build_warc(interleaved)

    out = logical_records(data)
    assert [r.rec_headers.get_header('WARC-Record-ID') for r, _ in out] == \
        [origin_b, origin_a]
    assert out[0][1] == b'B1B2'
    assert out[1][1] == b'A1A2A3'


def test_deleted_segment_other_origin_still_completes():
    """ Delete one physical segment of origin A.  Origin B must still be
    delivered, while A must never surface as a normal logical record. """
    writer = WARCWriter(io.BytesIO(), warc_version='WARC/1.1')
    origin_a, recs_a = make_segmented_response(
        writer, 'a', 'http://a.example/', [b'A1', b'A2', b'A3'])
    origin_b, recs_b = make_segmented_response(
        writer, 'b', 'http://b.example/', [b'B1', b'B2'])

    interleaved = [recs_a[0], recs_b[0], recs_a[1], recs_b[1], recs_a[2]]
    full_data = build_warc(interleaved)

    # physically remove A's middle segment (segment number 2).  Each
    # physical record is re-emitted in the same iteration, before
    # ArchiveIterator advances and drains its stream.
    damaged_buffer = io.BytesIO()
    rewriter = WARCWriter(damaged_buffer, gzip=False, warc_version='WARC/1.1')
    removed_origin = None
    for record in ArchiveIterator(io.BytesIO(full_data)):
        number = record.rec_headers.get_header('WARC-Segment-Number')
        origin = record.rec_headers.get_header('WARC-Segment-Origin-ID')
        if number == '2' and origin == origin_a:
            removed_origin = origin
            continue
        rewriter.write_record(record)
    assert removed_origin == origin_a
    damaged_data = damaged_buffer.getvalue()

    delivered = []
    iterator = SegmentedArchiveIterator(io.BytesIO(damaged_data))
    with pytest.raises(SegmentationError) as exc_info:
        for record in iterator:
            delivered.append(
                (record.rec_headers.get_header('WARC-Record-ID'),
                 record.content_stream().read()))

    # B completed before A's gap was discovered
    assert delivered == [(origin_b, b'B1B2')]

    error = exc_info.value
    assert error.origin_id == origin_a
    assert error.segment_number == 3
    assert 'missing segment' in str(error)

    # A is never delivered as a normal record
    assert all(origin != origin_a for origin, _ in delivered)
    # the damaged run cleans its spool directory up
    assert not os.path.exists(iterator.spool_dir)


def test_missing_terminal_segment_is_incomplete_not_a_record():
    """ Drop the final segment: no total-length header ever arrives, so at
    end of input the origin is reported as incomplete rather than yielded. """
    _, records = make_segmented_response(
        WARCWriter(io.BytesIO(), warc_version='WARC/1.1'),
        'a', 'http://a.example/', [b'A1', b'A2'])
    data = build_warc(records[:1])  # keep only segment 1

    iterator = SegmentedArchiveIterator(io.BytesIO(data))
    delivered = list(iterator)

    assert delivered == []
    assert iterator.incomplete == {'<urn:uuid:origin-a>': 1}


def test_duplicate_segment_reports_origin_and_number():
    _, records = make_segmented_response(
        WARCWriter(io.BytesIO(), warc_version='WARC/1.1'),
        'a', 'http://a.example/', [b'A1', b'A2'])
    # segment 1 twice, then segment 2: the repeated first segment must fail
    data = build_warc([records[0], records[0], records[1]])

    with pytest.raises(SegmentationError) as exc_info:
        logical_records(data)
    assert exc_info.value.origin_id == '<urn:uuid:origin-a>'
    assert exc_info.value.segment_number == 1
    assert 'duplicate' in str(exc_info.value)


def test_segment_number_backwards():
    _, records = make_segmented_response(
        WARCWriter(io.BytesIO(), warc_version='WARC/1.1'),
        'a', 'http://a.example/', [b'A1', b'A2', b'A3'])
    # 1, 2, then 2 again -> backwards / duplicate
    data = build_warc([records[0], records[1], records[1]])

    with pytest.raises(SegmentationError) as exc_info:
        logical_records(data)
    error = exc_info.value
    assert error.origin_id == '<urn:uuid:origin-a>'
    assert error.segment_number == 2
    assert 'backwards' in str(error)


def test_continuation_with_unknown_origin():
    writer = WARCWriter(io.BytesIO(), warc_version='WARC/1.1')
    record = writer.create_warc_record(
        '', 'continuation', payload=io.BytesIO(b'X'), length=1,
        warc_headers_dict={
            'WARC-Segment-Number': '2',
            'WARC-Segment-Origin-ID': '<urn:uuid:ghost>'})
    data = build_warc([record])

    with pytest.raises(SegmentationError) as exc_info:
        logical_records(data)
    assert exc_info.value.origin_id == '<urn:uuid:ghost>'
    assert exc_info.value.segment_number == 2


def test_wrong_total_length():
    _, records = make_segmented_response(
        WARCWriter(io.BytesIO(), warc_version='WARC/1.1'),
        'a', 'http://a.example/', [b'A1', b'A2'])
    records[-1].rec_headers.replace_header(
        'WARC-Segment-Total-Length', '999')
    data = build_warc(records)

    with pytest.raises(SegmentationError) as exc_info:
        logical_records(data)
    error = exc_info.value
    assert error.origin_id == '<urn:uuid:origin-a>'
    assert error.segment_number == 2
    assert 'Total-Length mismatch' in str(error)


def test_non_segmented_records_pass_through():
    writer = WARCWriter(io.BytesIO(), warc_version='WARC/1.1')
    record = writer.create_warc_record(
        'http://x.example/', 'response',
        payload=io.BytesIO(b'plain body'), length=10,
        http_headers=http_headers())
    data = build_warc([record])

    out = logical_records(data)
    assert len(out) == 1
    assert out[0][0].rec_type == 'response'
    assert out[0][1] == b'plain body'


def test_max_incomplete_groups_limit():
    writer = WARCWriter(io.BytesIO(), warc_version='WARC/1.1')
    _, recs_a = make_segmented_response(
        writer, 'a', 'http://a.example/', [b'A1', b'A2'])
    _, recs_b = make_segmented_response(
        writer, 'b', 'http://b.example/', [b'B1', b'B2'])
    # two first segments without any terminating segment
    data = build_warc([recs_a[0], recs_b[0]])

    with pytest.raises(SpoolLimitExceeded) as exc_info:
        logical_records(data, max_incomplete_groups=1)
    assert exc_info.value.origin_id == '<urn:uuid:origin-b>'


def test_max_spool_bytes_limit():
    _, records = make_segmented_response(
        WARCWriter(io.BytesIO(), warc_version='WARC/1.1'),
        'a', 'http://a.example/', [b'A1', b'A2'])
    data = build_warc([records[0]])

    with pytest.raises(SpoolLimitExceeded):
        logical_records(data, max_spool_bytes=1)


def test_early_break_removes_spool_directory():
    _, records = make_segmented_response(
        WARCWriter(io.BytesIO(), warc_version='WARC/1.1'),
        'a', 'http://a.example/', [b'A1', b'A2'])
    data = build_warc([records[0]])

    iterator = SegmentedArchiveIterator(io.BytesIO(data))
    spool_dir = iterator.spool_dir
    assert os.path.isdir(spool_dir)
    for _ in iterator:
        break
    assert not os.path.exists(spool_dir)


def test_explicit_close_is_idempotent_and_cleans_spool():
    _, records = make_segmented_response(
        WARCWriter(io.BytesIO(), warc_version='WARC/1.1'),
        'a', 'http://a.example/', [b'A1', b'A2'])
    data = build_warc([records[0]])

    iterator = SegmentedArchiveIterator(io.BytesIO(data))
    spool_dir = iterator.spool_dir
    assert os.path.isdir(spool_dir)

    iterator.close()
    assert not os.path.exists(spool_dir)
    # closing twice must not raise
    iterator.close()


def test_gzipped_warc_reassembly():
    _, records = make_segmented_response(
        WARCWriter(io.BytesIO(), warc_version='WARC/1.1'),
        'a', 'http://a.example/', [b'A1', b'A2'])
    data = build_warc(records, gzip=True)

    record, body = logical_records(data)[0]
    assert record.rec_type == 'response'
    assert body == b'A1A2'


def test_single_segment_with_total_length_is_delivered():
    """ A first segment that also carries WARC-Segment-Total-Length is a
    complete, single-segment logical record and must be delivered. """
    writer = WARCWriter(io.BytesIO(), warc_version='WARC/1.1')
    record = writer.create_warc_record(
        'http://a.example/', 'response',
        payload=io.BytesIO(b'ONLY'), length=4,
        http_headers=http_headers(),
        warc_headers_dict={'WARC-Segment-Number': '1'})
    record.rec_headers.replace_header('WARC-Record-ID',
                                      '<urn:uuid:origin-a>')
    record.http_headers.compute_headers_buffer()
    total = len(record.http_headers.headers_buff) + record.length
    record.rec_headers.add_header(
        'WARC-Segment-Total-Length', str(total))
    data = build_warc([record])

    iterator = SegmentedArchiveIterator(io.BytesIO(data))
    delivered = [(r, r.content_stream().read()) for r in iterator]
    assert len(delivered) == 1
    assert delivered[0][1] == b'ONLY'
    assert iterator.incomplete == {}


def test_accepts_existing_archive_iterator():
    _, records = make_segmented_response(
        WARCWriter(io.BytesIO(), warc_version='WARC/1.1'),
        'a', 'http://a.example/', [b'A1', b'A2'])
    data = build_warc(records)

    source = ArchiveIterator(io.BytesIO(data))
    out = []
    for record in SegmentedArchiveIterator(source=source):
        out.append((record, record.content_stream().read()))
    assert out[0][1] == b'A1A2'
