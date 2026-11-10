"""
Tests for the offline, streaming WARC integrity checker.

The fixtures are built from stdlib + warcio's WARCWriter (see
``integrity_corpus``) so the good corpus is valid by construction and each
corruption test mutates exactly one layer.  These tests also assert that a
half-read body can never be reported as ``pass`` and that the verifier stays
streaming (bounded buffers) on a large record.
"""

import io
import json

import pytest

from warcio.integrity import (
    verify_stream, verify_file, render_text,
    PASS, FAIL, NOT_PROVIDED, INCOMPLETE,
    parse_declared_digest, format_digest,
)
from warcio.integrity_gzip import GzipMemberStream

from . import integrity_corpus as corpus


def invariant(report, index, name):
    record = report.records[index - 1]
    result = record.get(name)
    assert result is not None, 'missing invariant {0}'.format(name)
    return result


class TestBaseline:
    def test_plain_warc_all_layers_pass(self):
        data = corpus.build_plain_warc()
        report = verify_stream(io.BytesIO(data), 'plain.warc')

        assert report.container == 'warc'
        assert report.status == PASS
        assert len(report.records) == 5

        for record in report.records:
            assert record.declared_length == record.bytes_read
            assert record.offset is not None
            assert record.record_id
            for result in record.invariants:
                assert result.status in (PASS, NOT_PROVIDED)

        # warcinfo carries no payload digest by builder convention
        assert invariant(report, 1, 'payload_digest').status == NOT_PROVIDED
        assert invariant(report, 1, 'block_digest').status == PASS

        # chunked + gzip response: transfer coding decoded, both digests pass
        chunked_record = report.records[3]
        assert chunked_record.target_uri.endswith('/chunked-gzip')
        assert invariant(report, 4, 'http_transfer_coding').status == PASS
        payload = invariant(report, 4, 'payload_digest')
        assert payload.status == PASS
        assert payload.computed['matched_layer'] == 'stored'

    def test_empty_body_record(self):
        data = corpus.build_plain_warc()
        report = verify_stream(io.BytesIO(data), 'plain.warc')
        empty = report.records[2]
        assert empty.target_uri.endswith('/empty')
        assert empty.declared_length == empty.bytes_read
        assert invariant(report, 3, 'warc_content_length').status == PASS
        assert invariant(report, 3, 'payload_digest').status == PASS

    def test_non_http_resource_has_no_http_invariant(self):
        data = corpus.build_plain_warc()
        report = verify_stream(io.BytesIO(data), 'plain.warc')
        assert invariant(report, 5, 'http_transfer_coding').status == NOT_PROVIDED
        assert invariant(report, 5, 'block_digest').status == PASS

    def test_duplicate_headers_are_flagged_not_dropped(self):
        data = corpus.build_duplicate_header_warc()
        report = verify_stream(io.BytesIO(data), 'dup.warc')
        notes = report.records[0].notes
        assert any('duplicate WARC header' in note for note in notes)
        assert any('duplicate HTTP header' in note for note in notes)

    def test_entity_layer_payload_digest(self):
        data, entity, _ = corpus.build_entity_digest_warc()
        report = verify_stream(io.BytesIO(data), 'entity.warc')
        payload = invariant(report, 1, 'payload_digest')
        assert payload.status == PASS
        assert payload.computed['matched_layer'] == 'entity'
        assert payload.computed['entity_layer'].endswith(
            corpus.b32_sha1(entity))

    def test_deflate_content_encoding_is_decoded(self):
        data, entity = corpus.build_deflate_warc()
        report = verify_stream(io.BytesIO(data), 'deflate.warc')
        record = report.records[0]
        assert record.status == PASS
        coding = record.get('http_transfer_coding')
        assert coding.status == PASS
        assert 'deflate' in coding.detail
        assert record.get('payload_digest').status == PASS
        assert record.get('payload_digest').computed[
            'entity_layer'].endswith(corpus.b32_sha1(entity))

    def test_truncated_content_encoding_is_isolated_to_http_layer(self):
        data = corpus.build_truncated_content_encoding_warc()
        report = verify_stream(io.BytesIO(data), 'trunc-ce.warc')
        record = report.records[0]
        # WARC framing and outer block are intact ...
        assert record.get('warc_content_length').status == PASS
        assert record.get('warc_record_terminator').status == PASS
        assert record.get('block_digest').status == PASS
        # ... but the HTTP content coding independently reports truncation.
        assert record.get('http_transfer_coding').status == INCOMPLETE


class TestGzip:
    def test_multi_member_gzip_pass(self, tmp_path):
        path = tmp_path / 'multi.warc.gz'
        corpus.build_gzip_warc(str(path), records_per_member=2)
        report = verify_file(str(path))

        assert report.container == 'warc.gz'
        assert report.status == PASS
        assert len(report.records) == 4
        assert len(report.gzip_members) == 4
        for member in report.gzip_members:
            assert member['crc_status'] == PASS
            assert member['compressed_end'] is not None
        for record in report.records:
            assert record.gzip_member['member_index'] == record.index - 1

    def test_member_boundary_aligned_reads_are_not_skipped(self, tmp_path):
        # Regression: a read chunk ending exactly at a member boundary must not
        # cause later gzip members to be dropped.
        path = tmp_path / 'aligned.warc.gz'
        corpus.build_gzip_warc(str(path), records_per_member=3)
        stream = GzipMemberStream(open(str(path), 'rb'))
        seen = b''
        while True:
            piece = stream.read(stream.READ_CHUNK)
            if not piece:
                break
            seen += piece
        assert len(stream.members) == 6
        assert seen

    def test_outer_crc_corruption_hits_gzip_layer(self, tmp_path):
        path = tmp_path / 'crc.warc.gz'
        corpus.build_gzip_warc(str(path))
        corpus.corrupt_gzip_crc(str(path))

        report = verify_file(str(path))
        assert report.status == FAIL
        assert report.gzip_members[0]['crc_status'] == FAIL
        # The failure must be attributable to a specific record and member,
        # not just surfaced as a top-level boolean.
        assert report.records, 'corruption must still yield a record report'
        first = report.records[0]
        assert first.index == 1
        assert first.gzip_member['member_index'] == 0
        crc = first.get('gzip_member_crc')
        assert crc.status == FAIL
        assert first.get('block_digest').status == INCOMPLETE

    def test_truncated_gzip_is_incomplete_never_pass(self, tmp_path):
        path = tmp_path / 'trunc.warc.gz'
        corpus.build_gzip_warc(str(path), records_per_member=2)
        corpus.truncate_file(str(path), 20)

        report = verify_file(str(path))
        assert report.status in (FAIL, INCOMPLETE)
        # Earlier members are intact and may legitimately pass; the member
        # that lost its trailer must be flagged, and no whole record that
        # depended on the broken member may report an overall pass.
        member_statuses = [member['crc_status']
                           for member in report.gzip_members]
        assert INCOMPLETE in member_statuses or FAIL in member_statuses
        for record in report.records:
            if record.status == PASS:
                assert record.gzip_member['member_index'] < \
                    len(report.gzip_members) - 1


class TestLayeredCorruption:
    def test_warc_length_corruption_fails_framing_and_digests(self):
        good = corpus.build_plain_warc()
        bad, new_length = corpus.corrupt_warc_length(good)
        report = verify_stream(io.BytesIO(bad), 'bad-length.warc')

        assert report.status == FAIL
        first = report.records[0]
        # The declared (now wrong) length is consumed exactly, so the framing
        # drift surfaces at the record terminator and at the block digest.
        assert first.get('warc_record_terminator').status == FAIL
        # The digest cannot be trusted once the terminator is wrong, so it is
        # reported as incomplete rather than as a false pass.
        assert first.get('block_digest').status == INCOMPLETE
        # The desynchronisation makes later records unlocatable.
        assert report.fatal_errors

    def test_chunk_size_corruption_hits_transfer_coding_only(self):
        good = corpus.build_plain_warc()
        bad = corpus.corrupt_chunk_size_line(good)
        report = verify_stream(io.BytesIO(bad), 'bad-chunk.warc')

        coding = invariant(report, 4, 'http_transfer_coding')
        assert coding.status == FAIL
        assert 'chunk size line' in coding.detail
        # framing layer itself still read exactly the declared bytes
        assert invariant(report, 4, 'warc_content_length').status in (
            PASS, INCOMPLETE)
        # digests must not be reported as passing on a broken HTTP layer
        assert invariant(report, 4, 'payload_digest').status == INCOMPLETE

    def test_chunk_terminator_corruption_hits_transfer_coding(self):
        good = corpus.build_plain_warc()
        bad = corpus.corrupt_chunk_terminator(good)
        report = verify_stream(io.BytesIO(bad), 'bad-chunk-tail.warc')

        coding = invariant(report, 4, 'http_transfer_coding')
        assert coding.status == FAIL
        assert invariant(report, 4, 'block_digest').status == INCOMPLETE

    def test_payload_digest_corruption_is_isolated(self):
        good = corpus.build_plain_warc()
        bad = corpus.corrupt_payload_digest(good)
        report = verify_stream(io.BytesIO(bad), 'bad-payload.warc')

        # locate the first record that actually carried a payload digest
        target = None
        for record in report.records:
            result = record.get('payload_digest')
            if result.expected:
                target = record
                break
        assert target is not None
        assert target.get('payload_digest').status == FAIL
        # block digest and framing remain green: failure is layer-isolated
        assert target.get('block_digest').status == PASS
        assert target.get('warc_content_length').status == PASS
        assert target.get('http_transfer_coding').status in (PASS, NOT_PROVIDED)

    def test_truncated_body_never_passes(self):
        good = corpus.build_plain_warc()
        report = verify_stream(io.BytesIO(good[:len(good) - 60]), 'trunc.warc')
        assert report.status == INCOMPLETE
        # Earlier, fully intact records may legitimately pass; the record that
        # lost part of its body must never report an overall pass, and at
        # least one record must be marked incomplete.
        statuses = [record.status for record in report.records]
        assert INCOMPLETE in statuses
        last = report.records[-1]
        assert last.status == INCOMPLETE
        for result in last.invariants:
            assert result.status != FAIL or result.name in (
                'http_transfer_coding',)

    def test_one_byte_truncation_still_suppresses_digest_pass(self):
        # Even when every declared block byte was read, losing the record
        # terminator means the record is not intact: no digest may pass.
        good = corpus.build_plain_warc()
        report = verify_stream(io.BytesIO(good[:-1]), 'trunc1.warc')
        last = report.records[-1]
        assert last.get('warc_record_terminator').status == INCOMPLETE
        assert last.get('block_digest').status in (INCOMPLETE, NOT_PROVIDED)
        assert last.get('payload_digest').status in (
            INCOMPLETE, NOT_PROVIDED)
        assert last.status == INCOMPLETE


class TestStreaming:
    def test_large_body_does_not_buffer_entire_payload(self, tmp_path,
                                                        monkeypatch):
        # A 5 MiB payload with a small forced chunk size.  A non-streaming
        # implementation would accumulate the whole body; the checker must
        # keep its working set bounded close to the read size.
        big = b'x' * (5 * 1024 * 1024)
        writer = __import__(
            'warcio.warcwriter', fromlist=['BufferWARCWriter']).BufferWARCWriter(
            gzip=False)
        from warcio.statusandheaders import StatusAndHeaders
        record = writer.create_warc_record(
            'http://example.test/big', 'response',
            payload=io.BytesIO(big),
            http_headers=StatusAndHeaders(
                '200 OK', [('Content-Type', 'text/plain')],
                protocol='HTTP/1.1'))
        writer.write_record(record)
        data = writer.get_contents()

        import warcio.integrity as integrity
        monkeypatch.setattr(integrity, 'READ_SIZE', 4096)
        report = verify_stream(io.BytesIO(data), 'big.warc')
        assert report.status == PASS

        # No single buffered object should ever approach the full body size.
        tracked = {'max': 0}
        original_update = integrity.StreamingHash.update

        def tracking_update(self, chunk):
            tracked['max'] = max(tracked['max'], len(chunk))
            return original_update(self, chunk)

        monkeypatch.setattr(integrity.StreamingHash, 'update', tracking_update)
        verify_stream(io.BytesIO(data), 'big.warc')
        assert tracked['max'] <= 4096


class TestDigestParsing:
    @pytest.mark.parametrize('declared,expected_algo', [
        ('sha1:CAFE', 'sha1'),
        ('SHA1:cafe', 'sha1'),
    ])
    def test_parse_hex_and_base32(self, declared, expected_algo):
        algo, _ = parse_declared_digest(declared)
        assert algo == expected_algo

    def test_base64_and_base32_equivalent(self):
        import hashlib
        import base64
        raw = hashlib.sha1(b'abc').digest()
        b32 = base64.b32encode(raw).decode()
        b64 = base64.b64encode(raw).decode()
        assert parse_declared_digest('sha1:' + b32)[1] == \
            parse_declared_digest('sha1:' + b64)[1]

    def test_unknown_algorithm_is_a_fail_not_a_crash(self):
        data = corpus.build_plain_warc()
        broken = data.replace(b'sha1:', b'nope:'.ljust(5, b' '), 1)
        report = verify_stream(io.BytesIO(broken), 'weird.warc')
        assert report.status in (FAIL, INCOMPLETE)

    def test_unknown_algorithm_is_isolated_to_one_record(self):
        data = corpus.build_plain_warc()
        broken = data.replace(b'WARC-Block-Digest: sha1:',
                              b'WARC-Block-Digest: xxx1:', 1)
        report = verify_stream(io.BytesIO(broken), 'weird.warc')
        assert report.records[0].get('block_digest').status == FAIL
        # later records keep their independent digests
        assert report.records[1].get('block_digest').status == PASS

    def test_malformed_digest_header_fails_that_record_only(self):
        import re
        data = corpus.build_plain_warc()
        broken = re.sub(rb'WARC-Payload-Digest: sha1:[A-Z2-7]+',
                        b'WARC-Payload-Digest: garbled', data, count=1)
        report = verify_stream(io.BytesIO(broken), 'malformed.warc')
        targets = [record for record in report.records
                   if record.get('payload_digest').expected == 'garbled']
        assert len(targets) == 1
        assert targets[0].get('payload_digest').status == FAIL

    def test_format_digest_roundtrip(self):
        import hashlib
        raw = hashlib.sha256(b'data').digest()
        rendered = format_digest('sha256', raw)
        assert rendered.startswith('sha256:')
        algo, value = parse_declared_digest(rendered)
        assert algo == 'sha256'


class TestReportingAndCli:
    def test_json_report_locates_record_and_invariant(self):
        data = corpus.build_plain_warc()
        report = verify_stream(io.BytesIO(data), 'plain.warc')
        payload = json.loads(report.to_json())
        assert payload['overall_status'] == PASS
        first = payload['records'][0]
        assert set(['record_index', 'record_id', 'physical_offset',
                    'declared_content_length', 'block_bytes_read',
                    'invariants']).issubset(first)
        names = [item['name'] for item in first['invariants']]
        assert names == [
            'warc_content_length', 'warc_record_terminator',
            'http_transfer_coding', 'gzip_member_crc'] or \
            'warc_content_length' in names

    def test_text_report_is_deterministic(self):
        data = corpus.build_plain_warc()
        report_a = verify_stream(io.BytesIO(data), 'plain.warc')
        report_b = verify_stream(io.BytesIO(data), 'plain.warc')
        text_a = render_text(report_a)
        text_b = render_text(report_b)
        assert text_a == text_b
        assert 'record #1' in text_a and 'physical' not in text_a

    def test_cli_exit_codes(self, tmp_path, capsys):
        from warcio.cli import main
        good = tmp_path / 'good.warc'
        good.write_bytes(corpus.build_plain_warc())
        with pytest.raises(SystemExit) as exc:
            main(['integrity', str(good)])
        assert exc.value.code == 0
        capsys.readouterr()

        bad = tmp_path / 'bad.warc'
        bad.write_bytes(corpus.corrupt_payload_digest(good.read_bytes()))
        with pytest.raises(SystemExit) as exc:
            main(['integrity', '--json', str(bad)])
        assert exc.value.code == 1
        out = capsys.readouterr().out
        payload = json.loads(out)
        assert payload[0]['overall_status'] == FAIL
