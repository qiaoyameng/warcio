import io
import json
import os
import pickle
import zlib

import pytest

from warcio.recordbuilder import RecordBuilder
from warcio.warcwriter import BufferWARCWriter
from warcio.recordindex import (
    build_record_index,
    load_record_index,
    RecordIndex,
    IndexBuildError,
    IndexValidationError,
    _GzipPump,
    _SingleGzipMemberReader,
)


RECORD_IDS = ['<urn:uuid:alpha-1>',
              '<urn:uuid:beta-2>',
              '<urn:uuid:gamma-3>',
              '<urn:uuid:alpha-1>']
CONTENT_IDENTITY = 'snapshot-42'


def make_pairs(ids=None):
    """Fresh (record, expected payload) pairs; records are write-once."""
    ids = RECORD_IDS if ids is None else ids
    builder = RecordBuilder()
    pairs = []
    for position, record_id in enumerate(ids):
        payload = ('payload-{0}-'.format(position)).encode() * 64
        record = builder.create_warc_record(
            'http://example.com/{0}'.format(position), 'resource',
            payload=io.BytesIO(payload),
            warc_headers_dict={'WARC-Record-ID': record_id})
        pairs.append((record, payload))
    return pairs


def write_plain(pairs):
    writer = BufferWARCWriter(gzip=False)
    for record in _records(pairs):
        writer.write_record(record)
    return writer.get_contents()


def write_single_member_gzip(pairs):
    writer = BufferWARCWriter(gzip=True)
    for record in _records(pairs):
        writer.write_record(record)
    return writer.get_contents()


def _records(pairs):
    return [item[0] if isinstance(item, tuple) else item
            for item in pairs]


def gzip_member(pairs):
    raw = write_plain(_records(pairs))
    compressor = zlib.compressobj(9, zlib.DEFLATED, zlib.MAX_WBITS + 16)
    return compressor.compress(raw) + compressor.flush()


def write_multi_member_gzip(pairs):
    midpoint = len(pairs) // 2
    return (gzip_member(pairs[:midpoint]) +
            gzip_member(pairs[midpoint:]))


@pytest.fixture
def archives(tmp_path):
    paths = {}
    builders = {
        'plain': (write_plain, 'warc'),
        'single': (write_single_member_gzip, 'warc.gz'),
        'multi': (write_multi_member_gzip, 'warc.gz'),
    }
    for label, (builder, suffix) in builders.items():
        path = tmp_path / ('archive-{0}.{1}'.format(label, suffix))
        path.write_bytes(builder(make_pairs()))
        paths[label] = str(path)
    return paths


@pytest.fixture
def indexes(tmp_path, archives):
    built = {}
    for label, path in archives.items():
        index_path = str(tmp_path / ('index-{0}.jsonl'.format(label)))
        built[label] = build_record_index(
            path, index_path, CONTENT_IDENTITY)
    return built


# ============================================================================
class TestBuildAndOffsets(object):
    def test_index_is_versioned_json_not_pickle(self, tmp_path, archives):
        path = archives['plain']
        index_path = str(tmp_path / 'index.jsonl')
        build_record_index(path, index_path, CONTENT_IDENTITY)

        raw = open(index_path, 'rb').read()
        # must be human-readable JSON lines, never a pickle stream
        assert not raw.startswith(b'\x80')
        with pytest.raises(Exception):
            pickle.loads(raw)

        lines = raw.decode('utf-8').splitlines()
        header = json.loads(lines[0])
        footer = json.loads(lines[-1])
        assert header['type'] == 'warcio-record-index'
        assert header['version'] == 1
        assert header['file_size'] == os.path.getsize(path)
        assert header['content_identity'] == CONTENT_IDENTITY
        assert footer['type'] == 'warcio-record-index-footer'
        assert footer['entries'] == len(RECORD_IDS)
        assert len(lines) == footer['entries'] + 2

    def test_plain_offsets(self, indexes, archives):
        index = indexes['plain']
        assert index.is_gzip is False
        assert len(index) == len(RECORD_IDS)
        for entry in index:
            assert entry.gzip_member_offset is None
            # plain WARC: record offset and member-internal offset coincide
            assert entry.offset == entry.member_record_offset
        # offsets are strictly increasing and physical
        offsets = [e.offset for e in index]
        assert offsets == sorted(offsets)
        assert offsets[0] == 0

    def test_single_member_gzip_offsets(self, indexes):
        index = indexes['single']
        assert index.is_gzip is True
        for entry in index:
            # one gzip member per record: every member starts at the record
            assert entry.gzip_member_offset == entry.offset
            assert entry.member_record_offset == 0
        member_starts = [e.gzip_member_offset for e in index]
        assert member_starts == sorted(set(member_starts))

    def test_multi_member_gzip_offsets(self, indexes):
        index = indexes['multi']
        assert index.is_gzip is True
        members = [e.gzip_member_offset for e in index]
        # two members, two records each; member start is shared
        assert sorted(set(members)) == [members[0], members[2]]
        first_member, second_member = members[0], members[2]
        local_offsets = [e.member_record_offset for e in index]
        # the member-internal offset is a decompressed offset, restarting
        # at zero for the second member
        assert local_offsets[0] == 0
        assert local_offsets[1] > 0
        assert local_offsets[2] == 0
        assert local_offsets[3] == local_offsets[1]
        # file offset points at the member, never at a decompressed position
        for entry in index:
            assert entry.offset == entry.gzip_member_offset
        assert first_member < second_member

    def test_duplicate_record_id_keeps_all_locations_in_order(self, indexes):
        for index in indexes.values():
            locations = index.lookup('<urn:uuid:alpha-1>')
            assert len(locations) == 2
            physical = [index.entries.index(loc) for loc in locations]
            assert physical == [0, 3]
            assert '<urn:uuid:alpha-1>' in index
            assert index.lookup('<urn:uuid:missing>') == []

    def test_declared_length_and_span_present(self, indexes):
        for index in indexes.values():
            for entry in index:
                assert entry.content_length > 0
                assert entry.record_span > entry.content_length


# ============================================================================
class TestFetchAndRanges(object):
    def test_fetch_every_record_matches_payload(self, tmp_path, indexes,
                                                archives):
        for label, index in indexes.items():
            expected_pairs = make_pairs()
            with index.open_session(archives[label]) as session:
                for position, entry in enumerate(index.entries):
                    result = session.fetch(entry)
                    assert result.record.rec_headers.get_header(
                        'WARC-Record-ID') == entry.record_id
                    assert result.record.raw_stream.read() == \
                        expected_pairs[position][1]

    def test_fetch_all_duplicate_returns_both(self, tmp_path, indexes,
                                              archives):
        expected_pairs = make_pairs()
        for label, index in indexes.items():
            with index.open_session(archives[label]) as session:
                results = session.fetch_all('<urn:uuid:alpha-1>')
                assert [r.entry for r in results] == \
                    index.lookup('<urn:uuid:alpha-1>')
                assert results[0].record.raw_stream.read() == \
                    expected_pairs[0][1]
                assert results[1].record.raw_stream.read() == \
                    expected_pairs[3][1]

    def test_plain_random_access_touches_only_record_intervals(
            self, indexes, archives):
        index = indexes['plain']
        with index.open_session(archives['plain']) as session:
            entry = index.entries[1]
            result = session.fetch(entry)
            # raw interval is exactly this one record
            assert result.raw_start == entry.offset
            assert result.raw_end == entry.offset + entry.record_span
            assert session.ranges == [
                (entry.offset, entry.offset + entry.record_span)]
            assert session.bytes_read == entry.record_span

    def test_gzip_multi_member_random_access_interval(self, indexes,
                                                      archives):
        index = indexes['multi']
        second_member = index.entries[2].gzip_member_offset
        file_size = os.path.getsize(archives['multi'])
        # block_size=1 makes the member boundary observable immediately, so
        # the logical fetch interval ends exactly at the member start
        with index.open_session(archives['multi'], block_size=1) as session:
            # the second record of member zero forces decompression of the
            # whole member from its own start; the logical interval ends at
            # the next member's raw offset
            result = session.fetch(index.entries[1])
            assert result.raw_start == 0
            assert result.raw_end == second_member
            assert session.ranges == [(0, second_member + 1)]

        # a fresh session targeting member two starts exactly at its offset
        with index.open_session(archives['multi'], block_size=1) as session:
            result_two = session.fetch(index.entries[2])
            assert result_two.raw_start == second_member
            assert result_two.raw_end == file_size
            assert session.ranges == [(second_member, file_size)]
            assert session.bytes_read == file_size - second_member

    def test_single_member_gzip_interval_covers_member(self, indexes,
                                                       archives):
        index = indexes['single']
        with index.open_session(archives['single']) as session:
            result = session.fetch(index.entries[0])
            assert result.raw_start == 0
            assert result.raw_end == index.entries[1].gzip_member_offset

    def test_fetch_does_not_seek_decompressed_offset(self, indexes,
                                                     archives, monkeypatch):
        # Guard against the classic mistake of seeking the raw gzip file to
        # a decompressed member-internal offset.
        index = indexes['multi']
        target = index.entries[1]
        assert target.member_record_offset > 0
        seen_seeks = []
        session = index.open_session(archives['multi'])
        raw_seek = session.fh.seek

        def tracking_seek(offset, whence=0):
            seen_seeks.append(offset)
            return raw_seek(offset, whence)

        monkeypatch.setattr(session.fh, 'seek', tracking_seek)
        session.fetch(target)
        # every raw seek must target a known member start, never `d`
        member_starts = sorted({e.gzip_member_offset for e in index.entries})
        assert all(offset in member_starts for offset in seen_seeks)
        assert target.member_record_offset not in seen_seeks
        session.close()


# ============================================================================
class TestValidationAndErrors(object):
    def test_content_identity_checked_on_load(self, tmp_path, archives):
        path = archives['plain']
        index_path = str(tmp_path / 'idx.jsonl')
        build_record_index(path, index_path, CONTENT_IDENTITY)
        load_record_index(index_path, CONTENT_IDENTITY, path)
        with pytest.raises(IndexValidationError):
            load_record_index(index_path, 'different-identity', path)

    def test_file_size_checked_on_session(self, tmp_path, archives):
        path = archives['plain']
        index_path = str(tmp_path / 'idx.jsonl')
        index = build_record_index(path, index_path, CONTENT_IDENTITY)
        with open(path, 'ab') as fh:
            fh.write(b'extra bytes')
        with pytest.raises(IndexValidationError):
            index.open_session(path)

    def test_truncated_index_rejected(self, tmp_path, archives):
        path = archives['plain']
        index_path = str(tmp_path / 'idx.jsonl')
        build_record_index(path, index_path, CONTENT_IDENTITY)
        raw = open(index_path, 'rb').read()
        open(index_path, 'wb').write(raw[:len(raw) // 2])
        with pytest.raises(IndexValidationError):
            load_record_index(index_path, CONTENT_IDENTITY, path)

    def test_tampered_index_checksum_rejected(self, tmp_path, archives):
        path = archives['plain']
        index_path = str(tmp_path / 'idx.jsonl')
        build_record_index(path, index_path, CONTENT_IDENTITY)
        lines = open(index_path, 'r', encoding='utf-8').read().splitlines()
        entry = json.loads(lines[1])
        entry['o'] = entry['o'] + 999
        lines[1] = json.dumps(entry, sort_keys=True)
        open(index_path, 'w', encoding='utf-8').write('\n'.join(lines))
        with pytest.raises(IndexValidationError):
            load_record_index(index_path, CONTENT_IDENTITY, path)

    def test_wrong_version_rejected(self, tmp_path, archives):
        path = archives['plain']
        index_path = str(tmp_path / 'idx.jsonl')
        build_record_index(path, index_path, CONTENT_IDENTITY)
        lines = open(index_path, 'r', encoding='utf-8').read().splitlines()
        header = json.loads(lines[0])
        header['version'] = 999
        lines[0] = json.dumps(header, sort_keys=True)
        open(index_path, 'w', encoding='utf-8').write('\n'.join(lines))
        with pytest.raises(IndexValidationError):
            load_record_index(index_path, CONTENT_IDENTITY, path)

    def test_tampered_record_id_detected_on_fetch(self, tmp_path):
        # build the index from the good archive, then tamper a record header
        # without touching the index: the mismatch must surface on fetch.
        good_path = str(tmp_path / 'good.warc')
        good_data = write_plain(make_pairs())
        open(good_path, 'wb').write(good_data)
        index = build_record_index(good_path,
                                   str(tmp_path / 'good.jsonl'),
                                   CONTENT_IDENTITY)
        path = str(tmp_path / 'tampered.warc')
        data = write_plain(make_pairs())
        marker = b'WARC-Record-ID: <urn:uuid:beta-2>'
        replacement = b'WARC-Record-ID: <urn:uuid:evil-x>'
        assert marker in data
        data = data.replace(marker, replacement, 1)
        open(path, 'wb').write(data)
        with index.open_session(path) as session:
            with pytest.raises(IndexValidationError):
                session.fetch(index.entries[1])

    def test_tampered_payload_length_detected(self, tmp_path):
        pairs = make_pairs()
        path = str(tmp_path / 'len.warc')
        data = write_plain(pairs)
        marker = b'Content-Length: '
        first = data.find(marker)
        line_end = data.find(b'\r\n', first)
        original = data[first + len(marker):line_end]
        bogus = str(int(original) + 50).encode()
        data = data[:first + len(marker)] + bogus + data[line_end:]
        open(path, 'wb').write(data)
        with pytest.raises(IndexBuildError):
            build_record_index(path, str(tmp_path / 'i.jsonl'),
                               CONTENT_IDENTITY)

    def test_bad_record_reports_position_and_no_index_left(
            self, tmp_path, archives):
        source = archives['multi']
        path = str(tmp_path / 'broken.warc.gz')
        data = open(source, 'rb').read()
        # truncate the tail: final gzip member becomes incomplete
        open(path, 'wb').write(data[:-20])
        index_path = str(tmp_path / 'should-not-exist.jsonl')
        with pytest.raises(IndexBuildError) as exc_info:
            build_record_index(path, index_path, CONTENT_IDENTITY)
        assert exc_info.value.raw_offset is not None
        assert not os.path.exists(index_path)
        # no temp file left behind either
        assert not [name for name in os.listdir(str(tmp_path))
                    if name.startswith('.warcio-index-')]

    def test_invalid_warc_header_reports_offset(self, tmp_path):
        path = str(tmp_path / 'bad.warc')
        open(path, 'wb').write(b'NOT-WARC\r\n\r\n')
        with pytest.raises(IndexBuildError) as exc_info:
            build_record_index(path, str(tmp_path / 'i.jsonl'),
                               CONTENT_IDENTITY)
        assert exc_info.value.decompressed_offset == 0

    def test_empty_archive_rejected(self, tmp_path):
        path = str(tmp_path / 'empty.warc')
        open(path, 'wb').write(b'')
        with pytest.raises(IndexBuildError):
            build_record_index(path, str(tmp_path / 'i.jsonl'),
                               CONTENT_IDENTITY)

    def test_bytes_content_identity_accepted(self, tmp_path, archives):
        path = archives['plain']
        index_path = str(tmp_path / 'idx.jsonl')
        build_record_index(path, index_path, b'byte-identity')
        index = load_record_index(index_path, b'byte-identity', path)
        assert index.content_identity == 'byte-identity'


# ============================================================================
class TestGzipPumpUnit(object):
    def test_member_boundaries_across_arbitrary_chunks(self):
        member_one = gzip_member(make_pairs(RECORD_IDS[:2]))
        member_two = gzip_member(make_pairs(RECORD_IDS[2:]))
        data = member_one + member_two
        for chunk_size in (1, 7, 64, 4096):
            pump = _GzipPump()
            for start in range(0, len(data), chunk_size):
                pump.feed(data[start:start + chunk_size])
            pump.finish()
            assert len(pump.member_starts) == 2
            assert pump.member_starts[1][0] == len(member_one)
            assert pump.member_starts[0][1] == 0
            assert pump.member_starts[1][1] > 0

    def test_single_member_reader_stays_inside_member(self, tmp_path):
        member_one = gzip_member(make_pairs(RECORD_IDS[:2]))
        member_two = gzip_member(make_pairs(RECORD_IDS[2:]))
        path = tmp_path / 'mm.gz'
        path.write_bytes(member_one + member_two)
        with open(str(path), 'rb') as fh:
            reader = _SingleGzipMemberReader(fh, 0)
            decompressed = reader.read()
            # EOF inside the raw file means it stopped at the boundary
            assert fh.tell() == len(member_one)
            # local offsets restart for a fresh reader
            reader_two = _SingleGzipMemberReader(fh, len(member_one))
            assert reader_two.read(4) == b'WARC'
            assert reader_two.tell() == 4
        assert b'WARC/1.0' in decompressed

    def test_large_member_spanning_many_read_blocks(self, tmp_path):
        # payloads larger than READ_CHUNK so members span multiple reads
        builder = RecordBuilder()

        def big_record(record_id, position):
            return builder.create_warc_record(
                'http://example.com/big/{0}'.format(position), 'resource',
                payload=io.BytesIO(b'z' * 20000),
                warc_headers_dict={'WARC-Record-ID': record_id})

        member_one = gzip_member([big_record('<m1a>', 0)])
        member_two = gzip_member([big_record('<m2a>', 1),
                                  big_record('<m2b>', 2)])
        member_three = gzip_member([big_record('<m3a>', 3)])
        path = tmp_path / 'big.warc.gz'
        path.write_bytes(member_one + member_two + member_three)
        index = build_record_index(str(path), str(tmp_path / 'big.jsonl'),
                                   CONTENT_IDENTITY)
        member_starts = sorted({e.gzip_member_offset for e in index.entries})

        with index.open_session(str(path)) as session:
            # second record inside the middle member: the whole middle
            # member must be decompressed from its own start
            target = index.lookup('<m2b>')[0]
            assert target.member_record_offset > 0
            result = session.fetch(target)
            assert result.raw_start == member_starts[1]
            assert result.raw_end == member_starts[2]
            assert len(result.record.raw_stream.read()) == 20000

            last = index.lookup('<m3a>')[0]
            result_last = session.fetch(last)
            assert result_last.raw_start == member_starts[2]
            assert result_last.raw_end == path.stat().st_size
