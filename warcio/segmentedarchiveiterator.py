"""
Reassembly of WARC 1.1 segmented records (continuation records) into
single logical records.

The WARC 1.1 specification allows a single logical record to be split
into several physical records: the first segment keeps the record type
of the original record (e.g. ``response``) and every following segment
is written as a ``continuation`` record linked back to the first segment
with ``WARC-Segment-Origin-ID`` and ordered with
``WARC-Segment-Number``.

:class:`warcio.archiveiterator.ArchiveIterator` continues to yield the
physical records unchanged. :class:`SegmentedArchiveIterator` wraps it,
buffers the segments of each origin (spooling their bodies to disk) and
only yields a record once the whole logical record has been seen and
validated.  Non-segmented records are passed straight through.
"""

import os
import shutil
import tempfile
import uuid

from warcio.archiveiterator import ArchiveIterator
from warcio.bufferedreaders import BufferedReader
from warcio.recordloader import ArcWarcRecordLoader
from warcio.statusandheaders import StatusAndHeaders
from warcio.utils import BUFF_SIZE


# ============================================================================
class SegmentationError(Exception):
    """ Raised when the WARC 1.1 segmentation rules are violated.

    The offending origin id and the physical segment number are kept on
    the exception so callers can report precisely which group failed.
    """
    def __init__(self, message, origin_id=None, segment_number=None):
        self.origin_id = origin_id
        self.segment_number = segment_number
        if origin_id is not None or segment_number is not None:
            message = '{} (origin-id={}, segment-number={})'.format(
                message, origin_id, segment_number)
        super(SegmentationError, self).__init__(message)


# ============================================================================
class SpoolLimitExceeded(SegmentationError):
    """ Raised when too many incomplete groups are held open or their
    spooled bodies exceed the configured byte budget. """
    pass


# ============================================================================
class _SegmentGroup(object):
    """ Reassembly state for a single WARC-Segment-Origin-ID group. """

    def __init__(self, origin_id, spool_path, first_record):
        self.origin_id = origin_id
        self.spool_path = spool_path
        self.spool = open(spool_path, 'w+b')

        # logical record metadata is always taken from the first segment
        self.first_record = first_record
        self.next_number = 1
        self.total_length = 0

    def write_block(self, data):
        self.spool.write(data)
        self.total_length += len(data)

    def close(self):
        if not self.spool.closed:
            self.spool.close()


# ============================================================================
class SegmentedArchiveIterator(object):
    """ Iterate over *logical* WARC records.

    Physical records are read from ``source``: either an existing
    :class:`ArchiveIterator` or any file-like object accepted by it.
    Records without a ``WARC-Segment-Number`` header are yielded as they
    are.  Segmented records are buffered until the final segment of their
    origin arrives; only then is the reassembled logical record yielded.

    Segment bodies are spooled to a temporary directory.

    :param max_incomplete_groups: maximum number of origins allowed to be
        open (first segment seen, final segment not yet seen) at once.
    :param max_spool_bytes: maximum total number of block bytes allowed to
        be spooled across all incomplete groups.
    :param spool_dir: directory in which segment bodies are spooled.
    :raises SegmentationError: on duplicate, missing, backwards or
        non-contiguous segment numbers, or a wrong
        ``WARC-Segment-Total-Length``.
    :raises SpoolLimitExceeded: when one of the spool limits is exceeded.
    """

    def __init__(self, fileobj=None, source=None,
                 max_incomplete_groups=None, max_spool_bytes=None,
                 spool_dir=None, **archive_kwargs):

        if source is not None:
            self.archive_iter = source
        elif fileobj is not None:
            self.archive_iter = ArchiveIterator(fileobj, **archive_kwargs)
        else:
            raise TypeError('A file-like object or an ArchiveIterator '
                            'source must be provided')

        self.max_incomplete_groups = max_incomplete_groups
        self.max_spool_bytes = max_spool_bytes
        self.spool_dir = tempfile.mkdtemp(prefix='warcio-segments-',
                                          dir=spool_dir)

        # origin id -> _SegmentGroup, insertion order tracks arrival
        self.groups = dict()
        self.spooled_bytes = 0
        self.loader = ArcWarcRecordLoader()
        self._closed = False

    def __iter__(self):
        return self._iterate()

    # ------------------------------------------------------------------
    def _iterate(self):
        try:
            for record in self.archive_iter:
                logical = self._process_record(record)
                if logical is not None:
                    yield logical
        finally:
            # failure (including SegmentationError) or early break: drop
            # everything spooled for this file
            self.close()

    # ------------------------------------------------------------------
    def _process_record(self, record):
        segment_number = self._parse_segment_number(record)
        if segment_number is None:
            # ordinary, non-segmented physical record
            return record

        origin_id = record.rec_headers.get_header('WARC-Segment-Origin-ID')

        if segment_number == 1:
            return self._start_group(record, origin_id)

        # continuation segment: it must belong to a known origin
        if not origin_id:
            raise SegmentationError(
                'continuation record without WARC-Segment-Origin-ID',
                segment_number=segment_number)
        group = self.groups.get(origin_id)
        if group is None:
            raise SegmentationError(
                'continuation record for unknown origin (no first segment)',
                origin_id, segment_number)

        return self._append_segment(group, record, segment_number)

    # ------------------------------------------------------------------
    def _start_group(self, record, origin_id):
        if origin_id is None:
            origin_id = record.rec_headers.get_header('WARC-Record-ID')

        if origin_id in self.groups:
            raise SegmentationError(
                'duplicate first segment for origin',
                origin_id, 1)

        if (self.max_incomplete_groups is not None and
                len(self.groups) >= self.max_incomplete_groups):
            raise SpoolLimitExceeded(
                'number of incomplete segment groups exceeds limit of '
                '{}'.format(self.max_incomplete_groups),
                origin_id, 1)

        spool_path = os.path.join(
            self.spool_dir, 'seg-{}.warc'.format(uuid.uuid4().hex))
        group = _SegmentGroup(origin_id, spool_path, record)
        self.groups[origin_id] = group
        self._drain_block(group, record)
        group.next_number = 2

        # a single-segment record may carry the total length directly on
        # its first (and only) segment
        declared_total = record.rec_headers.get_header(
            'WARC-Segment-Total-Length')
        if declared_total is not None:
            self._check_total_length(group, declared_total, 1)
            return self._build_logical_record(group)

        return None

    # ------------------------------------------------------------------
    def _append_segment(self, group, record, segment_number):
        if segment_number != group.next_number:
            if segment_number < group.next_number:
                reason = 'segment number went backwards'
            else:
                reason = ('missing segment: expected segment {} but got '
                          'segment {}').format(group.next_number,
                                               segment_number)
            raise SegmentationError(
                reason, group.origin_id, segment_number)

        self._drain_block(group, record)
        group.next_number += 1

        declared_total = record.rec_headers.get_header(
            'WARC-Segment-Total-Length')
        if declared_total is not None:
            self._check_total_length(group, declared_total, segment_number)
            return self._build_logical_record(group)

        return None

    # ------------------------------------------------------------------
    def _drain_block(self, group, record):
        """ Spool the full content block of one physical segment.

        HTTP headers are part of the first segment's block; continuation
        records have no HTTP headers, so their WARC headers are never
        written into the spooled body.
        """
        if record.http_headers:
            if record.http_headers.headers_buff is None:
                record.http_headers.compute_headers_buffer()
            self._write_spooled(group, record.http_headers.headers_buff)

        raw_stream = record.raw_stream
        while True:
            buff = raw_stream.read(BUFF_SIZE)
            if not buff:
                break
            self._write_spooled(group, buff)

    # ------------------------------------------------------------------
    def _write_spooled(self, group, data):
        if (self.max_spool_bytes is not None and
                self.spooled_bytes + len(data) > self.max_spool_bytes):
            raise SpoolLimitExceeded(
                'spooled segment bytes exceed limit of {}'
                .format(self.max_spool_bytes),
                group.origin_id, group.next_number)

        group.write_block(data)
        self.spooled_bytes += len(data)

    # ------------------------------------------------------------------
    def _check_total_length(self, group, declared_total, segment_number):
        try:
            declared_total = int(declared_total)
        except (TypeError, ValueError):
            raise SegmentationError(
                'WARC-Segment-Total-Length is not an integer: {!r}'
                .format(declared_total),
                group.origin_id, segment_number)

        if declared_total != group.total_length:
            raise SegmentationError(
                'WARC-Segment-Total-Length mismatch: declared {} but the '
                'reassembled block is {} bytes'
                .format(declared_total, group.total_length),
                group.origin_id, segment_number)

    # ------------------------------------------------------------------
    def _build_logical_record(self, group):
        first_headers = group.first_record.rec_headers

        # copy headers, dropping the segmentation control fields so the
        # delivered record looks like the original, unsplit record
        logical_headers = StatusAndHeaders(
            first_headers.statusline,
            list(first_headers.headers),
            protocol=first_headers.protocol)
        for header in ('WARC-Segment-Number',
                       'WARC-Segment-Origin-ID',
                       'WARC-Segment-Total-Length'):
            logical_headers.remove_header(header)
        logical_headers.replace_header('Content-Length',
                                       str(group.total_length))

        # write the complete, reconstructed record (WARC headers + block)
        # to its own file, then let the standard loader parse it so the
        # result is indistinguishable from a non-segmented record
        record_path = os.path.join(
            self.spool_dir, 'rec-{}.warc'.format(uuid.uuid4().hex))
        group.spool.flush()
        group.spool.seek(0)
        with open(record_path, 'w+b') as record_file:
            record_file.write(logical_headers.to_bytes(encoding='utf-8'))
            shutil.copyfileobj(group.spool, record_file, BUFF_SIZE)
            record_file.write(b'\r\n\r\n')

        block_stream = BufferedReader(open(record_path, 'rb'))

        try:
            logical_record = self.loader.parse_record_stream(
                block_stream, known_format='warc')
        finally:
            # the delivered record keeps record_path open, so that file
            # is removed with the spool directory on close(); drop the
            # group's own spool now that the block has been copied
            self._remove_group(group)
        return logical_record

    # ------------------------------------------------------------------
    def _remove_group(self, group):
        group.close()
        self.spooled_bytes -= group.total_length
        if self.spooled_bytes < 0:
            self.spooled_bytes = 0
        del self.groups[group.origin_id]
        try:
            os.remove(group.spool_path)
        except OSError:
            pass

    # ------------------------------------------------------------------
    @staticmethod
    def _parse_segment_number(record):
        raw = record.rec_headers.get_header('WARC-Segment-Number')
        if raw is None:
            return None
        try:
            number = int(raw)
        except (TypeError, ValueError):
            raise SegmentationError(
                'WARC-Segment-Number is not an integer: {!r}'.format(raw))
        if number < 1:
            raise SegmentationError(
                'WARC-Segment-Number must be >= 1, got {}'.format(number),
                segment_number=number)
        return number

    # ------------------------------------------------------------------
    @property
    def incomplete(self):
        """ Origins whose first segment was seen but never completed.

        Maps origin id to the number of contiguous segments buffered.
        """
        return dict((origin_id, group.next_number - 1)
                    for origin_id, group in self.groups.items())

    # ------------------------------------------------------------------
    def close(self):
        """ Release every spooled group and remove the spool directory.

        All buffered bytes and files are deleted, but the origin ids (and
        how many segments each had buffered) are retained so that
        :attr:`incomplete` stays meaningful after iteration ends.
        """
        if self._closed:
            return
        self._closed = True

        for group in list(self.groups.values()):
            group.close()
        self.spooled_bytes = 0

        shutil.rmtree(self.spool_dir, ignore_errors=True)

        archive_iter = getattr(self, 'archive_iter', None)
        if archive_iter is not None and hasattr(archive_iter, 'close'):
            archive_iter.close()
