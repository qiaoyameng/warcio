"""
Streaming, member-aware gzip reader used by the offline integrity checker.

The standard library :class:`gzip.GzipFile` hides gzip member boundaries and
does not expose per-member CRC32/ISIZE failures in a way that can be attached
to a specific WARC record.  This module provides a small forward-only reader
built directly on :mod:`zlib` that:

* never holds an entire gzip member (or record body) in memory;
* tracks the compressed-file offset of every byte it consumes;
* reports each gzip member's compressed byte range and CRC/trailer status;
* surfaces truncation (member declared but never finished) distinctly from a
  failed CRC, so a half-read body can never be reported as passing.

Implementation note: each gzip member gets its own
:class:`zlib.decompressobj`, driven one bounded raw chunk at a time *without*
an output length cap.  This keeps input accounting unambiguous (zlib reports
any following member's bytes through ``unused_data``), while decompressed
output is split into fixed-size pages so peak memory is bounded by
:data:`PAGE_SIZE` regardless of body size.
"""

import zlib
from collections import deque


GZIP_MAGIC = b'\x1f\x8b'


class GzipFormatError(Exception):
    """Raised when a gzip member cannot be decoded (bad CRC/trailer/header)."""


class GzipMemberInfo(object):
    """
    Metadata for one physical gzip member.

    ``comp_start`` / ``comp_end`` are offsets in the underlying compressed
    file.  ``crc_status`` is one of:

    * ``'pass'``       - member reached its trailer and CRC32 + ISIZE match;
    * ``'fail'``       - trailer present but CRC32 or ISIZE mismatched;
    * ``'incomplete'`` - underlying stream ended before the trailer.
    """

    __slots__ = ('index', 'comp_start', 'comp_end', 'crc_status', 'error',
                 'decomp_end')

    def __init__(self, index, comp_start):
        self.index = index
        self.comp_start = comp_start
        self.comp_end = None
        self.crc_status = 'incomplete'
        self.error = None
        self.decomp_end = None

    def as_dict(self):
        return {
            'member_index': self.index,
            'compressed_start': self.comp_start,
            'compressed_end': self.comp_end,
            'crc_status': self.crc_status,
            'error': self.error,
        }


class GzipMemberStream(object):
    """
    Forward-only stream over the *decompressed* bytes of a (possibly
    multi-member) gzip file, with per-member CRC and offset bookkeeping.
    """

    READ_CHUNK = 65536
    PAGE_SIZE = 65536

    def __init__(self, stream):
        self._stream = stream
        self._raw = b''
        self._raw_pos = 0
        self._decomp = zlib.decompressobj(31)
        self._members = []
        self._current = GzipMemberInfo(0, 0)
        self._members.append(self._current)
        self._eof = False
        self._fatal = None
        self._pages = deque()
        self._buffered = 0
        self._decomp_total = 0

    @property
    def members(self):
        return list(self._members)

    def current_member(self):
        return self._current

    def member_at_position(self, decompressed_position):
        """Return the member owning a given decompressed-stream offset."""
        owner = self._members[-1]
        for member in self._members:
            if member.decomp_end is None or \
                    decompressed_position <= member.decomp_end:
                owner = member
                break
        return owner

    def _start_next_member(self):
        self._current.comp_end = self._raw_pos
        if self._current.crc_status == 'incomplete':
            self._current.crc_status = 'pass'
        self._current.decomp_end = self._decomp_total
        info = GzipMemberInfo(self._current.index + 1, self._raw_pos)
        self._members.append(info)
        self._current = info
        self._decomp = zlib.decompressobj(31)

    def _finish_member(self):
        self._current.comp_end = self._raw_pos
        if self._current.crc_status == 'incomplete':
            self._current.crc_status = 'pass'

    def _mark_fail(self, exc):
        self._current.crc_status = 'fail'
        self._current.error = str(exc)
        self._fatal = GzipFormatError(
            'gzip member {0} CRC/trailer failure at compressed offset {1}: {2}'
            .format(self._current.index, self._current.comp_start, exc))
        raise self._fatal

    def _enqueue(self, data):
        """Split decompressed data into bounded pages."""
        offset = 0
        while offset < len(data):
            page = data[offset:offset + self.PAGE_SIZE]
            self._pages.append(page)
            self._buffered += len(page)
            offset += len(page)
            self._decomp_total += len(page)

    def _pump(self):
        """
        Feed one bounded raw chunk to the current member.  Pulls more input
        when the buffered prefix is exhausted mid-member.
        """
        if self._eof or self._fatal is not None:
            return

        if not self._raw:
            self._raw = self._stream.read(self.READ_CHUNK)
            if not self._raw:
                if not self._decomp.eof:
                    self._current.crc_status = 'incomplete'
                else:
                    self._finish_member()
                self._eof = True
                return

        offered = len(self._raw)
        try:
            piece = self._decomp.decompress(self._raw)
        except zlib.error as exc:
            self._mark_fail(exc)

        if piece:
            self._enqueue(piece)

        if self._decomp.eof:
            unused = self._decomp.unused_data
            self._raw_pos += offered - len(unused)
            self._raw = unused
            self._finish_member()
            if self._raw:
                self._start_next_member()
            else:
                self._eof = True
            return

        # Member still open: the whole offered chunk belonged to it.
        self._raw_pos += offered
        self._raw = b''

    def read(self, size=-1):
        if size is None or size < 0:
            size = self.READ_CHUNK
        if size == 0:
            return b''

        while self._buffered < size and not self._eof and \
                self._fatal is None:
            self._pump()
        return self._drain(size)

    def _drain(self, size):
        result = []
        remaining = size
        while remaining > 0 and self._pages:
            page = self._pages[0]
            if len(page) <= remaining:
                result.append(page)
                remaining -= len(page)
                self._buffered -= len(page)
                self._pages.popleft()
            else:
                result.append(page[:remaining])
                self._pages[0] = page[remaining:]
                self._buffered -= remaining
                remaining = 0
        return b''.join(result)
