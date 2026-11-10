"""
Index-based random access to records in plain and gzip-compressed WARC files.

The on-disk index is a versioned JSON-lines document (no pickle):

    {"type": "warcio-record-index", "version": 1, ...}      # header line
    {"r": "<WARC-Record-ID>", "o": 123, ...}                # one line per record
    ...
    {"type": "footer", "entries": N, "sha256": "..."}       # footer line

Three distinct offsets are stored for every record, because they are *not*
interchangeable:

* ``o``  - raw byte offset of the record (plain WARC) or of its gzip member
  (gzip WARC) in the underlying file.
* ``m``  - raw byte offset where the containing gzip member starts.
  A member may hold several records, so several entries may share ``m``.
  ``null`` for plain WARC.
* ``d``  - offset of the record inside the decompressed member (``0`` for the
  first record of a member). This is a *decompressed* offset and must never be
  passed to ``seek()`` on the raw file; the member has to be decompressed from
  its own start until this offset is reached.

Duplicate WARC-Record-IDs keep every location, in physical order.

The index binds the archive file size and a caller-provided content identity
value; both are checked when the index is opened.

Typical use (descriptive, not an executable doctest):

* build with ``build_record_index(warc_path, index_path, content_identity)``;
* reopen with :func:`load_record_index`, which verifies the checksum,
  version, file size binding and caller content identity;
* call :meth:`RecordIndex.lookup` to get every physical location of an ID,
  then :meth:`RecordIndex.open_session` and :meth:`RecordIndexSession.fetch`;
* the returned :class:`FetchResult` exposes ``raw_start`` / ``raw_end`` /
  ``raw_bytes`` describing the raw archive bytes read to reach the record.
"""

import hashlib
import io
import json
import os
import tempfile
import zlib

from warcio.recordloader import ArcWarcRecordLoader


INDEX_TYPE = 'warcio-record-index'
INDEX_VERSION = 1
FOOTER_TYPE = 'warcio-record-index-footer'

GZIP_MAGIC = b'\x1f\x8b'
WARC_VERSIONS = (b'WARC/1.0', b'WARC/1.1', b'WARC/0.17', b'WARC/0.18')
READ_CHUNK = 16384


# ============================================================================
class RecordIndexError(Exception):
    """Base class for record index errors."""


class IndexBuildError(RecordIndexError):
    """Raised when an archive cannot be fully indexed.

    ``raw_offset`` is the position in the underlying (possibly compressed)
    file at which the problem was detected; ``decompressed_offset`` is the
    corresponding decompressed position for gzip archives.
    """

    def __init__(self, reason, raw_offset=None, decompressed_offset=None):
        self.reason = reason
        self.raw_offset = raw_offset
        self.decompressed_offset = decompressed_offset

        details = [reason]
        if raw_offset is not None:
            details.append('raw offset {0}'.format(raw_offset))
        if decompressed_offset is not None:
            details.append('decompressed offset {0}'.format(decompressed_offset))
        super(IndexBuildError, self).__init__('; '.join(details))


class IndexValidationError(RecordIndexError):
    """Raised when an index file or a located record fails validation."""


# ============================================================================
class _GzipPump(object):
    """Incremental multi-member gzip decompressor.

    Fed raw bytes in arbitrary chunks; emits decompressed bytes while tracking
    where each gzip member starts, both as a raw offset and as a position in
    the concatenated decompressed stream.
    """

    def __init__(self):
        self.decomp = zlib.decompressobj(16 + zlib.MAX_WBITS)
        self.raw_pos = 0
        self.decomp_pos = 0
        # list of (raw member start, decompressed position of member start)
        self.member_starts = [(0, 0)]
        self._member_open = True
        # bytes belonging to the next member, carried across feed() calls
        self._carry = b''

    def feed(self, chunk):
        out = []
        data = self._carry + chunk
        self._carry = b''

        while data:
            if not self._member_open:
                # accumulate until the next member's gzip magic is visible
                if len(data) < 2:
                    self._carry = data
                    break
                if data[:2] != GZIP_MAGIC:
                    raise IndexBuildError(
                        'trailing bytes after gzip member are not a new '
                        'gzip member', raw_offset=self.raw_pos)
                self.decomp = zlib.decompressobj(16 + zlib.MAX_WBITS)
                self.member_starts.append((self.raw_pos,
                                           self.decomp_pos))
                self._member_open = True

            try:
                piece = self.decomp.decompress(data)
            except zlib.error as exc:
                raise IndexBuildError(
                    'invalid gzip data: {0}'.format(exc),
                    raw_offset=self.raw_pos)

            leftover = self.decomp.unused_data
            consumed = len(data) - len(leftover)
            self.raw_pos += consumed
            if piece:
                self.decomp_pos += len(piece)
                out.append(piece)

            if not leftover:
                break

            # member boundary; remaining bytes belong to the next member
            self._member_open = False
            data = leftover

        return b''.join(out)

    def finish(self):
        """Flush the final member and ensure the gzip stream is complete."""
        if self._carry:
            raise IndexBuildError(
                'truncated gzip stream: incomplete member header at end',
                raw_offset=self.raw_pos)
        if not self._member_open:
            raise IndexBuildError(
                'truncated gzip stream: empty trailing member',
                raw_offset=self.raw_pos)
        try:
            tail = self.decomp.flush()
        except zlib.error as exc:
            raise IndexBuildError(
                'invalid gzip data: {0}'.format(exc),
                raw_offset=self.raw_pos)
        if tail:
            self.decomp_pos += len(tail)
        if not self.decomp.eof:
            raise IndexBuildError(
                'truncated gzip stream: final member is incomplete',
                raw_offset=self.raw_pos)
        self._member_open = False

    def member_for(self, decomp_offset):
        """Return (raw member start, decompressed member start) for offset."""
        active = self.member_starts[0]
        for start in self.member_starts:
            if start[1] <= decomp_offset:
                active = start
            else:
                break
        return active


class _PlainPump(object):
    """Pass-through pump for uncompressed data; one implicit member at 0."""

    def __init__(self):
        self.raw_pos = 0
        self.decomp_pos = 0

    def feed(self, chunk):
        self.raw_pos += len(chunk)
        self.decomp_pos += len(chunk)
        return chunk

    def finish(self):
        pass

    def member_for(self, decomp_offset):
        return 0, 0


class _ScanReader(object):
    """File-like reader fed through a pump, with readline and tell."""

    def __init__(self, fh, pump):
        self.fh = fh
        self.pump = pump
        self.buff = b''
        self.buff_pos = 0
        self.eof = False

    def _refill(self):
        if self.eof:
            return b''
        chunk = self.fh.read(READ_CHUNK)
        if not chunk:
            self.eof = True
            self.pump.finish()
            return b''
        data = self.pump.feed(chunk)
        self.buff += data
        return data

    def read(self, size):
        while len(self.buff) - self.buff_pos < size and not self.eof:
            if not self._refill():
                break
        end = self.buff_pos + size
        data = self.buff[self.buff_pos:end]
        self.buff_pos += len(data)
        self._compact()
        return data

    def readline(self):
        while True:
            nl = self.buff.find(b'\n', self.buff_pos)
            if nl >= 0:
                end = nl + 1
                line = self.buff[self.buff_pos:end]
                self.buff_pos = end
                self._compact()
                return line
            if self.eof:
                line = self.buff[self.buff_pos:]
                self.buff_pos = len(self.buff)
                self._compact()
                return line
            self._refill()

    def _compact(self):
        if self.buff_pos and (self.buff_pos >= len(self.buff) or
                              self.buff_pos >= READ_CHUNK):
            self.buff = self.buff[self.buff_pos:]
            self.buff_pos = 0

    def tell(self):
        return self.pump.decomp_pos - (len(self.buff) - self.buff_pos)


class _PrefixedReader(object):
    """Reader which serves one already-consumed line before delegating."""

    def __init__(self, reader, prefix):
        self.reader = reader
        self.prefix = prefix

    def readline(self):
        if self.prefix is not None:
            line = self.prefix
            self.prefix = None
            return line
        return self.reader.readline()

    def read(self, size):
        return self.reader.read(size)

    def tell(self):
        if self.prefix is not None:
            return self.reader.tell() - len(self.prefix)
        return self.reader.tell()


# ============================================================================
def _parse_warc_header(reader, start, raw_offset):
    """Read and validate a WARC header block.

    ``reader`` must be positioned at the WARC version line.
    Returns (headers dict, header block length incl. terminating blank line,
    declared Content-Length).
    """
    header_lines = []
    header_len = 0
    while True:
        line = reader.readline()
        if not line:
            raise IndexBuildError(
                'unexpected end of data while reading WARC header',
                raw_offset=raw_offset, decompressed_offset=start)
        header_len += len(line)
        stripped = line.rstrip(b'\r\n')
        if not stripped:
            break
        if not header_lines:
            if stripped not in WARC_VERSIONS:
                raise IndexBuildError(
                    'invalid WARC version line: {0!r}'.format(
                        stripped.decode('iso-8859-1', 'replace')),
                    raw_offset=raw_offset, decompressed_offset=start)
        header_lines.append(stripped)

    headers = {}
    for line in header_lines[1:]:
        if b':' not in line:
            raise IndexBuildError(
                'malformed WARC header line: {0!r}'.format(
                    line.decode('iso-8859-1', 'replace')),
                raw_offset=raw_offset, decompressed_offset=start)
        name, value = line.split(b':', 1)
        name = name.strip().decode('iso-8859-1')
        value = value.strip().decode('iso-8859-1')
        if name.lower() not in headers:
            headers[name.lower()] = value

    if 'warc-record-id' not in headers:
        raise IndexBuildError(
            'record without WARC-Record-ID',
            raw_offset=raw_offset, decompressed_offset=start)

    if 'content-length' not in headers:
        raise IndexBuildError(
            'record {0} without Content-Length'.format(
                headers['warc-record-id']),
            raw_offset=raw_offset, decompressed_offset=start)
    try:
        content_length = int(headers['content-length'])
        if content_length < 0:
            raise ValueError()
    except ValueError:
        raise IndexBuildError(
            'record {0} has invalid Content-Length: {1!r}'.format(
                headers['warc-record-id'], headers['content-length']),
            raw_offset=raw_offset, decompressed_offset=start)

    return headers, header_len, content_length


def _scan_archive(fh, is_gzip):
    """Single forward pass producing index entries and the pump state."""
    pump = _GzipPump() if is_gzip else _PlainPump()
    reader = _ScanReader(fh, pump)
    entries = []

    while True:
        # blank lines between records are not part of any record
        line = reader.readline()
        while line and not line.strip():
            line = reader.readline()

        if not line:
            if not entries:
                raise IndexBuildError('empty archive: no WARC records')
            break

        start = reader.tell() - len(line)
        raw_offset, _ = pump.member_for(start)
        header_reader = _PrefixedReader(reader, line)
        headers, header_len, content_length = _parse_warc_header(
            header_reader, start, raw_offset)

        payload = reader.read(content_length)
        if len(payload) != content_length:
            raise IndexBuildError(
                'record {0} payload truncated: expected {1} bytes, '
                'got {2}'.format(headers['warc-record-id'],
                                 content_length, len(payload)),
                raw_offset=raw_offset, decompressed_offset=start)

        trailer = reader.read(4)
        if trailer != b'\r\n\r\n':
            raise IndexBuildError(
                'record {0} is not terminated by CRLF CRLF, found: {1!r}'
                .format(headers['warc-record-id'], trailer),
                raw_offset=raw_offset,
                decompressed_offset=reader.tell() - len(trailer))

        record_span = header_len + content_length + 4
        end = start + record_span
        if is_gzip:
            # Member boundaries are only discovered while decompressing
            # later bytes, so the member assignment is finalized after the
            # whole file has been consumed. Store the global decompressed
            # position here and resolve it in the post-processing pass.
            file_offset = None
            gzip_member_offset = None
            member_record_offset = None
        else:
            member_record_offset = start
            file_offset = start
            gzip_member_offset = None

        entries.append({
            'r': headers['warc-record-id'],
            'o': file_offset,
            'm': gzip_member_offset,
            'd': member_record_offset,
            'l': content_length,
            's': record_span,
            '_start': start,
            '_end': end,
        })

    if is_gzip:
        _resolve_gzip_members(entries, pump)
    else:
        for entry in entries:
            del entry['_start']
            del entry['_end']

    return entries, pump


def _resolve_gzip_members(entries, pump):
    """Fill member offsets now that every gzip boundary is known."""
    for entry in entries:
        member_raw_start, member_decomp_start = pump.member_for(
            entry['_start'])
        next_raw_start, _ = pump.member_for(entry['_end'] - 1)
        if next_raw_start != member_raw_start:
            raise IndexBuildError(
                'record {0} spans a gzip member boundary'.format(
                    entry['r']),
                raw_offset=member_raw_start,
                decompressed_offset=entry['_start'])
        entry['m'] = member_raw_start
        entry['o'] = member_raw_start
        entry['d'] = entry['_start'] - member_decomp_start
        del entry['_start']
        del entry['_end']


# ============================================================================
class RecordIndexEntry(object):
    """One physical location of a WARC record."""

    __slots__ = ('record_id', 'offset', 'gzip_member_offset',
                 'member_record_offset', 'content_length', 'record_span')

    def __init__(self, data):
        self.record_id = data['r']
        self.offset = data['o']
        self.gzip_member_offset = data['m']
        self.member_record_offset = data['d']
        self.content_length = data['l']
        self.record_span = data['s']

    @property
    def is_gzip(self):
        return self.gzip_member_offset is not None

    def __repr__(self):
        return ('RecordIndexEntry(record_id={0!r}, offset={1}, '
                'gzip_member_offset={2}, member_record_offset={3})').format(
                    self.record_id, self.offset,
                    self.gzip_member_offset, self.member_record_offset)


class FetchResult(object):
    """A fetched record plus the raw byte interval read to reach it."""

    __slots__ = ('entry', 'record', 'raw_start', 'raw_end', 'raw_bytes')

    def __init__(self, entry, record, raw_start, raw_end):
        self.entry = entry
        self.record = record
        self.raw_start = raw_start
        self.raw_end = raw_end
        self.raw_bytes = raw_end - raw_start


class _BytesPayload(object):
    """In-memory replacement for a record stream consumed during fetch."""

    def __init__(self, data):
        self._buf = io.BytesIO(data)

    def read(self, size=-1):
        if size is None or size < 0:
            return self._buf.read()
        return self._buf.read(size)

    def readline(self, size=-1):
        return self._buf.readline(size)

    def tell(self):
        return self._buf.tell()

    def seek(self, offset, whence=0):
        return self._buf.seek(offset, whence)

    def close(self):
        self._buf.close()


# ============================================================================
def _detect_gzip(fh):
    head = fh.read(2)
    fh.seek(0)
    return head == GZIP_MAGIC


def build_record_index(warc_path, index_path, content_identity):
    """Build a versioned, non-pickle index for a WARC file.

    Supports plain WARC and concatenated-member gzip WARC, including gzip
    members that contain several records.

    The index is written to a temporary file and atomically renamed into
    place, so a build failure (including a bad record) never leaves a file
    that could be mistaken for a complete index.

    :param str warc_path: path to the WARC file (must be seekable).
    :param str index_path: destination path for the JSON-lines index.
    :param content_identity: caller-defined identity value (str, or bytes
        which are decoded as UTF-8) bound to the archive and checked on open.
    :rtype: RecordIndex
    """
    if isinstance(content_identity, bytes):
        content_identity = content_identity.decode('utf-8')
    if not isinstance(content_identity, str):
        raise TypeError('content_identity must be str or bytes')

    with open(warc_path, 'rb') as fh:
        is_gzip = _detect_gzip(fh)
        file_size = _file_size(fh)
        entries, pump = _scan_archive(fh, is_gzip)
        if pump.raw_pos != file_size:
            raise IndexBuildError(
                'scanner consumed {0} bytes but file size is {1}'.format(
                    pump.raw_pos, file_size),
                raw_offset=pump.raw_pos)
        if is_gzip:
            indexed_members = set(e['m'] for e in entries)
            known_members = set(m[0] for m in pump.member_starts)
            if indexed_members != known_members:
                raise IndexBuildError(
                    'gzip member without any WARC record detected')

    header = {
        'type': INDEX_TYPE,
        'version': INDEX_VERSION,
        'gzip': is_gzip,
        'file_size': file_size,
        'content_identity': content_identity,
    }

    index_dir = os.path.dirname(os.path.abspath(index_path))
    tmp_fd, tmp_path = tempfile.mkstemp(
        prefix='.warcio-index-', suffix='.tmp', dir=index_dir)
    try:
        digest = hashlib.sha256()
        with os.fdopen(tmp_fd, 'w', encoding='utf-8', newline='\n') as out:
            _write_index_line(out, digest, header)
            for entry in entries:
                _write_index_line(out, digest, entry)
            footer = {
                'type': FOOTER_TYPE,
                'entries': len(entries),
                'sha256': digest.hexdigest(),
            }
            _write_index_line(out, digest, footer, checksum=False)
        os.replace(tmp_path, index_path)
    except BaseException:
        _silent_remove(tmp_path)
        raise

    return RecordIndex(index_path, content_identity=content_identity,
                       warc_path=warc_path)


def _write_index_line(out, digest, obj, checksum=True):
    line = json.dumps(obj, ensure_ascii=False, sort_keys=True) + '\n'
    if checksum:
        digest.update(line.encode('utf-8'))
    out.write(line)


def _silent_remove(path):
    try:
        os.remove(path)
    except OSError:
        pass


def _file_size(fh):
    fh.seek(0, os.SEEK_END)
    size = fh.tell()
    fh.seek(0)
    return size


# ============================================================================
class _RangeTrackingReader(object):
    """Wraps a seekable binary file and records raw byte intervals read."""

    def __init__(self, fh):
        self.fh = fh
        self.ranges = []
        self.bytes_read = 0

    def seek(self, offset, whence=os.SEEK_SET):
        return self.fh.seek(offset, whence)

    def tell(self):
        return self.fh.tell()

    def read(self, size=-1):
        start = self.fh.tell()
        data = self.fh.read(size)
        end = start + len(data)
        if data:
            self._record(start, end)
        return data

    def readline(self, size=-1):
        start = self.fh.tell()
        data = self.fh.readline(size)
        end = start + len(data)
        if data:
            self._record(start, end)
        return data

    def _record(self, start, end):
        self.bytes_read += end - start
        if self.ranges and start <= self.ranges[-1][1]:
            prev_start, prev_end = self.ranges[-1]
            self.ranges[-1] = (prev_start, max(prev_end, end))
        else:
            self.ranges.append((start, end))


class _SingleGzipMemberReader(object):
    """Decompresses exactly one gzip member.

    Raw reads never cross the member boundary: once the member's final
    compressed block is seen, further reads return ``b''`` even if the
    underlying file contains another member. ``tell()`` is the position in
    this member's own decompressed stream, which is exactly the coordinate
    stored as ``member_record_offset`` in the index.
    """

    def __init__(self, raw, member_raw_offset, block_size=READ_CHUNK):
        self.raw = raw
        self.block_size = block_size
        self.member_raw_offset = member_raw_offset
        self.raw_end = None
        raw.seek(member_raw_offset)
        self.decomp = zlib.decompressobj(16 + zlib.MAX_WBITS)
        self.buff = b''
        self.buff_pos = 0
        self.num_read = 0
        self.member_done = False

    def _fill(self):
        if self.member_done:
            return
        block_start = self.raw.tell()
        chunk = self.raw.read(self.block_size)
        if not chunk:
            data = self.decomp.flush()
            self.raw_end = block_start
            self.member_done = True
        else:
            data = self.decomp.decompress(chunk)
            if self.decomp.unused_data:
                # Push back the raw (compressed) bytes belonging to the next
                # member. The decompressor tells us how many compressed
                # bytes it consumed; unused_data length is decompressed-size
                # related and must not be used as a raw seek delta.
                consumed = len(chunk) - len(self.decomp.unused_data)
                self.raw_end = block_start + consumed
                self.raw.seek(self.raw_end)
                data += self.decomp.flush()
                self.member_done = True
        self.buff += data

    def read(self, size=-1):
        if size is None or size < 0:
            while not self.member_done:
                self._fill()
            data = self.buff[self.buff_pos:]
            self.buff_pos = len(self.buff)
        else:
            while (len(self.buff) - self.buff_pos < size
                   and not self.member_done):
                self._fill()
            end = self.buff_pos + size
            data = self.buff[self.buff_pos:end]
            self.buff_pos = end
        self.num_read += len(data)
        self._compact()
        return data

    def readline(self):
        while True:
            nl = self.buff.find(b'\n', self.buff_pos)
            if nl >= 0:
                end = nl + 1
                line = self.buff[self.buff_pos:end]
                self.buff_pos = end
                self.num_read += len(line)
                self._compact()
                return line
            if self.member_done:
                line = self.buff[self.buff_pos:]
                self.buff_pos = len(self.buff)
                self.num_read += len(line)
                self._compact()
                return line
            self._fill()

    def tell(self):
        return self.num_read

    def _compact(self):
        if self.buff_pos and self.buff_pos >= len(self.buff):
            self.buff = b''
            self.buff_pos = 0


class RecordIndex(object):
    """A validated, versioned, non-pickle index of a WARC file.

    Load with :func:`load_record_index` or :func:`build_record_index`.
    Lookups return all physical locations of a WARC-Record-ID in physical
    order; a record ID that appears more than once yields several entries.
    """

    def __init__(self, index_path, content_identity=None, warc_path=None):
        self.index_path = index_path
        self.warc_path = warc_path
        self.version = None
        self.is_gzip = None
        self.file_size = None
        self.content_identity = None
        self.entries = []
        self._by_id = {}
        self._load(index_path, content_identity)

    def _load(self, index_path, content_identity):
        try:
            with open(index_path, 'r', encoding='utf-8') as fh:
                lines = fh.read().splitlines()
        except OSError as exc:
            raise IndexValidationError(
                'cannot open index {0!r}: {1}'.format(index_path, exc))

        if len(lines) < 3:
            raise IndexValidationError(
                'index {0!r} is incomplete (missing header/entries/footer)'
                .format(index_path))

        try:
            header = json.loads(lines[0])
            footer = json.loads(lines[-1])
            entry_lines = lines[1:-1]
        except ValueError as exc:
            raise IndexValidationError(
                'index {0!r} is not valid JSON-lines: {1}'
                .format(index_path, exc))

        if header.get('type') != INDEX_TYPE:
            raise IndexValidationError(
                'index {0!r} has wrong document type: {1!r}'
                .format(index_path, header.get('type')))
        if header.get('version') != INDEX_VERSION:
            raise IndexValidationError(
                'index {0!r} has unsupported version {1!r}, expected {2}'
                .format(index_path, header.get('version'), INDEX_VERSION))
        if footer.get('type') != FOOTER_TYPE:
            raise IndexValidationError(
                'index {0!r} is missing a valid footer'.format(index_path))

        digest = hashlib.sha256()
        for line in lines[:-1]:
            digest.update((line + '\n').encode('utf-8'))
        if digest.hexdigest() != footer.get('sha256'):
            raise IndexValidationError(
                'index {0!r} checksum mismatch; file is corrupt or truncated'
                .format(index_path))

        entries = []
        for pos, line in enumerate(entry_lines, start=2):
            try:
                data = json.loads(line)
            except ValueError as exc:
                raise IndexValidationError(
                    'invalid index entry on line {0}: {1}'.format(pos, exc))
            try:
                entry = RecordIndexEntry(data)
            except (KeyError, TypeError) as exc:
                raise IndexValidationError(
                    'malformed index entry on line {0}: {1}'.format(pos, exc))
            entries.append(entry)

        if footer.get('entries') != len(entries):
            raise IndexValidationError(
                'index {0!r} footer reports {1} entries but {2} found'
                .format(index_path, footer.get('entries'), len(entries)))

        self.version = header['version']
        self.is_gzip = bool(header['gzip'])
        self.file_size = header['file_size']
        self.content_identity = header['content_identity']

        if content_identity is not None:
            supplied = content_identity.decode('utf-8') \
                if isinstance(content_identity, bytes) else content_identity
            if supplied != self.content_identity:
                raise IndexValidationError(
                    'content identity mismatch: index was built for {0!r}, '
                    'caller supplied {1!r}'.format(
                        self.content_identity, supplied))

        self.entries = entries
        self._by_id = {}
        for index, entry in enumerate(entries):
            self._by_id.setdefault(entry.record_id, []).append(index)

    def lookup(self, record_id):
        """Return every :class:`RecordIndexEntry` for ``record_id``.

        Locations stay in physical order; an unknown ID returns an empty
        list rather than raising.
        """
        return [self.entries[i] for i in self._by_id.get(record_id, [])]

    def __contains__(self, record_id):
        return record_id in self._by_id

    def __len__(self):
        return len(self.entries)

    def __iter__(self):
        return iter(self.entries)

    def open_session(self, warc_path=None, block_size=READ_CHUNK):
        """Open a :class:`RecordIndexSession` for fetching records."""
        return RecordIndexSession(self, warc_path or self.warc_path,
                                  block_size=block_size)

    def fetch_record(self, entry, warc_path=None):
        """Convenience wrapper opening a one-shot session for one fetch."""
        session = self.open_session(warc_path)
        try:
            return session.fetch(entry)
        finally:
            session.close()


# ============================================================================
class RecordIndexSession(object):
    """Fetches records located through a :class:`RecordIndex`.

    Every fetch verifies:

    * the archive file size still matches the bound size;
    * the located record's WARC-Record-ID matches the index entry;
    * its declared Content-Length matches the bound length.

    Raw byte intervals actually read from the archive are accumulated in
    ``ranges`` / ``bytes_read`` so random-access cost can be measured.
    """

    def __init__(self, index, warc_path, block_size=READ_CHUNK):
        if warc_path is None:
            raise ValueError(
                'warc_path is required: the index does not store a path')
        self.index = index
        self.warc_path = warc_path
        self.block_size = block_size
        self.fh = open(warc_path, 'rb')
        self.tracker = _RangeTrackingReader(self.fh)
        self.ranges = self.tracker.ranges
        self.bytes_read = 0
        self._closed = False
        self._check_file_size()

    def _check_file_size(self):
        actual = _file_size(self.fh)
        if actual != self.index.file_size:
            raise IndexValidationError(
                'archive size mismatch: index bound to {0} bytes but {1!r} '
                'is {2} bytes'.format(self.index.file_size,
                                      self.warc_path, actual))

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()

    def close(self):
        if not self._closed:
            self._closed = True
            self.fh.close()

    def fetch_all(self, record_id):
        """Fetch every physical record sharing ``record_id``, in order."""
        return [self.fetch(entry)
                for entry in self.index.lookup(record_id)]

    def fetch(self, entry):
        """Locate and validate one :class:`RecordIndexEntry`."""
        if self._closed:
            raise RecordIndexError('session is closed')

        if entry.is_gzip:
            return self._fetch_gzip(entry)
        return self._fetch_plain(entry)

    def _fetch_plain(self, entry):
        if self.index.is_gzip:
            raise IndexValidationError(
                'plain entry used against a gzip index')

        self.tracker.seek(entry.offset)
        raw_start = entry.offset

        loader = ArcWarcRecordLoader(verify_http=False, arc2warc=False)
        record = loader.parse_record_stream(
            self.tracker, known_format='warc', no_record_parse=True)
        self._verify(entry, record)

        # Eagerly consume the (already length-limited) payload so that the
        # reported raw interval covers the whole record regardless of
        # whether the caller reads the stream afterwards.
        payload = record.raw_stream.read()
        trailer = self.tracker.read(4)
        if trailer != b'\r\n\r\n':
            raise IndexValidationError(
                'record {0!r} missing CRLF CRLF trailer'.format(
                    entry.record_id))
        record.raw_stream = _BytesPayload(payload)
        self.bytes_read = self.tracker.bytes_read
        return FetchResult(entry, record, raw_start, self.fh.tell())

    def _fetch_gzip(self, entry):
        if not self.index.is_gzip:
            raise IndexValidationError(
                'gzip entry used against a plain WARC index')

        # Decompress from the *member start*. The member-internal offset is a
        # decompressed offset and must never be used to seek the raw file.
        raw_start = entry.gzip_member_offset

        member_reader = _SingleGzipMemberReader(
            self.tracker, entry.gzip_member_offset,
            block_size=self.block_size)
        loader = ArcWarcRecordLoader(verify_http=False, arc2warc=False)

        # Walk the member from its own start, decompressing. The target may
        # be preceded by other records in the same member; every record is
        # validated against the index, none is skipped blindly.
        target = None
        target_payload = None
        while True:
            record_start = member_reader.tell()
            located = self._entry_for_reader_position(
                entry.gzip_member_offset, record_start)
            record = loader.parse_record_stream(
                member_reader, known_format='warc', no_record_parse=True)
            self._verify(located, record)
            payload = record.raw_stream.read()
            trailer = member_reader.read(4)
            if trailer != b'\r\n\r\n':
                raise IndexValidationError(
                    'record {0!r} missing CRLF CRLF trailer'.format(
                        record.rec_headers.get_header('WARC-Record-ID')))
            if located == entry:
                target = record
                target_payload = payload
                # drain the remainder of this gzip member so the reported
                # raw interval covers the complete member
                member_reader.read()
                break

        target.raw_stream = _BytesPayload(target_payload)
        self.bytes_read = self.tracker.bytes_read
        return FetchResult(entry, target, raw_start, self.fh.tell())

    def _entry_for_reader_position(self, member_offset, reader_tell):
        for candidate in self.index.entries:
            if (candidate.gzip_member_offset == member_offset and
                    candidate.member_record_offset == reader_tell):
                return candidate
        raise IndexValidationError(
            'index has no entry for member {0} decompressed offset {1}'
            .format(member_offset, reader_tell))

    @staticmethod
    def _verify(entry, record):
        actual_id = record.rec_headers.get_header('WARC-Record-ID')
        if actual_id != entry.record_id:
            raise IndexValidationError(
                'record ID mismatch at offset {0}: index expects {1!r}, '
                'found {2!r}'.format(entry.offset, entry.record_id,
                                     actual_id))
        declared_length = record.rec_headers.get_header('Content-Length')
        if declared_length is None:
            raise IndexValidationError(
                'record {0!r} has no Content-Length'.format(actual_id))
        try:
            declared_length = int(declared_length)
        except ValueError:
            raise IndexValidationError(
                'record {0!r} has non-integer Content-Length: {1!r}'
                .format(actual_id, declared_length))
        if declared_length != entry.content_length:
            raise IndexValidationError(
                'declared length mismatch for {0!r}: index has {1}, '
                'record declares {2}'.format(actual_id, entry.content_length,
                                             declared_length))


# ============================================================================
def load_record_index(index_path, content_identity=None, warc_path=None):
    """Load and validate a versioned index previously written to disk."""
    return RecordIndex(index_path,
                       content_identity=content_identity,
                       warc_path=warc_path)
