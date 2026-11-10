"""
Batch conversion of duplicate WARC ``response`` records into ``revisit``
records, built on top of :meth:`RecordBuilder.create_revisit_record`.

Payload comparison convention (encoding layer and digest algorithm)
===================================================================
Two records are considered duplicates when their *decoded HTTP payloads*
are identical.  The decoded payload is the byte stream returned by
:meth:`ArcWarcRecord.content_stream`, i.e. the record content block with

* the HTTP status line and HTTP headers removed, and
* HTTP transfer decoding applied: ``Transfer-Encoding: chunked`` is
  removed and a ``Content-Encoding`` of ``gzip``/``x-gzip`` (and
  ``deflate``/``br`` where supported by
  :class:`warcio.bufferedreaders.BufferedReader`) is decompressed.

The digest computed over those decoded bytes defaults to SHA-1, base32
encoded and labelled per WARC convention, e.g. ``sha1:<BASE32>`` (see
:class:`warcio.utils.Digester`).  The algorithm can be changed via the
``digest_algo`` parameter; whatever algorithm is chosen, the same one is
used consistently for comparison, for the local index and for the
``WARC-Payload-Digest`` headers written to the output.

Referent selection rules
========================
A ``response`` record is converted to a ``revisit`` only when a referent
is available that

* is a complete ``response`` record (never another ``revisit``),
* comes from the output currently being written or from an output whose
  index was previously published to the local index directory,
* has the same ``WARC-Target-URI`` and the same decoded-payload digest,
* has a ``WARC-Date`` not later than the current record's date.

When several referents qualify, the earliest by ``(WARC-Date,
WARC-Record-ID)`` is chosen, making the selection stable.

Existing ``WARC-Payload-Digest`` headers on input records are never
trusted: the digest is always recomputed from the decoded payload and a
mismatching stored digest is corrected (and logged) on the way out.

Index publication
=================
The local index is a directory of JSON-lines files, one per converted
output.  An index file is published (atomically renamed into place) only
after its corresponding output WARC has been fully written and renamed
into its final location.  A failed conversion therefore leaves no index
behind, and a retry can never reference records that do not exist in a
completed output.
"""

import json
import logging
import os

from io import BytesIO

from warcio.archiveiterator import ArchiveIterator
from warcio.digestverifyingreader import _compare_digest_rfc_3548
from warcio.recordbuilder import RecordBuilder
from warcio.timeutils import iso_date_to_datetime
from warcio.utils import Digester, BUFF_SIZE
from warcio.warcwriter import WARCWriter


logger = logging.getLogger(__name__)


DEFAULT_DIGEST_ALGO = 'sha1'

INDEX_SUFFIX = '.idx.jsonl'

ENTRY_FIELDS = ('uri', 'date', 'record_id', 'digest', 'source')


# ============================================================================
def _parse_date(value):
    try:
        return iso_date_to_datetime(value)
    except Exception:
        return None


def _not_later_than(candidate_date, current_date):
    """True if candidate_date is not later than current_date.

    Parsed as ISO datetimes; falls back to lexicographic comparison of
    the raw values when either side can not be parsed.
    """
    candidate_dt = _parse_date(candidate_date)
    current_dt = _parse_date(current_date)
    if candidate_dt is not None and current_dt is not None:
        return candidate_dt <= current_dt
    return (candidate_date or '') <= (current_date or '')


def _entry_sort_key(entry):
    """Stable ordering key: capture time, then record id."""
    date_dt = _parse_date(entry.get('date'))
    if date_dt is not None:
        return (0, date_dt, entry.get('record_id') or '')
    return (1, entry.get('date') or '', entry.get('record_id') or '')


def select_candidate(entries, date):
    """Pick the referent for a record captured at ``date``.

    ``entries`` must already be restricted to matching URI and digest.
    Only entries captured no later than ``date`` qualify; the earliest
    by ``(date, record_id)`` wins.  Returns the entry dict or None.
    """
    eligible = [entry for entry in entries
                if _not_later_than(entry.get('date'), date)]
    if not eligible:
        return None
    return min(eligible, key=_entry_sort_key)


# ============================================================================
class RevisitIndex(object):
    """Local persistent index of response payloads eligible as referents.

    Only complete ``response`` records are ever added; ``revisit``
    records are excluded so a revisit is never used as a referent.
    """

    def __init__(self, index_dir):
        self.index_dir = index_dir
        self._entries = {}

    def load(self):
        """Load all published index files from the index directory."""
        self._entries = {}
        if not os.path.isdir(self.index_dir):
            return

        for name in sorted(os.listdir(self.index_dir)):
            if not name.endswith(INDEX_SUFFIX):
                continue

            path = os.path.join(self.index_dir, name)
            with open(path, 'r', encoding='utf-8') as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue

                    stored = json.loads(line)
                    self.add(*[stored.get(field) for field in ENTRY_FIELDS])

    def add(self, uri, date, record_id, digest, source=''):
        entry = dict(zip(ENTRY_FIELDS, (uri, date, record_id, digest, source)))
        self._entries.setdefault((uri, digest), []).append(entry)

    def iter_entries(self, uri, digest):
        return self._entries.get((uri, digest), ())

    def publish(self, index_name, entries):
        """Atomically publish ``entries`` as a new index file.

        Must only be called after the corresponding output has been
        fully written to its final location.
        """
        if not os.path.isdir(self.index_dir):
            os.makedirs(self.index_dir)

        final_path = os.path.join(self.index_dir, index_name + INDEX_SUFFIX)
        temp_path = final_path + '.tmp'
        with open(temp_path, 'w', encoding='utf-8') as fh:
            for entry in entries:
                fh.write(json.dumps(entry, sort_keys=True) + '\n')

            fh.flush()
            os.fsync(fh.fileno())

        os.replace(temp_path, final_path)
        return final_path


# ============================================================================
class RevisitDeduper(RecordBuilder):
    """Batch-convert duplicate responses in WARC files to revisits.

    The caller explicitly supplies:

    * ``index_dir`` -- local index location (see :class:`RevisitIndex`),
    * ``allowed_uris`` -- iterable of URI prefixes; only ``response``
      records whose ``WARC-Target-URI`` starts with one of them are
      considered for conversion and registration,
    * the input order, as the ordered ``inputs`` argument of
      :meth:`convert`.
    """

    def __init__(self, index_dir, allowed_uris, warc_version=None,
                 gzip=True, digest_algo=DEFAULT_DIGEST_ALGO):
        super(RevisitDeduper, self).__init__(warc_version=warc_version)
        self.index = RevisitIndex(index_dir)
        self.allowed_uris = tuple(allowed_uris)
        self.gzip = gzip
        self.digest_algo = digest_algo
        self._pending = None

    def convert(self, inputs, output_dir):
        """Convert ``inputs`` (an ordered iterable of WARC paths), writing
        one output per input into ``output_dir`` under the same basename.

        Returns the list of output paths in input order.
        """
        self.index.load()
        return [self.convert_one(input_path, output_dir)
                for input_path in inputs]

    def convert_one(self, input_path, output_dir):
        """Convert a single WARC, publishing its index only after the
        output has been fully written.  On failure nothing is published
        and no trace of the attempt remains in the index.
        """
        if not os.path.isdir(output_dir):
            os.makedirs(output_dir)

        base = os.path.basename(input_path)
        output_path = os.path.join(output_dir, base)
        temp_path = output_path + '.tmp'

        self._pending = []
        try:
            with open(temp_path, 'wb') as out:
                writer = WARCWriter(out, gzip=self.gzip,
                                    warc_version=self.warc_version)
                with open(input_path, 'rb') as fh:
                    for record in ArchiveIterator(fh):
                        self._process_record(record, writer, base)

            os.replace(temp_path, output_path)
        except Exception:
            self._pending = None
            if os.path.exists(temp_path):
                os.remove(temp_path)
            raise

        pending = self._pending
        self._pending = None

        # output has landed successfully: the index may now be published
        self.index.publish(base, pending)
        for entry in pending:
            self.index.add(*[entry[field] for field in ENTRY_FIELDS])

        return output_path

    def _process_record(self, record, writer, source):
        uri = record.rec_headers.get_header('WARC-Target-URI')
        if record.rec_type != 'response' or not self._uri_allowed(uri):
            writer.write_record(record)
            return

        date = record.rec_headers.get_header('WARC-Date')
        self._buffer_record(record)
        digester = self._payload_digester(record)
        record.raw_stream.seek(0)
        digest = str(digester)

        self._verify_stored_digest(record, digester, digest)

        candidate = self._lookup(uri, digest, date)
        if candidate is None:
            writer.write_record(record)
            record_id = record.rec_headers.get_header('WARC-Record-ID')
            self._pending.append(dict(zip(ENTRY_FIELDS,
                                          (uri, date, record_id, digest,
                                           source))))
            return

        revisit = self.create_revisit_record(
            uri,
            digest,
            refers_to_uri=candidate['uri'],
            refers_to_date=candidate['date'],
            http_headers=record.http_headers,
            warc_headers_dict={'WARC-Date': date,
                               'WARC-Refers-To': candidate['record_id']})
        writer.write_record(revisit)

    def _uri_allowed(self, uri):
        return bool(uri) and uri.startswith(self.allowed_uris)

    @staticmethod
    def _buffer_record(record):
        """Buffer the record content block in memory so that it can be
        read for digesting and then written out in full.
        """
        record.raw_stream = BytesIO(record.raw_stream.read())

    def _lookup(self, uri, digest, date):
        entries = list(self.index.iter_entries(uri, digest))
        entries.extend(entry for entry in self._pending
                       if entry['uri'] == uri and entry['digest'] == digest)
        return select_candidate(entries, date)

    def _payload_digester(self, record):
        """Digest the decoded HTTP payload (see module docstring)."""
        digester = Digester(self.digest_algo)
        stream = record.content_stream()
        while True:
            buff = stream.read(BUFF_SIZE)
            if not buff:
                break

            digester.update(buff)

        return digester

    def _verify_stored_digest(self, record, digester, digest):
        """Never trust an existing WARC-Payload-Digest without verifying
        it against the recomputed decoded-payload digest.
        """
        stored = record.rec_headers.get_header('WARC-Payload-Digest')
        if not stored:
            record.rec_headers.add_header('WARC-Payload-Digest', digest)
            return

        if _compare_digest_rfc_3548(digester, stored) is not True:
            logger.warning('WARC-Payload-Digest mismatch for %s (%s): '
                           'stored %s, recomputed %s; using recomputed',
                           record.rec_headers.get_header('WARC-Target-URI'),
                           record.rec_headers.get_header('WARC-Record-ID'),
                           stored, digest)
            record.rec_headers.replace_header('WARC-Payload-Digest', digest)
