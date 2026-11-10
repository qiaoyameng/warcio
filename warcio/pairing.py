"""
Optional request/response pairing stream for WARC archives.

In an archive, a request and its response may be separated by many
unrelated records, so the pairing can not be recovered from record
order, target URLs or timestamps.  This module provides PairingIterator,
a wrapper around ArchiveIterator, which pairs 'request' and 'response'
records exclusively by their WARC-Record-ID / WARC-Concurrent-To
declarations:

- A relationship is established when *either* side declares the
  other's record id in a WARC-Concurrent-To header.
- Duplicate record ids, contradictory mutual declarations and
  multiple responses for one request are all preserved and reported
  as ambiguity -- nothing is silently resolved by "last one wins",
  and no guessing by URL or time proximity is ever attempted.
- Records of any other type pass through unmodified, and pairing
  never alters the original HTTP content of buffered records.

The input is scanned exactly once.  Pending records are bounded by two
independent budgets: a metadata budget (max_pending records) and an
in-memory body budget (max_body_bytes); bodies beyond the memory budget
are spilled to temporary files which are removed on close().  When a
record's pairing window expires, when budgets force an eviction, or at
end of archive, the record is delivered -- either as a pair group or as
an unpaired record with a reason.  Delivery is final: a later record
referencing an already delivered id is reported as a late reference and
can not retroactively modify the delivered result.
"""

from collections import defaultdict, deque
from io import BytesIO

import tempfile

from warcio.archiveiterator import ArchiveIterator
from warcio.recordloader import ArcWarcRecord


# ============================================================================
class PairReport(object):
    """A single ambiguity / anomaly observation attached to an event."""

    # two pending records share the same WARC-Record-ID
    DUPLICATE_RECORD_ID = 'duplicate-record-id'
    # A declares B, but B declares C (!= A); both relations are kept
    CONFLICTING_DECLARATION = 'conflicting-declaration'
    # concurrent-to between two requests or two responses; not paired
    TYPE_CONFLICT = 'type-conflict'
    # one request matched by more than one response (kept as 1:n)
    MULTIPLE_RESPONSES = 'multiple-responses'
    # one response matched by more than one request (kept as n:1)
    MULTIPLE_REQUESTS = 'multiple-requests'
    # reference to an id that was already delivered; delivered results
    # are immutable and can not be retroactively modified
    LATE_REFERENCE = 'late-reference'
    # declared target id never appeared while the record was pending
    UNRESOLVED_TARGET = 'unresolved-target'

    def __init__(self, kind, message, record_ids=None):
        self.kind = kind
        self.message = message
        self.record_ids = list(record_ids) if record_ids else []

    def __repr__(self):
        return 'PairReport({0}: {1})'.format(self.kind, self.message)

    def __eq__(self, other):
        return (isinstance(other, PairReport) and
                self.kind == other.kind and
                self.message == other.message and
                self.record_ids == other.record_ids)


# ============================================================================
class PassthroughEvent(object):
    """A non request/response record, passed through unbuffered."""

    kind = 'passthrough'

    def __init__(self, record):
        self.record = record

    def __repr__(self):
        return 'PassthroughEvent({0})'.format(self.record.rec_type)


class PairEvent(object):
    """A matched group of one or more requests and responses.

    One-to-many relations are preserved: requests and responses are
    lists, and any ambiguity is described in reports.
    """

    kind = 'pair'

    def __init__(self, requests, responses, reports):
        self.requests = requests
        self.responses = responses
        self.reports = reports

    @property
    def record(self):
        # convenience for the common 1:1 case
        return self.requests[0] if self.requests else self.responses[0]

    def __repr__(self):
        return 'PairEvent(requests={0}, responses={1}, reports={2})'.format(
            len(self.requests), len(self.responses), len(self.reports))


class UnpairedEvent(object):
    """A request/response record delivered without a counterpart."""

    kind = 'unpaired'

    def __init__(self, record, reason, reports):
        self.record = record
        self.reason = reason
        self.reports = reports

    def __repr__(self):
        return 'UnpairedEvent({0}, reason={1})'.format(
            self.record.rec_type, self.reason)


# ============================================================================
class _MemoryBody(object):
    __slots__ = ('data',)

    def __init__(self, data):
        self.data = data

    def open_stream(self):
        return BytesIO(self.data)


class _FileBody(object):
    __slots__ = ('fh',)

    def __init__(self, fh):
        self.fh = fh

    def open_stream(self):
        self.fh.seek(0)
        return self.fh


class _BodyStore(object):
    """Retains record bodies for pending records.

    Bodies are held in memory while the cumulative in-memory size stays
    within max_memory_bytes; beyond that they spill to temporary files.
    Temporary files are unlinked immediately on platforms that support
    it and are always closed by close(), so an early close never leaves
    stray temp files behind.
    """

    def __init__(self, max_memory_bytes, spill_dir=None):
        self.max_memory_bytes = max_memory_bytes
        self.spill_dir = spill_dir
        self.memory_used = 0
        self._temp_files = []

    def store(self, data):
        if self.memory_used + len(data) <= self.max_memory_bytes:
            self.memory_used += len(data)
            return _MemoryBody(data)

        fh = tempfile.TemporaryFile(dir=self.spill_dir)
        fh.write(data)
        self._temp_files.append(fh)
        return _FileBody(fh)

    def release(self, body):
        # ownership of a delivered body transfers to the consumer;
        # only the memory accounting is adjusted here -- spilled files
        # stay readable until close()
        if isinstance(body, _MemoryBody):
            self.memory_used -= len(body.data)

    def discard(self, body):
        if isinstance(body, _MemoryBody):
            self.memory_used -= len(body.data)
        else:
            body.fh.close()
            if body.fh in self._temp_files:
                self._temp_files.remove(body.fh)

    def close(self):
        for fh in self._temp_files:
            try:
                fh.close()
            except Exception:  # pragma: no cover
                pass
        self._temp_files = []
        self.memory_used = 0


# ============================================================================
class _PendingRecord(object):
    __slots__ = ('record', 'rec_id', 'rec_type', 'concurrent_to', 'matches',
                 'reports', 'position', 'body')

    def __init__(self, record, rec_id, concurrent_to, position, body):
        self.record = record
        self.rec_id = rec_id
        self.rec_type = record.rec_type
        self.concurrent_to = concurrent_to
        self.position = position
        self.body = body
        self.matches = set()
        self.reports = []


# ============================================================================
class PairingIterator(object):
    """Streaming request/response pairing over an ArchiveIterator.

    Optional wrapper: iterate PairingIterator instead of ArchiveIterator
    to receive PassthroughEvent / PairEvent / UnpairedEvent objects
    instead of raw records.  Pairing uses WARC-Concurrent-To only.

    :param fileobj: archive stream or an existing ArchiveIterator
    :param window: max number of subsequent records a pending record
        waits for its counterpart before being delivered
    :param max_pending: metadata budget -- max number of pending
        request/response records; the oldest is evicted (and delivered)
        when the budget is exceeded
    :param max_body_bytes: body budget -- max cumulative in-memory bytes
        of retained record bodies; overflow spills to temp files
    :param spill_dir: directory for spilled body temp files
    """

    PAIRABLE_TYPES = ('request', 'response')

    REASON_WINDOW_EXPIRED = 'window-expired'
    REASON_BUDGET_EXCEEDED = 'pending-budget-exceeded'
    REASON_EOF = 'end-of-archive'

    def __init__(self, fileobj, window=128, max_pending=1024,
                 max_body_bytes=16 * 1024 * 1024, spill_dir=None, **kwargs):
        if isinstance(fileobj, ArchiveIterator):
            self.iterator = fileobj
        else:
            self.iterator = ArchiveIterator(fileobj, **kwargs)

        self.window = window
        self.max_pending = max_pending

        self.bodies = _BodyStore(max_body_bytes, spill_dir)

        self.pending = []
        self._pending_set = set()
        self._by_id = defaultdict(list)
        self._declarations = defaultdict(list)
        self._delivered_ids = set()

        self.events = deque()
        self.reports = []

        self.position = 0
        self._exhausted = False
        self._closed = False

    def __iter__(self):
        return self

    def __next__(self):
        while not self.events:
            if self._exhausted or self._closed:
                raise StopIteration
            self._read_next()
        return self.events.popleft()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def close(self):
        """Stop iteration and release all retained bodies.

        Safe to call at any point (including mid-iteration); removes
        any spilled temp files so nothing is left behind.
        """
        if self._closed:
            return
        self._closed = True
        for pending in self.pending:
            self.bodies.discard(pending.body)
        self.pending = []
        self._pending_set = set()
        self._by_id = defaultdict(list)
        self._declarations = defaultdict(list)
        self.events = deque()
        self.bodies.close()
        self.iterator.close()

    # -- reading ------------------------------------------------------

    def _read_next(self):
        try:
            record = next(self.iterator)
        except StopIteration:
            self._exhausted = True
            self._flush_all(self.REASON_EOF)
            return

        self.position += 1

        if record.rec_type not in self.PAIRABLE_TYPES:
            self.events.append(PassthroughEvent(record))
        else:
            self._add_pending(record)

        self._expire()

    def _add_pending(self, record):
        data = record.raw_stream.read()
        body = self.bodies.store(data)

        rec_id = record.rec_headers.get_header('WARC-Record-ID')
        concurrent_to = [value for name, value in record.rec_headers.headers
                         if name.lower() == 'warc-concurrent-to']

        pending = _PendingRecord(record, rec_id, concurrent_to,
                                 self.position, body)

        if rec_id is not None and rec_id in self._by_id:
            others = [p.rec_id for p in self._by_id[rec_id]]
            self._report(pending, PairReport.DUPLICATE_RECORD_ID,
                         'WARC-Record-ID {0} is already held by another '
                         'pending record; both are kept'.format(rec_id),
                         [rec_id] + others)

        # reverse direction: pending records that declared this id
        for declarer in self._declarations.get(rec_id, []):
            if declarer in self._pending_set:
                self._link(declarer, pending)
            else:
                self._report(pending, PairReport.LATE_REFERENCE,
                             'declared by an already delivered record; '
                             'delivered results can not be modified '
                             'retroactively', [rec_id])

        # forward direction: ids this record declares
        for target in concurrent_to:
            if target == rec_id:
                continue
            targets = self._by_id.get(target)
            if targets:
                for other in targets:
                    self._link(pending, other)
            elif target in self._delivered_ids:
                self._report(pending, PairReport.LATE_REFERENCE,
                             'declared target {0} was already delivered; '
                             'delivered results can not be modified '
                             'retroactively'.format(target), [target])

        self.pending.append(pending)
        self._pending_set.add(pending)
        if rec_id is not None:
            self._by_id[rec_id].append(pending)
        for target in concurrent_to:
            self._declarations[target].append(pending)

        return pending

    def _link(self, declarer, target):
        if declarer is target or target in declarer.matches:
            return

        ids = [declarer.rec_id, target.rec_id]

        if target.concurrent_to and declarer.rec_id not in target.concurrent_to:
            msg = ('{0} declares {1}, but {1} declares {2} instead; '
                   'both relations are kept'.format(
                       declarer.rec_id, target.rec_id,
                       ', '.join(target.concurrent_to)))
            self._report(declarer, PairReport.CONFLICTING_DECLARATION,
                         msg, ids)
            self._report(target, PairReport.CONFLICTING_DECLARATION,
                         msg, ids)

        if {declarer.rec_type, target.rec_type} != {'request', 'response'}:
            self._report(declarer, PairReport.TYPE_CONFLICT,
                         'WARC-Concurrent-To between two {0} records; '
                         'not a request/response pair'.format(
                             declarer.rec_type), ids)
            self._report(target, PairReport.TYPE_CONFLICT,
                         'WARC-Concurrent-To between two {0} records; '
                         'not a request/response pair'.format(
                             declarer.rec_type), ids)
            return

        declarer.matches.add(target)
        target.matches.add(declarer)

    # -- delivery -----------------------------------------------------

    def _expire(self):
        while (self.pending and
               self.position - self.pending[0].position >= self.window):
            self._deliver_group(self.pending[0], self.REASON_WINDOW_EXPIRED)

        while len(self.pending) > self.max_pending:
            self._deliver_group(self.pending[0], self.REASON_BUDGET_EXCEEDED)

    def _flush_all(self, reason):
        while self.pending:
            self._deliver_group(self.pending[0], reason)

    def _collect_component(self, entry):
        seen = {entry}
        stack = [entry]
        while stack:
            current = stack.pop()
            for other in current.matches:
                if other not in seen:
                    seen.add(other)
                    stack.append(other)
        return sorted(seen, key=lambda p: p.position)

    def _deliver_group(self, entry, reason):
        group = self._collect_component(entry)
        for pending in group:
            self._remove(pending)
            if pending.rec_id is not None:
                self._delivered_ids.add(pending.rec_id)

        reports = []
        for pending in group:
            reports.extend(pending.reports)
            reports.extend(self._unresolved_reports(pending))

        requests = [p for p in group if p.rec_type == 'request']
        responses = [p for p in group if p.rec_type == 'response']

        if len(group) > 1:
            if len(responses) > 1:
                reports.append(PairReport(
                    PairReport.MULTIPLE_RESPONSES,
                    'request matched by {0} responses; all are '
                    'kept'.format(len(responses)),
                    [p.rec_id for p in responses]))
            if len(requests) > 1:
                reports.append(PairReport(
                    PairReport.MULTIPLE_REQUESTS,
                    'response matched by {0} requests; all are '
                    'kept'.format(len(requests)),
                    [p.rec_id for p in requests]))
            self.events.append(PairEvent(
                requests=[self._deliverable(p) for p in requests],
                responses=[self._deliverable(p) for p in responses],
                reports=reports))
        else:
            pending = group[0]
            self.events.append(UnpairedEvent(
                self._deliverable(pending), reason, reports))

    def _unresolved_reports(self, pending):
        reports = []
        matched_ids = {other.rec_id for other in pending.matches}
        for target in pending.concurrent_to:
            if target == pending.rec_id or target in matched_ids:
                continue
            if target in self._delivered_ids:
                # already reported as a late reference on arrival
                continue
            if target in self._by_id:
                # still pending (e.g. type conflict); already reported
                continue
            reports.append(PairReport(
                PairReport.UNRESOLVED_TARGET,
                'declared target {0} never appeared while the record '
                'was pending'.format(target), [target]))
        return reports

    def _remove(self, pending):
        self.pending.remove(pending)
        self._pending_set.discard(pending)
        if pending.rec_id is not None:
            entries = self._by_id.get(pending.rec_id)
            if entries and pending in entries:
                entries.remove(pending)
            if entries is not None and not entries:
                del self._by_id[pending.rec_id]

    def _deliverable(self, pending):
        """Rebuild a record over the retained body.

        The original HTTP content is preserved byte for byte; only the
        backing stream is replaced by the buffered copy.
        """
        record = pending.record
        body = pending.body
        self.bodies.release(body)
        return ArcWarcRecord(record.format, record.rec_type,
                             record.rec_headers, body.open_stream(),
                             record.http_headers, record.content_type,
                             record.length,
                             payload_length=record.payload_length)

    def _report(self, pending, kind, message, record_ids=None):
        report = PairReport(kind, message, record_ids)
        pending.reports.append(report)
        self.reports.append(report)
