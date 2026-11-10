from io import BytesIO

from warcio.pairing import (PairingIterator, PairReport, PairEvent,
                            UnpairedEvent, PassthroughEvent)
from warcio.recordbuilder import RecordBuilder
from warcio.statusandheaders import StatusAndHeaders
from warcio.warcwriter import BufferWARCWriter


# ============================================================================
def make_request(builder, url, rec_id, method='GET', path='/', body=None,
                 concurrent_to=None):
    headers_list = [('Host', 'example.com')]
    if body is not None:
        headers_list.append(('Content-Length', str(len(body))))

    http_headers = StatusAndHeaders('{0} {1} HTTP/1.1'.format(method, path),
                                    headers_list, is_http_request=True)

    warc_headers_dict = {'WARC-Record-ID': rec_id}
    if concurrent_to:
        warc_headers_dict['WARC-Concurrent-To'] = concurrent_to

    kwargs = {}
    if body is not None:
        kwargs['payload'] = BytesIO(body)
        kwargs['length'] = len(body)

    return builder.create_warc_record(url, 'request',
                                      http_headers=http_headers,
                                      warc_headers_dict=warc_headers_dict,
                                      **kwargs)


def make_response(builder, url, rec_id, status='200 OK', payload=b'some\ntext',
                  concurrent_to=None, extra_headers=None):
    headers_list = [('Content-Type', 'text/plain; charset="UTF-8"'),
                    ('Content-Length', str(len(payload)))]
    if extra_headers:
        headers_list.extend(extra_headers)

    http_headers = StatusAndHeaders(status, headers_list, protocol='HTTP/1.1')

    warc_headers_dict = {'WARC-Record-ID': rec_id}
    if concurrent_to:
        warc_headers_dict['WARC-Concurrent-To'] = concurrent_to

    return builder.create_warc_record(url, 'response',
                                      payload=BytesIO(payload),
                                      length=len(payload),
                                      http_headers=http_headers,
                                      warc_headers_dict=warc_headers_dict)


def run_pairing(records, gzip=False, **kwargs):
    writer = BufferWARCWriter(gzip=gzip)
    for record in records:
        writer.write_record(record)
    stream = writer.get_stream()
    return list(PairingIterator(stream, **kwargs))


def rec_id(record):
    return record.rec_headers.get_header('WARC-Record-ID')


def report_kinds(event):
    return [report.kind for report in event.reports]


# ============================================================================
def demo_records():
    """Two interleaved POSTs to the same URL, one redirect response
    (paired strictly by WARC-Concurrent-To) and one orphan request.
    """
    builder = RecordBuilder()

    warcinfo = builder.create_warcinfo_record('demo.warc',
                                              {'software': 'pairing-demo'})

    req1 = make_request(builder, 'http://example.com/login',
                        '<urn:uuid:req-1>', method='POST', path='/login',
                        body=b'user=alice')

    req2 = make_request(builder, 'http://example.com/login',
                        '<urn:uuid:req-2>', method='POST', path='/login',
                        body=b'user=bob')

    resp1 = make_response(builder, 'http://example.com/login',
                          '<urn:uuid:resp-1>', status='302 Found', payload=b'',
                          concurrent_to='<urn:uuid:req-1>',
                          extra_headers=[('Location',
                                          'http://example.com/')])

    req3 = make_request(builder, 'http://example.com/other',
                        '<urn:uuid:req-3>', method='POST', path='/other',
                        body=b'x=1')

    return [warcinfo, req1, req2, resp1, req3]


# ============================================================================
class TestPairingIterator(object):
    def test_demo_interleaved_posts_redirect_and_orphan(self):
        events = run_pairing(demo_records())

        assert [event.kind for event in events] == [
            'passthrough', 'pair', 'unpaired', 'unpaired']

        # warcinfo passes through unmodified
        assert events[0].record.rec_type == 'warcinfo'

        # the redirect pairs with req-1 by id, even though req-2 has
        # the exact same URL
        pair = events[1]
        assert rec_id(pair.requests[0]) == '<urn:uuid:req-1>'
        assert rec_id(pair.responses[0]) == '<urn:uuid:resp-1>'
        assert pair.reports == []

        # original HTTP content is untouched by pairing
        assert b'user=alice' in pair.requests[0].content_stream().read()
        assert pair.responses[0].http_headers.get_statuscode() == '302'

        # req-2 (same URL!) and the orphan req-3 are delivered unpaired
        assert rec_id(events[2].record) == '<urn:uuid:req-2>'
        assert events[2].reason == PairingIterator.REASON_EOF
        assert rec_id(events[3].record) == '<urn:uuid:req-3>'
        assert events[3].reason == PairingIterator.REASON_EOF

    def test_demo_gzip(self):
        events = run_pairing(demo_records(), gzip=True)
        assert [event.kind for event in events] == [
            'passthrough', 'pair', 'unpaired', 'unpaired']

    def test_request_may_declare_response(self):
        # either side may declare the other's id
        builder = RecordBuilder()
        req = make_request(builder, 'http://example.com/', '<urn:uuid:req-1>',
                           concurrent_to='<urn:uuid:resp-1>')
        resp = make_response(builder, 'http://example.com/', '<urn:uuid:resp-1>')

        events = run_pairing([req, resp])

        assert [event.kind for event in events] == ['pair']
        assert rec_id(events[0].requests[0]) == '<urn:uuid:req-1>'
        assert rec_id(events[0].responses[0]) == '<urn:uuid:resp-1>'

    def test_duplicate_record_id_kept(self):
        builder = RecordBuilder()
        req1 = make_request(builder, 'http://example.com/a', '<urn:uuid:dup>')
        req2 = make_request(builder, 'http://example.com/b', '<urn:uuid:dup>')
        resp = make_response(builder, 'http://example.com/a', '<urn:uuid:resp>',
                             concurrent_to='<urn:uuid:dup>')

        events = run_pairing([req1, req2, resp])

        # no "last one wins": the response links to both records that
        # share the id, and the collision is reported
        assert [event.kind for event in events] == ['pair']
        pair = events[0]
        assert len(pair.requests) == 2
        assert len(pair.responses) == 1
        assert PairReport.DUPLICATE_RECORD_ID in report_kinds(pair)
        assert PairReport.MULTIPLE_REQUESTS in report_kinds(pair)

    def test_conflicting_declarations_kept(self):
        builder = RecordBuilder()
        req1 = make_request(builder, 'http://example.com/1', '<urn:uuid:req-1>',
                            concurrent_to='<urn:uuid:resp-1>')
        resp = make_response(builder, 'http://example.com/1', '<urn:uuid:resp-1>',
                             concurrent_to='<urn:uuid:req-2>')
        req2 = make_request(builder, 'http://example.com/2', '<urn:uuid:req-2>')

        events = run_pairing([req1, resp, req2])

        # req1->resp1 and resp1->req2 contradict each other; both
        # relations are kept and the contradiction is reported
        assert [event.kind for event in events] == ['pair']
        pair = events[0]
        assert sorted(rec_id(r) for r in pair.requests) == [
            '<urn:uuid:req-1>', '<urn:uuid:req-2>']
        assert len(pair.responses) == 1
        assert PairReport.CONFLICTING_DECLARATION in report_kinds(pair)
        assert PairReport.MULTIPLE_REQUESTS in report_kinds(pair)

    def test_multiple_responses_one_to_many(self):
        builder = RecordBuilder()
        req = make_request(builder, 'http://example.com/', '<urn:uuid:req-1>')
        resp1 = make_response(builder, 'http://example.com/', '<urn:uuid:resp-1>',
                              concurrent_to='<urn:uuid:req-1>')
        resp2 = make_response(builder, 'http://example.com/', '<urn:uuid:resp-2>',
                              concurrent_to='<urn:uuid:req-1>')

        events = run_pairing([req, resp1, resp2])

        assert [event.kind for event in events] == ['pair']
        pair = events[0]
        assert len(pair.requests) == 1
        assert sorted(rec_id(r) for r in pair.responses) == [
            '<urn:uuid:resp-1>', '<urn:uuid:resp-2>']
        assert PairReport.MULTIPLE_RESPONSES in report_kinds(pair)

    def test_type_conflict_not_paired(self):
        builder = RecordBuilder()
        req1 = make_request(builder, 'http://example.com/1', '<urn:uuid:req-1>',
                            concurrent_to='<urn:uuid:req-2>')
        req2 = make_request(builder, 'http://example.com/2', '<urn:uuid:req-2>')

        events = run_pairing([req1, req2])

        assert [event.kind for event in events] == ['unpaired', 'unpaired']
        assert PairReport.TYPE_CONFLICT in report_kinds(events[0])
        assert PairReport.TYPE_CONFLICT in report_kinds(events[1])

    def test_window_expired_then_late_reference(self):
        builder = RecordBuilder()
        req1 = make_request(builder, 'http://example.com/1', '<urn:uuid:req-1>')
        filler1 = make_request(builder, 'http://example.com/f1', '<urn:uuid:f-1>')
        filler2 = make_request(builder, 'http://example.com/f2', '<urn:uuid:f-2>')
        resp = make_response(builder, 'http://example.com/1', '<urn:uuid:resp-1>',
                             concurrent_to='<urn:uuid:req-1>')

        events = run_pairing([req1, filler1, filler2, resp], window=2)

        by_id = {}
        for event in events:
            if event.kind == 'unpaired':
                by_id[rec_id(event.record)] = event

        # req-1's window expired before its response arrived
        assert by_id['<urn:uuid:req-1>'].reason == \
            PairingIterator.REASON_WINDOW_EXPIRED

        # the late response can not retroactively modify that result
        late = by_id['<urn:uuid:resp-1>']
        assert late.reason == PairingIterator.REASON_EOF
        assert PairReport.LATE_REFERENCE in report_kinds(late)

    def test_pending_budget_exceeded(self):
        builder = RecordBuilder()
        records = [make_request(builder, 'http://example.com/%d' % n,
                                '<urn:uuid:req-%d>' % n)
                   for n in range(3)]

        events = run_pairing(records, window=100, max_pending=1)

        assert events[0].kind == 'unpaired'
        assert events[0].reason == PairingIterator.REASON_BUDGET_EXCEEDED
        assert rec_id(events[0].record) == '<urn:uuid:req-0>'

    def test_unresolved_target_reported(self):
        builder = RecordBuilder()
        req = make_request(builder, 'http://example.com/', '<urn:uuid:req-1>',
                           concurrent_to='<urn:uuid:resp-never>')

        events = run_pairing([req])

        assert [event.kind for event in events] == ['unpaired']
        assert PairReport.UNRESOLVED_TARGET in report_kinds(events[0])

    def test_passthrough_and_content_unchanged(self):
        builder = RecordBuilder()
        warcinfo = builder.create_warcinfo_record('t.warc', {'software': 'x'})
        metadata = builder.create_warc_record(
            'http://example.com/', 'metadata',
            payload=BytesIO(b'key: value'), length=10)
        req = make_request(builder, 'http://example.com/', '<urn:uuid:req-1>',
                           method='POST', path='/', body=b'payload-bytes')
        resp = make_response(builder, 'http://example.com/', '<urn:uuid:resp-1>',
                             payload=b'response-bytes',
                             concurrent_to='<urn:uuid:req-1>')

        events = run_pairing([warcinfo, metadata, req, resp])

        assert [event.kind for event in events] == [
            'passthrough', 'passthrough', 'pair']
        assert events[0].record.rec_type == 'warcinfo'
        assert events[1].record.rec_type == 'metadata'

        pair = events[2]
        assert pair.requests[0].content_stream().read() == b'payload-bytes'
        assert pair.responses[0].content_stream().read() == b'response-bytes'

    def test_body_budget_spills_to_disk(self, tmp_path):
        builder = RecordBuilder()
        req = make_request(builder, 'http://example.com/', '<urn:uuid:req-1>',
                           method='POST', path='/', body=b'x' * 4096)
        resp = make_response(builder, 'http://example.com/', '<urn:uuid:resp-1>',
                             payload=b'y' * 4096,
                             concurrent_to='<urn:uuid:req-1>')

        # tiny in-memory body budget: bodies spill to temp files,
        # content is still delivered intact
        events = run_pairing([req, resp], max_body_bytes=10,
                             spill_dir=str(tmp_path))

        pair = [e for e in events if e.kind == 'pair'][0]
        assert pair.requests[0].content_stream().read() == b'x' * 4096
        assert pair.responses[0].content_stream().read() == b'y' * 4096

    def test_early_close_leaves_no_temp_files(self, tmp_path):
        builder = RecordBuilder()
        records = [make_request(builder, 'http://example.com/%d' % n,
                                '<urn:uuid:req-%d>' % n,
                                method='POST', path='/', body=b'x' * 2048)
                   for n in range(4)]

        writer = BufferWARCWriter(gzip=False)
        for record in records:
            writer.write_record(record)

        # zero body budget: every pending body spills to disk
        iterator = PairingIterator(writer.get_stream(), window=100,
                                   max_pending=2, max_body_bytes=0,
                                   spill_dir=str(tmp_path))

        first = next(iterator)
        assert first.kind == 'unpaired'
        assert first.reason == PairingIterator.REASON_BUDGET_EXCEEDED

        # pending bodies really are on disk right now
        assert iterator.bodies._temp_files

        iterator.close()

        assert list(tmp_path.iterdir()) == []

    def test_context_manager(self):
        builder = RecordBuilder()
        req = make_request(builder, 'http://example.com/', '<urn:uuid:req-1>')

        writer = BufferWARCWriter(gzip=False)
        writer.write_record(req)

        with PairingIterator(writer.get_stream()) as iterator:
            events = list(iterator)

        assert [event.kind for event in events] == ['unpaired']
        assert events[0].reason == PairingIterator.REASON_EOF


# ============================================================================
if __name__ == '__main__':
    for event in run_pairing(demo_records()):
        if event.kind == 'passthrough':
            print('passthrough  {0}'.format(event.record.rec_type))
        elif event.kind == 'pair':
            for request in event.requests:
                for response in event.responses:
                    print('pair         {0} {1}  <->  {2} ({3})'.format(
                        request.http_headers.protocol,
                        rec_id(request),
                        rec_id(response),
                        response.http_headers.statusline))
            for report in event.reports:
                print('  report: {0}: {1}'.format(report.kind, report.message))
        else:
            print('unpaired     {0} {1}  reason={2}'.format(
                event.record.rec_type, rec_id(event.record), event.reason))
            for report in event.reports:
                print('  report: {0}: {1}'.format(report.kind, report.message))
