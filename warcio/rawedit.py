"""
Raw-block-preserving WARC record editing.

This module provides an editing entry point for use cases such as
adding capture metadata headers or fixing a WARC-Target-URI, where the
record block (the HTTP status line, HTTP headers and the payload) must
be copied as opaque bytes and must remain byte-for-byte identical to
the original -- including duplicate HTTP headers, header casing,
chunk extensions and (possibly compressed) payload bodies.

``Content-Length`` and ``WARC-Block-Digest`` are derived from the
actual block bytes and are therefore always computed by the output
process; attempting to set them through an edit raises
``ComputedHeaderEditError``.

Usage::

    from warcio.archiveiterator import ArchiveIterator
    from warcio.rawedit import RawBlockEditor

    editor = RawBlockEditor()
    with open('in.warc.gz', 'rb') as fh, open('out.warc.gz', 'wb') as out:
        for record in ArchiveIterator(fh, no_record_parse=True):
            editor.write_record(record, out, gzip=True, edits=[
                ('set', 'WARC-Target-URI', 'http://example.com/fixed'),
                ('add', 'X-Collection-Tag', 'crawl-2026'),
            ])

The input stream does not need to be seekable. The block is spooled to
a temporary buffer (in memory up to ``max_mem_size`` bytes, then on
disk) and the output record is only written once the block has been
read in full and verified, so a failure never produces a partial
output record that claims to be complete.
"""

from collections import namedtuple

import tempfile

from warcio.digestverifyingreader import _compare_digest_rfc_3548
from warcio.utils import Digester, BUFF_SIZE
from warcio.warcwriter import GzippingWrapper


# ============================================================================
class RawBlockEditError(Exception):
    """ A record could not be edited with its raw block preserved """


class DigestVerificationFailed(RawBlockEditError):
    """ The existing WARC-Block-Digest did not match the block bytes """


class ComputedHeaderEditError(ValueError):
    """ Attempt to edit a header that is computed from the content """


# ============================================================================
#: headers computed by the output process, not directly editable
COMPUTED_HEADERS = frozenset(('content-length', 'warc-block-digest'))

#: result of editing a single record
#: - length: byte length of the raw block (the new Content-Length)
#: - block_digest: the newly computed WARC-Block-Digest value
#: - verified: True if an existing WARC-Block-Digest matched the block,
#:   None if there was no usable original digest to verify against
#:   (verification is never claimed without an original digest)
EditResult = namedtuple('EditResult', ['length', 'block_digest', 'verified'])


# ============================================================================
def apply_header_edits(rec_headers, edits):
    """
    Apply a sequence of edits to a StatusAndHeaders WARC header block,
    in order. Each edit is a tuple:

    - ('set', name, value):
        Replace ALL existing occurrences of `name` with a single
        header, inserted at the position of the first occurrence
        (appended if not present).
    - ('set_all', name, values):
        Replace ALL existing occurrences of `name` with one header per
        value in `values`, inserted at the position of the first
        occurrence (appended if not present).
    - ('set_at', name, index, value):
        Replace only the `index`-th (0-based) occurrence of `name`,
        leaving other duplicates and their order untouched.
        Raises IndexError if there is no such occurrence.
    - ('add', name, value):
        Append a new header, keeping any existing duplicates.
    - ('remove', name):
        Remove ALL occurrences of `name`.

    Headers listed in COMPUTED_HEADERS (Content-Length and
    WARC-Block-Digest) can not be edited: they are computed from the
    actual content by the output process. Attempting to edit one
    raises ComputedHeaderEditError.

    Headers not named by any edit are kept as-is, preserving duplicate
    headers and their original order.
    """
    for edit in edits:
        op = edit[0]
        name = edit[1]

        if name.lower() in COMPUTED_HEADERS:
            msg = 'Header {0} is computed from the content and can not be edited'
            raise ComputedHeaderEditError(msg.format(name))

        if op == 'set':
            rec_headers.replace_all_headers(name, [edit[2]])
        elif op == 'set_all':
            rec_headers.replace_all_headers(name, list(edit[2]))
        elif op == 'set_at':
            rec_headers.replace_header_at(name, edit[2], edit[3])
        elif op == 'add':
            rec_headers.add_header(name, edit[2])
        elif op == 'remove':
            rec_headers.replace_all_headers(name, [])
        else:
            raise ValueError('Unknown header edit operation: ' + repr(op))

    return rec_headers


# ============================================================================
class RawBlockEditor(object):
    """
    Edits WARC records while preserving the raw record block
    byte-for-byte.

    Records are typically read with
    ``ArchiveIterator(fh, no_record_parse=True)`` so that the HTTP
    headers and payload are never parsed, decompressed or re-chunked.

    ``max_mem_size`` controls how many bytes of a record block are
    buffered in memory before spilling to a temporary file.
    """

    def __init__(self, max_mem_size=512 * 1024, digest_algorithm='sha1'):
        self.max_mem_size = max_mem_size
        self.digest_algorithm = digest_algorithm

    def write_record(self, record, out, edits=(), gzip=False):
        """
        Write `record` to `out` with `edits` applied to its WARC
        headers, copying the record block as opaque bytes.

        The entire block is buffered and checked first; if reading or
        verifying the block fails, or an edit is invalid, nothing is
        written to `out`, so no partial record claiming to be complete
        is ever produced.

        If the record carries a WARC-Block-Digest, the block bytes are
        verified against it (using the digest's own algorithm) and a
        mismatch raises DigestVerificationFailed. If there is no
        original digest, verification is not claimed: the returned
        EditResult.verified is None.

        Content-Length and WARC-Block-Digest in the output are always
        computed from the actual block bytes.

        Returns an EditResult.
        """
        if record.format != 'warc':
            raise RawBlockEditError('Can only edit WARC records, found: ' +
                                    str(record.format))

        if record.length is None:
            raise RawBlockEditError('Record has no known Content-Length')

        rec_headers = record.rec_headers

        block_digester = Digester(self.digest_algorithm)
        verify_digester = self._make_verify_digester(rec_headers)

        # buffer the whole block before writing anything out
        block = tempfile.SpooledTemporaryFile(max_size=self.max_mem_size)
        try:
            self._buffer_block(record, block, block_digester, verify_digester)

            verified = self._verify(rec_headers, verify_digester)

            apply_header_edits(rec_headers, edits)

            rec_headers.replace_all_headers('Content-Length',
                                            [str(record.length)])
            block_digest = str(block_digester)
            rec_headers.replace_all_headers('WARC-Block-Digest',
                                            [block_digest])

            self._write_record(out, rec_headers, block, gzip)
        finally:
            block.close()

        return EditResult(length=record.length,
                          block_digest=block_digest,
                          verified=verified)

    def _buffer_block(self, record, block, block_digester, verify_digester):
        read = 0
        while True:
            buff = record.raw_stream.read(BUFF_SIZE)
            if not buff:
                break

            read += len(buff)
            block_digester.update(buff)
            if verify_digester:
                verify_digester.update(buff)

            block.write(buff)

        if read != record.length:
            msg = 'Record block truncated: expected {0} bytes, got {1}'
            raise RawBlockEditError(msg.format(record.length, read))

    def _make_verify_digester(self, rec_headers):
        orig_digest = rec_headers.get_header('WARC-Block-Digest')
        if not orig_digest:
            return None

        algo = orig_digest.partition(':')[0]
        try:
            return Digester(algo)
        except ValueError:
            # unknown algorithm: can not verify, do not claim verification
            return None

    def _verify(self, rec_headers, verify_digester):
        if not verify_digester:
            return None

        orig_digest = rec_headers.get_header('WARC-Block-Digest')
        check = _compare_digest_rfc_3548(verify_digester, orig_digest)
        if check is False:
            raise DigestVerificationFailed(
                'WARC-Block-Digest mismatch: ' + orig_digest)

        return True if check else None

    def _write_record(self, out, rec_headers, block, gzip):
        if gzip:
            out = GzippingWrapper(out)

        # WARC headers can be utf-8 per spec
        out.write(rec_headers.to_bytes(encoding='utf-8'))

        block.seek(0)
        while True:
            buff = block.read(BUFF_SIZE)
            if not buff:
                break

            out.write(buff)

        # add two lines
        out.write(b'\r\n\r\n')

        out.flush()
