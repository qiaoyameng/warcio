"""Offline unseekable input check without the Unix cat executable."""
import io
from pathlib import Path
from warcio.archiveiterator import ArchiveIterator

class ForwardOnly:
    def __init__(self,data): self.stream=io.BytesIO(data)
    def read(self,n=-1): return self.stream.read(n)

for filename in ('example-iana.org-chunked.warc','example.warc.gz'):
    data=(Path(__file__).parent/'test/data'/filename).read_bytes()
    def read(source):
        return [(r.rec_type,r.rec_headers.get_header('WARC-Record-ID'),r.content_stream().read()) for r in ArchiveIterator(source)]
    assert read(ForwardOnly(data))==read(io.BytesIO(data))
print('PASS: forward-only plain and gzip WARC match seekable input')
