from argparse import ArgumentParser, RawTextHelpFormatter
import json
import sys

from warcio.indexer import Indexer
from warcio.checker import Checker
from warcio.extractor import Extractor
from warcio.recompressor import Recompressor
from warcio.integrity import verify_file, render_text

try:
    from importlib.metadata import version
except ImportError:
    import pkg_resources
    def version(package):
        return pkg_resources.get_distribution(package).version

# ============================================================================
def main(args=None):
    parser = ArgumentParser(description='warcio utils',
                            formatter_class=RawTextHelpFormatter)

    parser.add_argument('-V', '--version', action='version', version=get_version())

    subparsers = parser.add_subparsers(dest='cmd')
    subparsers.required = True

    index = subparsers.add_parser('index', help='WARC/ARC Indexer')
    index.add_argument('inputs', nargs='*', help='input file(s); default is stdin')
    index.add_argument('-f', '--fields', default='offset,warc-type,warc-target-uri',
            help='fields to include in json output; supported values are "offset", '
                 '"length", "filename", "http:status", "http:{http-header}" '
                 '(arbitrary http header), and "{warc-header}" (arbitrary warc '
                 'record header)')
    index.add_argument('-o', '--output', help='output file; default is stdout')
    index.set_defaults(func=indexer)

    recompress = subparsers.add_parser('recompress', help='Recompress an existing WARC or ARC',
                                       description='Read an existing, possibly broken WARC ' +
                                                   'and correctly recompress it to fix any compression errors\n' +
                                                   'Also convert any ARC file to a standard compressed WARC file')
    recompress.add_argument('filename')
    recompress.add_argument('output')
    recompress.add_argument('-v', '--verbose', action='store_true')
    recompress.set_defaults(func=recompressor)

    extract = subparsers.add_parser('extract', help='Extract WARC/ARC Record')
    extract.add_argument('filename')
    extract.add_argument('offset')
    group = extract.add_mutually_exclusive_group()
    group.add_argument('--payload', action='store_true', help='output only record payload (after content and transfer decoding, if applicable)')
    group.add_argument('--headers', action='store_true', help='output only record headers (and http headers, if applicable)')

    extract.set_defaults(func=extractor)

    check = subparsers.add_parser('check', help='WARC digest checker')
    check.add_argument('inputs', nargs='+')
    check.add_argument('-v', '--verbose', action='store_true')
    check.set_defaults(func=checker)

    integrity = subparsers.add_parser(
        'integrity',
        help='Offline, streaming WARC integrity verification (framing, gzip '
             'CRC, HTTP coding and block/payload digests as separate layers)')
    integrity.add_argument('inputs', nargs='+', help='input WARC or WARC.gz file(s)')
    integrity.add_argument('--json', action='store_true',
                           help='emit machine-readable JSON instead of text')
    integrity.set_defaults(func=integrity_checker)

    cmd = parser.parse_args(args=args)
    cmd.func(cmd)


# ============================================================================
def get_version():
    return '%(prog)s ' + version('warcio')


# ============================================================================
def indexer(cmd):
    inputs = cmd.inputs or ('-',)  # default to stdin
    _indexer = Indexer(cmd.fields, inputs, cmd.output)
    _indexer.process_all()


# ============================================================================
def checker(cmd):
    _checker = Checker(cmd)
    sys.exit(_checker.process_all())


# ============================================================================
def integrity_checker(cmd):
    exit_value = 0
    reports = [verify_file(path) for path in cmd.inputs]
    if cmd.json:
        payload = [report.as_dict() for report in reports]
        sys.stdout.write(json.dumps(payload, indent=2) + '\n')
    else:
        for index, report in enumerate(reports):
            if index:
                sys.stdout.write('\n')
            sys.stdout.write(render_text(report) + '\n')
    for report in reports:
        if report.status in ('fail', 'incomplete'):
            exit_value = 1
    sys.exit(exit_value)


# ============================================================================
def extractor(cmd):
    _extractor = Extractor(cmd.filename, cmd.offset)
    _extractor.extract(cmd.payload, cmd.headers)


# ============================================================================
def recompressor(cmd):
    _recompressor = Recompressor(cmd.filename, cmd.output, cmd.verbose)
    _recompressor.recompress()


# ============================================================================
if __name__ == "__main__":  #pragma: no cover
    main()
