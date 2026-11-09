# Reproducible authoring environment

Upstream: https://github.com/webrecorder/warcio
Upstream commit: b9036802318d20a2dec8d58e56a8dacb543fa3ef
Verified runtime: 3.13.14 (tags/v3.13.14:fd17997, Jun 10 2026, 13:03:48) [MSC v.1944 64 bit (AMD64)]
Verified platform: win32

Use an isolated virtual environment. Install the pinned dependencies with
`python -m pip install -r requirements-domain.lock`, then `python -m pip install -e .`.
Set the following environment variables before installation and testing:

```text
PYTHONUTF8=1
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1
```

Core baseline:

```text
python -m pytest -q -o addopts= test/test_archiveiterator.py test/test_writer.py test/test_digestverifyingreader.py test/test_bufferedreaders.py -k "not test_unseekable"
python domain_baseline.py
```

Measured pytest process time: 0.403 seconds on the authoring host.
The Windows pytest selection excludes two tests that invoke the Unix cat executable. domain_baseline.py checks the same forward-only read surface without an external command. Optional codec tests retain upstream skips.

All documented checks use in-memory fixtures or local temporary files. No production
accounts, data services, credentials or external network endpoints are required after setup.
Reset by making a fresh checkout of this seed and creating a new virtual environment.
Test fixtures remain under their upstream repository license.
