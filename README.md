# VigilML

Security scanner for the AI development lifecycle.

[![PyPI version](https://img.shields.io/pypi/v/vigilml)](https://pypi.org/project/vigilml/) [![Python versions](https://img.shields.io/pypi/pyversions/vigilml)](https://pypi.org/project/vigilml/) [![License](https://img.shields.io/badge/license-MIT-green)](https://github.com/sharmaamanrajesh/vigilml/blob/main/LICENSE) [![Tests](https://img.shields.io/badge/tests-375%20passing-brightgreen)](https://github.com/sharmaamanrajesh/vigilml)

```bash
pip install vigilml && vigilml scan .
```

Requires Python 3.10+.

## Contents

- [What it catches](#what-it-catches)
- [Quick start](#quick-start)
- [All CLI options](#all-cli-options)
- [Suppressing findings](#suppressing-findings)
- [CI/CD integration](#cicd-integration)
- [Real findings on real repos](#real-findings-on-real-repos)
- [Available scanners](#available-scanners)
- [Contributing](#contributing)
- [Licence](#licence)

## What it catches

VigilML runs 7 scanners over your project and reports findings with a
file, a line number, a severity, and a remediation. The table below
lists specific detectors from each scanner, not a general summary.

| Category                | What triggers it                                    | Severity     |
|--------------------------|-------------------------------------------------------|--------------|
| Hardcoded API keys       | `openai-api-key`, `aws-secret-key`, `mongodb-connection-string` patterns in `.py`, `.ipynb`, `.env`, `Dockerfile`, and 20+ other file types | CRITICAL     |
| Private keys and tokens  | RSA/EC/OpenSSH private key headers, Slack tokens, generic `SECRET`/`KEY`/`TOKEN`-named variables | CRITICAL/MEDIUM |
| Unsafe deserialisation   | `.pkl`/`.pickle`/`.joblib`/`.dill` files on disk, `pickle.load()`, `torch.load()` without `weights_only=True` | HIGH         |
| Arbitrary code execution | `trust_remote_code=True`, `eval()`/`exec()` with a non-literal argument, `yaml.load()` without `SafeLoader` | CRITICAL     |
| Cloud misconfiguration   | S3 `ACL="public-read"`, S3 uploads without server-side encryption, IAM `"Action": "*"` wildcards | HIGH         |
| Insecure serving/build   | Docker containers running as root, Flask/FastAPI routes with no auth check, `.run(debug=True)` | HIGH         |
| Known dependency CVEs    | 140+ ML packages (torch, numpy, transformers, langchain, and more) checked against OSV.dev | CRITICAL-LOW |
| Supply chain risk        | Typosquatting (`pytorch` instead of `torch`), deprecated packages, unpinned security-critical dependencies | HIGH/MEDIUM  |
| Unvalidated LLM input    | `sys.argv`/`input()`/web response content flowing into an LLM call | CRITICAL/HIGH |
| Exposed system prompts   | API keys or internal URLs embedded in a `system_prompt` string literal | HIGH/MEDIUM  |
| Risky data handling      | HTTP (non-HTTPS) dataset downloads, downloads with no checksum verification, unverified `load_dataset()` sources | HIGH/MEDIUM  |
| PII exposure             | PII-indicator DataFrame columns (`ssn`, `email_address`), PII values passed to `print()`/`logging` calls | MEDIUM/HIGH  |
| Leaked notebook outputs  | Credentials, stack traces, or PII DataFrame previews committed inside a notebook's OUTPUT cells | CRITICAL/HIGH |
| Risky notebook cells     | `!pip install`, `!wget http://`, `%env TOKEN=...` setting a real secret | HIGH/LOW     |

## Quick start

```bash
# Scan the current directory
vigilml scan .
```

```bash
# Scan with JSON output for CI/CD pipelines
vigilml scan . --json
```

```bash
# Run only specific scanners
vigilml scan . --scanners credentials,model_files
```

## All CLI options

| Flag           | Description                                              |
|-----------------|-----------------------------------------------------------|
| `--scanners`    | Comma-separated scanner names to run, or `all` (default `all`) |
| `--json`        | Output findings as JSON to stdout                          |
| `--no-colour`   | Disable ANSI colour codes                                   |
| `--quiet`       | Print only the one-line summary                             |
| `--stats-only`  | Print only the summary panel, with no individual findings   |
| `--config`      | Path to a `.vigilml.yml` config file                        |
| `--version`     | Print the installed version and exit                        |
| `--help`        | Show usage and all available options                        |

## Suppressing findings

VigilML supports three suppression comments, checked directly in your
source files. All three require an explicit comment — there is no way
to silently disable a finding without leaving a trace in the code.

**Inline** — suppresses a single line. Use this for one isolated false
positive, such as a test fixture value that happens to match a
credential pattern.

```python
# Known false positive: fixture value used only in tests
TEST_API_KEY = "sk-test-51H8xJ2KL9mN3pQrStUvWxYz12345"  # vigilml: ignore
```

**Block** — suppresses every line between the two markers. Use this
for several consecutive lines that are all false positives, such as a
block of demo credentials in a tutorial notebook.

```python
# vigilml: ignore-start
# Demo credentials for the onboarding notebook. Never real, rotated
# before every workshop.
DEMO_HF_TOKEN = "hf_demoTokenNotARealSecret1234567890"
DEMO_OPENAI_KEY = "sk-demo-not-a-real-openai-key-000000000000"
# vigilml: ignore-end
```

**File-level** — suppresses every finding in the file. Use this only
when an entire file exists to contain example patterns, such as a
scanner's own test fixtures or its pattern definitions.

```python
# vigilml: ignore-file
"""Fixtures for the credential scanner's unit tests.

Every string below is a synthetic pattern the scanner is meant to
detect, not a real secret.
"""
```

## CI/CD integration

Basic version — fails the build on any finding, of any severity:

```yaml
name: Security scan
on: [push, pull_request]
jobs:
  vigilml:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install vigilml
      - run: vigilml scan . --no-colour
```

Strict version — narrows to the scanners whose findings are most often
CRITICAL/HIGH (`--scanners`), and writes a config that raises every
rule's `min_severity` to HIGH so the exit code reflects severity, not
just presence:

```yaml
name: Security scan (strict)
on: [push, pull_request]
jobs:
  vigilml-strict:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install vigilml
      - name: Write a CRITICAL/HIGH-only config
        run: |
          cat > .vigilml-strict.yml << 'EOF'
          version: 1
          rules:
            credentials:
              min_severity: HIGH
            model_files:
              min_severity: HIGH
            dependencies:
              min_severity: HIGH
            prompt_injection:
              min_severity: HIGH
          EOF
      - run: >
          vigilml scan . --config .vigilml-strict.yml
          --scanners credentials,model_files,dependencies,prompt_injection
          --no-colour
```

## Real findings on real repos

| Repo                                | Author          | Stars | Total findings | Most notable finding type          |
|--------------------------------------|-----------------|-------|-----------------|--------------------------------------|
| nanoGPT                              | Andrej Karpathy | 38K+  | 42               | `pii-logging` (14 occurrences)       |
| Hands-On ML (handson-ml3)            | Aurelien Geron  | 28K+  | 104              | `env-var-in-llm-prompt` (23 occurrences) |
| PyTorch-GAN                          | -               | 16K+  | 83               | `torch-load-without-weights-only` (37 occurrences) |
| Approaching (Almost) Any ML Problem  | Abhishek Thakur | 11K+  | 443              | Every finding is a dependency CVE (443 of 443) |

All repos scanned with `vigilml scan .` on unmodified public code.

## Available scanners

| Scanner name           | Flag value          | What it detects                                              |
|-------------------------|-----------------------|-----------------------------------------------------------------|
| Credentials              | `credentials`         | Hardcoded API keys, tokens, and connection strings across 20+ file types |
| Model files               | `model_files`          | Unsafe deserialisation: pickle/joblib/dill files, unsafe `torch.load()`/`yaml.load()` calls |
| Cloud & infrastructure    | `cloud`                | S3/GCS/Azure misconfigurations, insecure Dockerfiles, unauthenticated model-serving endpoints |
| Dependencies               | `dependencies`         | Known CVEs in 140+ ML packages via OSV.dev, typosquatting, deprecated packages |
| Prompt injection           | `prompt_injection`     | User-controlled input flowing into LLM calls, exposed system prompts |
| Data pipeline               | `data_pipeline`        | Insecure dataset downloads, PII in DataFrame columns or logs, data leakage |
| Notebook risks               | `notebook_risks`       | Credentials, PII, and stack traces leaked in notebook cell OUTPUTS, risky notebook cells |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, code standards, and
how to report a false positive. Open an issue at
[github.com/sharmaamanrajesh/vigilml/issues](https://github.com/sharmaamanrajesh/vigilml/issues)
before starting any large change.

## Licence

MIT — see [LICENSE](LICENSE).
