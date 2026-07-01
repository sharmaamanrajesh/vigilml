# VigilML

**Security for the AI development lifecycle.**

VigilML is a free CLI that catches AI-specific security vulnerabilities
before ML engineers push code. Install it in 30 seconds, scan your
project in under 10.

```bash
pip install vigilml
vigilml scan .
```

---

## What it catches

| Vulnerability | Example | Severity |
|---------------|---------|----------|
| Hardcoded API keys | OpenAI, HuggingFace, AWS tokens in `.py` and `.ipynb` files | CRITICAL |
| Unsafe model deserialisation | `.pkl` files, `torch.load()` without `weights_only=True` | HIGH |
| Cloud misconfigurations | Public S3 writes, world-readable model output directories | MEDIUM |
| ML dependency CVEs | Outdated `torch`, `numpy`, `transformers` with known CVEs | HIGH–LOW |

---

## Install

```bash
pip install vigilml
```

Requires Python 3.10+. No account. No sign-up. No telemetry by default.

---

## Usage

```bash
# Scan the current directory
vigilml scan .

# Scan a specific path
vigilml scan /path/to/ml/project

# JSON output for CI/CD
vigilml scan . --json

# No colour for CI logs
vigilml scan . --no-colour

# Quiet mode — summary line only
vigilml scan . --quiet
```

Exit code `0` = clean. Exit code `1` = findings present.

---

## CI/CD integration

VigilML is CI/CD ready out of the box. Add it to your GitHub Actions:

```yaml
- name: VigilML security scan
  run: |
    pip install vigilml
    vigilml scan . --no-colour
```

---

## Configuration

Add a `.vigilml.yml` to your project root to customise behaviour:

```yaml
version: 1
scan:
  exclude_paths:
    - "legacy/"
    - "notebooks/archive/"
rules:
  cloud:
    enabled: false  # using a separate cloud security tool
  dependencies:
    min_severity: HIGH
```

---

## Community

- Discord: [discord.gg/vigilml](https://discord.gg/vigilml)
- Issues: [github.com/vigilml/vigilml/issues](https://github.com/vigilml/vigilml/issues)
- Docs: [docs.vigilml.ai](https://docs.vigilml.ai)

---

## Licence

MIT — free forever for individuals.
Team and enterprise plans at [vigilml.ai](https://vigilml.ai).
