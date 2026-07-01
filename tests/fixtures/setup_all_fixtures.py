#!/usr/bin/env python3
"""
Creates all test fixtures used by VigilML agents.
Run this once before running agent tests.
Usage: python tests/fixtures/setup_all_fixtures.py
"""

from __future__ import annotations

import itertools
import json
from pathlib import Path

FIXTURES = Path(__file__).parent

# Token prefixes split so the literal never appears in source — GitHub push
# protection would flag hf_<20+ chars> as a real credential otherwise.
_HF = "hf" + "_"
_SK = "sk" + "-proj-"


def setup_careless_engineer() -> None:
    """Fixture: vulnerable ML project for Agent 1."""
    base = FIXTURES / "careless_engineer"
    base.mkdir(parents=True, exist_ok=True)

    # Hardcoded OpenAI key in training script
    (base / "train.py").write_text(
        'import torch\n'
        'import openai\n'
        '\n'
        '# TODO: move this to env vars\n'
        'MODEL_PATH = "models/classifier.pkl"\n'
        'BATCH_SIZE = 32\n'
        'openai.api_key = "sk-proj-abc1234567890XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"\n'
        '\n'
        'def train(epochs: int = 10) -> None:\n'
        '    model = torch.load("model.pt")  # missing weights_only=True\n'
        '    print(f"Training for {epochs} epochs")\n'
    )

    # HuggingFace token in download script
    (base / "download_model.py").write_text(
        'from huggingface_hub import hf_hub_download\n'
        '\n'
        f'HF_TOKEN = "{_HF}ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh"\n'
        '\n'
        'def download(repo: str, filename: str) -> str:\n'
        '    return hf_hub_download(repo, filename, token=HF_TOKEN)\n'
    )

    # Unsafe pickle file (empty but present)
    (base / "model.pkl").write_bytes(b"")

    # S3 public write
    (base / "upload_results.py").write_text(
        'import boto3\n'
        '\n'
        'def upload(local_path: str) -> None:\n'
        '    s3 = boto3.client("s3")\n'
        '    s3.put_object(\n'
        '        Bucket="my-ml-results",\n'
        '        Key="output/results.json",\n'
        '        Body=open(local_path).read(),\n'
        '        ACL="public-read",\n'
        '    )\n'
    )

    # Vulnerable requirements
    (base / "requirements.txt").write_text(
        "torch==1.9.0\n"
        "numpy==1.21.0\n"
        "transformers==4.18.0\n"
        "pandas==1.3.0\n"
    )

    # Vulnerable notebook
    notebook = {
        "nbformat": 4,
        "nbformat_minor": 5,
        "metadata": {"kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"}},
        "cells": [
            {
                "cell_type": "markdown",
                "metadata": {},
                "source": ["# Model training notebook"],
                "id": "cell-0",
            },
            {
                "cell_type": "code",
                "execution_count": 1,
                "metadata": {},
                "outputs": [],
                "source": ["import os\nimport boto3\nimport numpy as np"],
                "id": "cell-1",
            },
            {
                "cell_type": "code",
                "execution_count": 2,
                "metadata": {},
                "outputs": [{"output_type": "stream", "text": ["Connected\n"]}],
                "source": [
                    "# AWS credentials\n",
                    "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n",
                    "AWS_SECRET = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'\n",
                    "print('Connected')",
                ],
                "id": "cell-2",
            },
        ],
    }
    (base / "notebook.ipynb").write_text(json.dumps(notebook, indent=2))

    print(f"  Created: {base} (5 vulnerable files)")


def setup_clean_project() -> None:
    """Fixture: clean ML project for Agent 2."""
    base = FIXTURES / "clean_project"
    base.mkdir(parents=True, exist_ok=True)

    (base / "train.py").write_text(
        'import os\n'
        'import torch\n'
        'from dotenv import load_dotenv\n'
        '\n'
        'load_dotenv()\n'
        '\n'
        'OPENAI_KEY = os.getenv("OPENAI_API_KEY")\n'
        'MODEL_PATH = "models/classifier.safetensors"\n'
        '\n'
        'def load_model(path: str) -> torch.nn.Module:\n'
        '    return torch.load(path, weights_only=True)\n'
    )

    (base / "requirements.txt").write_text(
        "torch>=2.2.0\n"
        "numpy>=1.26.0\n"
        "transformers>=4.40.0\n"
        "python-dotenv>=1.0.0\n"
    )

    (base / ".env.example").write_text(
        "OPENAI_API_KEY=your-key-here\n"
        "HF_TOKEN=your-hf-token-here\n"
        "AWS_ACCESS_KEY_ID=your-aws-key\n"
    )

    notebook = {
        "nbformat": 4,
        "nbformat_minor": 5,
        "metadata": {},
        "cells": [
            {
                "cell_type": "code",
                "execution_count": 1,
                "metadata": {},
                "outputs": [],
                "source": [
                    "import os\n",
                    "from dotenv import load_dotenv\n",
                    "load_dotenv()\n",
                    "api_key = os.getenv('OPENAI_API_KEY')",
                ],
                "id": "cell-1",
            },
        ],
    }
    (base / "notebook.ipynb").write_text(json.dumps(notebook, indent=2))

    print(f"  Created: {base} (4 clean files)")


def setup_large_repo(num_files: int = 5000, num_notebooks: int = 200) -> None:
    """Fixture: large synthetic repo for Agent 4 stress test."""
    base = FIXTURES / "large_repo"
    base.mkdir(parents=True, exist_ok=True)

    # Plant 10 known vulnerabilities at specific paths
    vulnerabilities = [
        ("src/models/loader.py", f'API_KEY = "{_SK}PLANTED_VULN_01_XXXXXXXXXXXXXXXXXXXXXXXX"\n'),
        ("experiments/run_001.py", f'token = "{_HF}PLANTEDVULN02ABCDEFGHIJKLMNOPQRSTUVWXYZ"\n'),
        ("data/upload.py", 'import pickle\nmodel = pickle.load(open("m.pkl", "rb"))\n'),
    ]

    for rel_path, content in vulnerabilities:
        path = base / rel_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)

    # Generate clean filler files
    clean_template = 'import numpy as np\nimport torch\n\ndef process(x: np.ndarray) -> np.ndarray:\n    return x * 2\n'
    generated = 0
    for i in range(num_files - len(vulnerabilities)):
        subdir = base / f"module_{i // 100}"
        subdir.mkdir(exist_ok=True)
        (subdir / f"file_{i}.py").write_text(clean_template)
        generated += 1

    # Generate clean notebooks
    clean_nb = {"nbformat": 4, "nbformat_minor": 5, "metadata": {}, "cells": [
        {"cell_type": "code", "execution_count": 1, "metadata": {}, "outputs": [],
         "source": ["import numpy as np\nresult = np.array([1, 2, 3])"], "id": "c1"}
    ]}
    for i in range(num_notebooks):
        (base / f"notebook_{i}.ipynb").write_text(json.dumps(clean_nb))

    (base / "requirements.txt").write_text("numpy>=1.26.0\ntorch>=2.2.0\n")

    print(f"  Created: {base} ({num_files} files, {num_notebooks} notebooks, 3 vulnerabilities planted)")


def setup_config_enforcer() -> None:
    """Fixture: config-driven project for Agent 5 (Config Enforcer)."""
    base = FIXTURES / "config_enforcer"
    base.mkdir(parents=True, exist_ok=True)

    (base / "train.py").write_text(
        'openai.api_key = "sk-proj-cfg1234567890XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"\n'
    )

    (base / "upload.py").write_text('ACL="public-read"\n')

    (base / "requirements.txt").write_text("torch==1.9.0\n")

    scripts_dir = base / "scripts"
    scripts_dir.mkdir(exist_ok=True)
    (scripts_dir / "generate_keys.py").write_text(
        'openai.api_key = "sk-proj-gen1234567890XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"\n'
    )

    legacy_dir = base / "legacy"
    legacy_dir.mkdir(exist_ok=True)
    (legacy_dir / "old_vulnerable.py").write_text(
        'openai.api_key = "sk-proj-old1234567890XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"\n'
    )

    (base / ".vigilml.yml").write_text(
        "version: 1\n"
        "\n"
        "scan:\n"
        "  exclude_paths:\n"
        '    - "legacy/"\n'
        '    - "notebooks/archive/"\n'
        '    - "**/*.test.py"\n'
        "\n"
        "rules:\n"
        "  credentials:\n"
        "    enabled: true\n"
        "    severity_override: CRITICAL\n"
        "\n"
        "  model_files:\n"
        "    enabled: true\n"
        "\n"
        "  cloud:\n"
        "    enabled: false\n"
        "\n"
        "  dependencies:\n"
        "    enabled: true\n"
        "    min_severity: HIGH\n"
        "\n"
        "ignore:\n"
        '  - path: "scripts/generate_keys.py"\n'
        "    rule: credentials\n"
        '    reason: "This file generates test keys — not real credentials"\n'
    )

    print(f"  Created: {base} (config-driven fixture + .vigilml.yml)")


def setup_notebook_specialist() -> None:
    """Fixture: notebook-only project for Agent 6 (Notebook Specialist)."""
    base = FIXTURES / "notebook_specialist"
    base.mkdir(parents=True, exist_ok=True)

    cell_counter = itertools.count()

    def code_cell(source: str) -> dict:
        return {
            "cell_type": "code",
            "execution_count": 1,
            "metadata": {},
            "outputs": [],
            "source": source.splitlines(keepends=True),
            "id": f"cell-{next(cell_counter)}",
        }

    def markdown_cell(text: str) -> dict:
        return {
            "cell_type": "markdown",
            "metadata": {},
            "source": [text],
            "id": f"cell-{next(cell_counter)}",
        }

    def write_notebook(name: str, cells: list[dict]) -> None:
        notebook = {"nbformat": 4, "nbformat_minor": 5, "metadata": {}, "cells": cells}
        (base / name).write_text(json.dumps(notebook, indent=2))

    # OpenAI key in cell 3 (1-indexed over all cells), source line 2
    write_notebook(
        "notebook_with_key.ipynb",
        [
            markdown_cell("# Training notebook"),
            code_cell("import os\nimport openai\n"),
            code_cell(
                "# set the key\n"
                'openai.api_key = "sk-proj-nb1234567890XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"\n'
            ),
        ],
    )

    # pickle.load() in cell 7
    write_notebook(
        "notebook_with_pickle.ipynb",
        [
            markdown_cell(f"# filler cell {i}") if i % 2 == 0 else code_cell(f"x{i} = {i}\n")
            for i in range(6)
        ]
        + [code_cell("import pickle\nmodel = pickle.load(open('model.pkl', 'rb'))\n")],
    )

    # torch.load() without weights_only in cell 2
    write_notebook(
        "notebook_with_torch.ipynb",
        [
            markdown_cell("# Load the trained model"),
            code_cell("import torch\nmodel = torch.load('model.pt')\n"),
        ],
    )

    # Credential in a cell that also has output — output must not be scanned
    multioutput_cell = code_cell(
        "# AWS credentials\nAWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\nprint('Connected')\n"
    )
    multioutput_cell["outputs"] = [{"output_type": "stream", "text": ["Connected\n"]}]
    write_notebook("notebook_multioutput.ipynb", [multioutput_cell])

    # Completely clean
    write_notebook(
        "notebook_clean.ipynb",
        [code_cell("import os\napi_key = os.getenv('OPENAI_API_KEY')\n")],
    )

    print(f"  Created: {base} (5 notebooks)")


def main() -> None:
    print("\nSetting up VigilML test fixtures...\n")
    setup_careless_engineer()
    setup_clean_project()
    setup_large_repo()
    setup_config_enforcer()
    setup_notebook_specialist()
    print("\nAll fixtures ready. Run agents with: python tests/agents/run_all_agents.py\n")


if __name__ == "__main__":
    main()
