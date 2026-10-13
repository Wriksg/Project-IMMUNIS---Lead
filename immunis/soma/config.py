"""Model config loader."""
from pathlib import Path
from typing import Any

import yaml


def load_model_for_role(role: str,
                        path: str = "config/models.yaml") -> str:
    data: dict[str, Any] = yaml.safe_load(Path(path).read_text())
    model = data.get(role)
    if not model:
        raise RuntimeError(f"no model configured for role {role!r}")
    return str(model)
