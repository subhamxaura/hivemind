"""Export FastAPI OpenAPI schema to docs/openapi.yaml."""

from __future__ import annotations

from pathlib import Path

import yaml

from hivemind.api import app


def main() -> None:
    """Generate and write the OpenAPI schema from the FastAPI app."""
    output_path = Path(__file__).resolve().parents[1] / "docs" / "openapi.yaml"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    schema = app.openapi()
    with open(output_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(schema, f, sort_keys=False, allow_unicode=True)
    print(f"Exported OpenAPI schema to {output_path}")


if __name__ == "__main__":
    main()
