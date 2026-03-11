#!/usr/bin/env python3
"""Launcher for the Security Incident Triage Assistant CLI."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

REQUIRED_MODULES = {
    "openai": "openai",
    "dotenv": "python-dotenv",
    "azure.identity": "azure-identity",
}


def _missing_dependencies() -> list[str]:
    missing: list[str] = []
    for module, package in REQUIRED_MODULES.items():
        if importlib.util.find_spec(module) is None:
            missing.append(package)
    return sorted(set(missing))


def check_python_version() -> bool:
    """Require a modern Python runtime for type hints/features used here."""
    if sys.version_info >= (3, 9):
        return True

    print(f"❌ Python 3.9+ is required, found {sys.version.split()[0]}.")
    return False


def check_requirements() -> bool:
    """Validate dependencies without auto-installing packages at runtime."""
    missing = _missing_dependencies()
    if not missing:
        return True

    print("❌ Missing required dependencies:")
    for package in missing:
        print(f"   - {package}")
    print("\nInstall them with:\n   pip install -r requirements.txt")
    return False


def _read_env_values(path: Path) -> dict[str, str]:
    """Read simple KEY=VALUE pairs from .env-like files."""
    values: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def check_env_file() -> bool:
    """Ensure .env exists and contains valid required values."""
    env_file = Path(".env")
    if not env_file.exists():
        print("❌ .env file not found.")
        print("📝 Copy .env.example to .env and set real values.")
        return False

    values = _read_env_values(env_file)
    required = ["ENDPOINT_URL", "DEPLOYMENT_NAME"]

    missing = [key for key in required if not values.get(key)]
    if missing:
        print(f"❌ .env is missing required values: {', '.join(missing)}")
        return False

    if not values["ENDPOINT_URL"].startswith("https://"):
        print("❌ ENDPOINT_URL must start with 'https://'.")
        return False

    return True


def main() -> None:
    print("🚀 Starting Security Incident Triage Assistant")
    print("=" * 50)

    if not check_python_version() or not check_requirements() or not check_env_file():
        raise SystemExit(1)

    print("✅ Environment checks passed. Launching assistant...")
    print("=" * 50)

    try:
        from assistant import main as assistant_main

        assistant_main()
    except KeyboardInterrupt:
        print("\n👋 Assistant stopped by user.")
        raise SystemExit(0)


if __name__ == "__main__":
    main()
