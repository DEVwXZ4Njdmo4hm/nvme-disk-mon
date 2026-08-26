"""Repository-root entry point for the declarative deployment system."""

import sys
from pathlib import Path

DEPLOY_SOURCE = Path(__file__).resolve().parent / "scripts" / "deploy-sys" / "src"
if str(DEPLOY_SOURCE) not in sys.path:
    sys.path.insert(0, str(DEPLOY_SOURCE))

from main import main

if __name__ == "__main__":
    raise SystemExit(main())
