"""``python -m ai_gateway.scheduler``."""

import logging
import sys

from ai_gateway.scheduler import main

if __name__ == "__main__":  # pragma: no cover
    logging.basicConfig(level=logging.INFO)
    sys.exit(main())
