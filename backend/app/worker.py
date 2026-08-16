"""Long-running Module 004 detector process."""

from __future__ import annotations

import logging
import time

from app.core.config import settings
from app.db.postgres import DatabaseUnavailableError
from app.services.detector import DetectionUnavailableError, run_detection_once

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("sentinel.detector")


def main() -> None:
    """Poll Elasticsearch for new events and write alerts."""
    logger.info("Detection worker started")
    while True:
        try:
            result = run_detection_once()
            logger.info("Detection pass complete: %s", result)
        except (DatabaseUnavailableError, DetectionUnavailableError) as exc:
            logger.warning("Detection pass unavailable: %s", exc)
        time.sleep(settings.detector_poll_interval_seconds)


if __name__ == "__main__":
    main()
