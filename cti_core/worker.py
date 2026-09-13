"""Continuous threat intelligence ingestion worker service."""

import asyncio
import logging
import os
import signal

from cti_core.database import AsyncSessionLocal, init_db
from cti_core.pipeline import global_pipeline

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] (worker) %(name)s: %(message)s",
)
logger = logging.getLogger("cti_worker")

SYNC_INTERVAL_SECONDS = int(os.getenv("SYNC_INTERVAL_SECONDS", "3600"))
RUN_ONCE = os.getenv("RUN_ONCE", "false").lower() in ("true", "1", "yes")


async def run_worker_loop():
    """Execute periodic ingestion and confidence scoring cycles."""
    logger.info("Initializing worker database connection...")
    await init_db()

    is_running = True

    def _handle_shutdown(signum, frame):
        nonlocal is_running
        logger.info("Shutdown signal received. Terminating worker loop...")
        is_running = False

    try:
        signal.signal(signal.SIGINT, _handle_shutdown)
        signal.signal(signal.SIGTERM, _handle_shutdown)
    except Exception:
        pass

    logger.info("Worker loop started. Sync interval: %d seconds.", SYNC_INTERVAL_SECONDS)

    while is_running:
        logger.info("Triggering scheduled CTI feed aggregation run...")
        try:
            async with AsyncSessionLocal() as session:
                result = await global_pipeline.run_pipeline(session, use_live=True)
                logger.info("Scheduled ingestion result: %s", result)
        except Exception as exc:
            logger.error("Error encountered during worker pipeline execution: %s", exc, exc_info=True)

        if RUN_ONCE:
            logger.info("RUN_ONCE set; exiting worker.")
            break

        # Wait for next interval
        for _ in range(SYNC_INTERVAL_SECONDS):
            if not is_running:
                break
            await asyncio.sleep(1)


if __name__ == "__main__":
    asyncio.run(run_worker_loop())
