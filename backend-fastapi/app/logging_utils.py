from datetime import datetime
import logging
from pathlib import Path
import sys


LOG_FILE = Path(__file__).resolve().parents[1] / "logs" / "server.log"
logger = logging.getLogger("secure_messenger")


def log_event(message: str) -> None:
    timestamp = datetime.now().isoformat(timespec="seconds")
    line = f"[{timestamp}] {message}"

    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with LOG_FILE.open("a", encoding="utf-8") as log_file:
        log_file.write(f"{line}\n")

    logger.info(message)
    print(line, file=sys.stderr, flush=True)
