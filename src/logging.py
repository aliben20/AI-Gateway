import logging
import sys

from src.config import settings

def setup_logging():
    logger = logging.getLogger("ai-gateway")
    logger.setLevel(getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO))

    formatter = logging.Formatter(
        "[%(asctime)s] %(levelname)s - %(name)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    try:
        log_path = settings.LOG_FILE
        file_handler = logging.FileHandler(log_path)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except Exception:
        pass  # File logging may fail on readonly filesystems (Vercel)

    return logger

logger = setup_logging()
