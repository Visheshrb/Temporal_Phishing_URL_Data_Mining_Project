"""Module loggers with one consistent format."""

import logging

FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"
DATEFMT = "%Y-%m-%d %H:%M:%S"


def get_logger(name: str) -> logging.Logger:
    """Return the logger `name` at INFO level with a single stderr handler.

    Calling it again for the same name does not add another handler. Records still propagate,
    so pytest's caplog sees them.
    """
    logger = logging.getLogger(name)
    if not any(getattr(h, "_phishshift", False) for h in logger.handlers):
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter(FORMAT, DATEFMT))
        handler._phishshift = True
        logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    return logger
