"""Library logger setup."""

__all__ = ("logger",)

import logging

logger = logging.getLogger("pydantic-vault")
logger.addHandler(logging.NullHandler())
