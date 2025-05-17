import os
import logging
from .config import *

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)

CORS_ORIGINS = os.getenv("CORS_ORIGINS", "").split(",")