"""Definition of base container controllers.

It contains functionality concerning the management of containers and related
objects, e.g. clusters, that are common among different cloud providers.
"""
from mist.api.clouds.controllers.base import BaseController

log = logging.getLogger(__name__)

__all__ = [
    "BaseContainerController",
]

class BaseContainerController(BaseController):
    """Abstract base class for clouds that provide container features."""
