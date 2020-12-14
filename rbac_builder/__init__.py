"""Role Base Access Control Builder
Import the `RBACBuilder` module to work with the RBAC builder:
    >>> from rbac_builder import RBACBuilder
    >>> rbac_builder = RBACBuilder()
See https://github.com/tukida/rbac_builder for more information
"""

__author__ = "Kidataek"
__version__ = "1.0.1"

from .base import RBACBuilder
from .baseview import BaseView
from .utils import generate_uuid
from .models import Model, SQLA
from .security.decorators import has_access, permission_name
from .security.manager import BaseSecurityManager
