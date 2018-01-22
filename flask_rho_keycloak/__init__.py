import logging

__version__ = '0.2.1'

logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.INFO)

from .openid import KeyCloakAuthManager
from .admin import KeyCloakAdminManager
from .decorators import check_jwt_auth