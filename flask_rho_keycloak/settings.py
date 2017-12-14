from .exceptions import ConfigurationError


def init_settings(config):

    """ Add additional settings to the Flask app config object

    :param config: The flask app config.
    """

    # Basic KeyCloak client configuration
    config.setdefault('KEYCLOAK_HOST', None)
    config.setdefault('KEYCLOAK_REALM', None)
    config.setdefault('KEYCLOAK_CLIENT_NAME', None)
    config.setdefault('KEYCLOAK_CLIENT_ID', None)
    config.setdefault('KEYCLOAK_CLIENT_SECRET', None)

    # KeyCloak admin configuration
    config.setdefault('KEYCLOAK_ADMIN_ACCOUNT', 'admin-cli')
    config.setdefault('KEYCLOAK_ADMIN_SECRET', None)

    # App signing key
    config.setdefault('API_SIGNING_KEY', 'secret')


def validate_settings(config):
    """ Validates that the given settings are correct.

    :param config: The flask app config.
    """

    if config['KEYCLOAK_HOST'] is None:
        raise ConfigurationError('KEYCLOAK_HOST setting is required.')

    if config['KEYCLOAK_REALM'] is None:
        raise ConfigurationError('KEYCLOAK_REALM setting is required.')

    if config['KEYCLOAK_CLIENT_NAME'] is None:
        raise ConfigurationError('KEYCLOAK_CLIENT_NAME is required.')

    if config['KEYCLOAK_CLIENT_ID'] is None:
        raise ConfigurationError('KEYCLOAK_CLIENT_ID is required.')

    if config['KEYCLOAK_CLIENT_SECRET'] is None:
        raise ConfigurationError('KEYCLOAK_CLIENT_SECRET is required.')

    if config['KEYCLOAK_ADMIN_SECRET'] is None:
        raise ConfigurationError('KEYCLOAK_ADMIN_SECRET is required.')
        