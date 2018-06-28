from .openid import KeyCloakAuthManager
from .settings import init_settings, validate_settings


def _get_state(app, cache, **kwargs):

    kwargs.update(dict(
        app=app,
        cache=cache
    ))
    return _KeyCloakState(**kwargs)


class _KeyCloakState(object):

    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key.lower(), value)


class KeyCloak(object):
    """ Initializes the Flask-KeyCloak extension """

    def __init__(self, app=None, cache=None, auth_manager=None):
        self.app = app

        if self.app is not None:
            self.init_app(app, cache, auth_manager)

    def init_app(self, app, cache, auth_manager=None, **kwargs):
        """ Initialize the Flask application """

        # set the default settings
        init_settings(app.config)

        # validate the settings
        validate_settings(app.config)

        self.init_certs(app, cache, auth_manager)

        self._state = state = _get_state(app, cache, **kwargs)
        app.extensions['keycloak'] = state

    def init_certs(self, app, cache=None, auth_manager=None):
        """ retrieve jwt certs from keycloak and store """

        with app.app_context():
            if auth_manager:
                auth = auth_manager()
            else:
                auth = KeyCloakAuthManager()
            key = auth.get_jwt_cert()

        cache.set('keycloak_secret_key', key, timeout=0)
        