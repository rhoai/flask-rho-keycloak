import pytest

from flask import Flask
from werkzeug.contrib.cache import SimpleCache

from flask_rho_keycloak.core import KeyCloak
from flask_rho_keycloak.decorators import check_jwt_auth
from mocks import MockKeyCloakAuthManager


def get_app_config():

    config = {
        'KEYCLOAK_HOST': 'http://localhost:8080',
        'KEYCLOAK_REALM': 'test-realm',
        'KEYCLOAK_CLIENT_NAME': 'test-client',
        'KEYCLOAK_CLIENT_ID': '123456',
        'KEYCLOAK_CLIENT_SECRET': 'client-secret',
        'KEYCLOAK_ADMIN_SECRET': 'admin-secret',
        'API_SIGNING_KEY': 'test-secret'
    }
    return config


def bootstrap_app():

    # Create basic flask app
    app = Flask(__name__)
    config = get_app_config()
    app.config.update(config)

    cache = SimpleCache()
    KeyCloak(app, cache, MockKeyCloakAuthManager)

    @app.route('/secure')
    @check_jwt_auth
    def secure_route():
        return "Requires jwt auth"

    return app


@pytest.fixture(scope="session")
def app(request):

    app = bootstrap_app()

    ctx = app.app_context()
    ctx.push()

    def teardown():
        ctx.pop()

    request.addfinalizer(teardown)
    return app
