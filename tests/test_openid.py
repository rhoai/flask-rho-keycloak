import pytest

from mock import patch
from jose import jwt
from httmock import response
from flask_rho_keycloak.openid import KeyCloakAuthManager
from flask_rho_keycloak.exceptions import KeyCloakError
from .fixtures.mocks import MockConnectionManager

class TestOpenID:

    def test_init_with_args(self):

        auth = KeyCloakAuthManager(client_name='test-client',
                                   client_secret='test-secret',
                                   host='http://127.0.0.1')

        assert auth.client_name == 'test-client'
        assert auth.client_secret == 'test-secret'
        assert auth._connection.base_url == 'http://127.0.0.1/auth/'

    def test_get_password_access_token(self, app):

        class TokenManager(MockConnectionManager):

            def post(self, path, data=None, json=None, request_headers=None):
                headers = {'content-type': 'application/json'}

                token_data = {
                    'aud': 'test-client',
                    'groups': ['test-client']
                }
                access_token = jwt.encode(token_data, 'cert')
                content = {
                    'access_token': access_token,
                    'refresh_token': 'refresh'
                }
                return response(200, content, headers, None, 5)

        with patch('flask_rho_keycloak.openid.ConnectionManager',
                   TokenManager):
            auth = KeyCloakAuthManager()
            tokens = auth.get_access_token('password',
                                           username='test-user',
                                           password='test-password')

        assert 'access_token' in tokens
        assert 'refresh_token' in tokens

    def test_invalid_credentials(self, app):

        class TokenManager(MockConnectionManager):

            def post(self, path, data=None, json=None, request_headers=None):
                headers = {'content-type': 'application/json'}

                content = b'Unauthorized'
                return response(401, content, headers, content, 5)

        with patch('flask_rho_keycloak.openid.ConnectionManager',
                   TokenManager):
            auth = KeyCloakAuthManager()

            with pytest.raises(KeyCloakError) as excinfo:
                tokens = auth.get_access_token('password',
                                               username='wrong-user',
                                               password='wrong-password')

            assert excinfo.value.response_code == 401
            assert excinfo.value.message == 'Invalid username or password.'

    def test_user_cannot_access_client(self, app):
        
        class TokenManager(MockConnectionManager):

            def post(self, path, data=None, json=None, request_headers=None):
                headers = {'content-type': 'application/json'}

                token_data = {
                    'aud': 'test-client',
                    'groups': ['wrong-client']
                }
                access_token = jwt.encode(token_data, 'cert')
                content = {
                    'access_token': access_token,
                    'refresh_token': 'refresh'
                }
                return response(200, content, headers, None, 5)

        with patch('flask_rho_keycloak.openid.ConnectionManager',
                   TokenManager):
            auth = KeyCloakAuthManager()

            with pytest.raises(KeyCloakError) as excinfo:
                tokens = auth.get_access_token('password',
                                               username='test-user',
                                               password='test-password')
                raise Exception(excinfo.value)
                assert excinfo.value.response_code == 401

    def test_invalid_grant_type(self, app):

        auth = KeyCloakAuthManager()
        with pytest.raises(ValueError) as excinfo:
            tokens = auth.get_access_token('foo')

            assert 'Unsupported grant type: foo' in str(excinfo)

    def test_missing_username_password(self, app):

        auth = KeyCloakAuthManager()
        with pytest.raises(ValueError) as excinfo:
            tokens = auth.get_access_token('password')

            assert 'Username and password required to retrieve access token'\
                in str(excinfo)

    def test_logout(self, app):

        class TokenManager(MockConnectionManager):

            def post(self, path, data=None, json=None, request_headers=None):
                headers = {'content-type': 'application/json'}
                return response(204, None, headers, None, 5)

        access_token = 'access_token'
        refresh_token = 'refresh'

        with patch('flask_rho_keycloak.openid.ConnectionManager',
                   TokenManager):
            auth = KeyCloakAuthManager()
            resp = auth.logout(access_token, refresh_token)

        assert resp == None

    def test_refresh_access_token(self, app):

        class TokenManager(MockConnectionManager):

            def post(self, path, data=None, json=None, request_headers=None):
                headers = {'content-type': 'application/json'}

                token_data = {
                    'aud': 'test-client',
                    'resource_access': ['test-client']
                }
                access_token = jwt.encode(token_data, 'cert')
                content = {
                    'access_token': access_token,
                    'refresh_token': 'refresh'
                }
                return response(200, content, headers, None, 5)

        access_token = 'access_token'
        refresh_token = 'refresh1'

        with patch('flask_rho_keycloak.openid.ConnectionManager',
                   TokenManager):
            auth = KeyCloakAuthManager()
            tokens = auth.refresh_access_token(access_token,
                                               refresh_token)

            assert 'access_token' in tokens
            assert 'refresh_token' in tokens

    def test_get_jwt_cert(self, app):

        class TokenManager(MockConnectionManager):

            def get(self, path, params=None, request_headers=None):
                headers = {'content-type': 'application/json'}
                content = {
                    'keys': ['cert']
                }
                return response(200, content, headers, None, 5)

        with patch('flask_rho_keycloak.openid.ConnectionManager',
                   TokenManager):
            auth = KeyCloakAuthManager()
            cert = auth.get_jwt_cert()

            assert cert == {'keys': ['cert']}
