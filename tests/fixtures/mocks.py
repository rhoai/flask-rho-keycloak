from httmock import urlmatch, response
from jose import jwt
from flask_rho_keycloak import url_patterns


class MockConnectionManager(object):

    def __init__(self, host=None):

        self.host = host


class MockKeyCloakAuthManager(object):

    def __init__(self, username=None, password=None):

        self.username = username
        self.password = password

    def get_jwt_cert(self):
        return {
           'cert': 'cert'
        }

    def get_access_token(self, grant_type):
        return {
            'access_token': 'access_token',
            'refresh_token': 'refresh_token'
        }