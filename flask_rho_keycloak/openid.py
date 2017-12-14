from flask import current_app
from jose import jwt
from werkzeug.local import LocalProxy

import url_patterns
from .connection import ConnectionManager
from .exceptions import KeyCloakError, raise_error_from_response


_keycloak = LocalProxy(lambda: current_app.extensions['keycloak'])
_cache = LocalProxy(lambda: _keycloak.cache)


class KeyCloakAuthManager(object):

    def __init__(self, client_name=None, client_secret=None, host=None):

        if client_name:
            self.client_name = client_name
        else:
            self.client_name = current_app.config['KEYCLOAK_CLIENT_NAME']

        if client_secret:
            self.client_secret = client_secret
        else:
            self.client_secret = current_app.config['KEYCLOAK_CLIENT_SECRET']

        if host:
            host = host
        else:
            host = current_app.config['KEYCLOAK_HOST']
        conn = ConnectionManager(host)
        self._connection = conn

    def get_access_token(self, grant_type, username=None, password=None):

        supported_grant_types = [
            'client_credentials', 'password'
        ]
        if grant_type not in supported_grant_types:
            raise ValueError('Unsupported grant type: {0}'.format(grant_type))

        if grant_type != 'client_credentials' and\
                not (username and password):
            raise ValueError('Username and password required '
                             'to retrieve access token.')

        headers = {
            'accept': 'application/json',
            'content-type': 'application/x-www-form-urlencoded'
        }

        path_params = {'realm-name': current_app.config['KEYCLOAK_REALM']}
        data = {
            'client_id': self.client_name,
            'client_secret': self.client_secret,
            'grant_type': grant_type
        }
        if username and password:
            data['username'] = username
            data['password'] = password

        response = self._connection.post(
            url_patterns.URL_TOKEN.format(**path_params), data=data,
            request_headers=headers
        )

        message = 'Error while retrieving access token'
        raw = raise_error_from_response(response, message)

        if grant_type == 'password':
            # if user check they are users of client
            access_token = raw['access_token']
            token_data = jwt.decode(
                access_token,
                _cache.get('keycloak_secret_key'),
                audience=current_app.config['KEYCLOAK_CLIENT_NAME']
            )
            #return token_data
            if current_app.config['KEYCLOAK_CLIENT_NAME']\
                    not in token_data['groups']:
                raise KeyCloakError(response_code=401)
        return raw

    def refresh_access_token(self, access_token, refresh_token):

        path_params = {'realm-name': current_app.config['KEYCLOAK_REALM']}
        data = {
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token,
            'client_id': self.client_name,
            'client_secret': self.client_secret
        }

        response = self._connection.post(
            url_patterns.URL_TOKEN.format(**path_params), data=data)

        message = 'Error while refreshing access token'
        raw = raise_error_from_response(response, message)
        return raw
        #return raw['access_token']

    def logout(self, access_token, refresh_token):

        headers = {
            'authorization': 'Bearer {}'.format(access_token)
        }

        path_params = {'realm-name': current_app.config['KEYCLOAK_REALM']}
        data = {
            'refresh_token': refresh_token,
            'client_id': self.client_name,
            'client_secret': self.client_secret
        }

        response = self._connection.post(
            url_patterns.URL_LOGOUT.format(**path_params), data=data,
            request_headers=headers)

        message = 'Error logging out user'
        return raise_error_from_response(response, message)

    def get_jwt_cert(self):
        """ retrive jwt cert from keycloak """
        headers = {
            'content-type': 'application/json'
        }
        path_params = {'realm-name': current_app.config['KEYCLOAK_REALM']}

        response = self._connection.get(
            url_patterns.URL_CERTS.format(**path_params),
            request_headers=headers
        )

        message = 'Error retrieving cert keys'
        return raise_error_from_response(response, message)
