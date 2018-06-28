import requests
from flask import current_app

from .exceptions import KeyCloakError
try:
    from urllib.parse import urljoin
except ImportError:
    from urlparse import urljoin


class ConnectionManager(object):

    def __init__(self, base_url, headers=None):

        self.base_url = urljoin(base_url, 'auth/')
        self.headers = headers

        self.verify = current_app.config.get('KEYCLOAK_SSL_CA_PATH') or False

    def get(self, path, params=None, request_headers=None):

        headers = request_headers or self.headers
        try:
            return requests.get(urljoin(self.base_url, path),
                                params=params,
                                headers=headers,
                                verify=self.verify)
        except Exception as e:
            raise KeyCloakError('Unable to connect to server {0}'.format(e))

    def post(self, path, data=None, json=None, request_headers=None):

        headers = request_headers or self.headers
        try:
            return requests.post(urljoin(self.base_url, path),
                                 data=data,
                                 json=json,
                                 headers=headers,
                                 verify=self.verify)
        except Exception as e:
            raise KeyCloakError('Unable to connect to server {0}'.format(e))

    def put(self, path, data=None, json=None, request_headers=None):

        headers = request_headers or self.headers
        try:
            return requests.put(urljoin(self.base_url, path),
                                data=data,
                                json=json,
                                headers=headers,
                                verify=self.verify)
        except Exception as e:
            raise KeyCloakError('Unable to connect to server {0}'.format(e))

    def delete(self, path, json=None, request_headers=None):

        headers = request_headers or self.headers
        try:
            return requests.delete(urljoin(self.base_url, path),
                                   json=json,
                                   headers=headers,
                                   verify=self.verify)
        except Exception as e:
            raise KeyCloakError('Unable to connect to server {0}'.format(e))
