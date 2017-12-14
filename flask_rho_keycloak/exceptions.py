import requests
from .compat import json_decode_error


class KeyCloakError(Exception):
    """ KeyCloak Exceptions """

    def __init__(self, message='', response_code=None,
                 response_body=None):

        Exception.__init__(self, message)

        self.message = message
        self.response_code = response_code
        self.response_body = response_body


class ConfigurationError(KeyCloakError):
    """ A configuration error """
    pass


def raise_error_from_response(response, message):

    if response.ok:
        try:
            return response.json()
        except json_decode_error:
            return response.content

    try:
        response.raise_for_status()
    except requests.exceptions.HTTPError:
        if response.status_code == 401:
            e = 'Invalid username or password.'
        else:
            e = '{0} {1} {2}'.format(message,
                                     response.status_code,
                                     response.reason)
        raise KeyCloakError(e, response.status_code, response.reason)
