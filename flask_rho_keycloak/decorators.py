from functools import wraps

from flask import request, current_app, jsonify, make_response
from werkzeug.local import LocalProxy
from jose import jwt, ExpiredSignatureError, JWTError


_keycloak = LocalProxy(lambda: current_app.extensions['keycloak'])
_cache = LocalProxy(lambda: _keycloak.cache)


def _get_unauthorized_response(text=None, code=401, json=False):
    if json:
        return make_response(jsonify({
            'status': 'error',
            'result': text
        }), code)


def check_jwt_auth(function):
    """ Decorator that protects endpoints using jwt token authentication. 
        The token should be added to the request in the 'Authorization'
        header.
    """

    @wraps(function)
    def wrapper(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return _get_unauthorized_response(
                text='Not authorized', json=True)

        try:
            user_info = jwt.decode(
                token,
                _cache.get('keycloak_secret_key'),
                audience=current_app.config['KEYCLOAK_CLIENT_NAME']
            )
            kwargs.update(user_info)

        except ExpiredSignatureError:
            return _get_unauthorized_response(
                text='Authorization token expired', code=403, json=True)
        except JWTError:
            return _get_unauthorized_response(
                text='Invalid authorization token', json=True)
        return function(*args, **kwargs)
    return wrapper
