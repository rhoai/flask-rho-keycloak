from flask import current_app
from werkzeug.local import LocalProxy
from jose import jwt, JWTError


_keycloak = LocalProxy(lambda: current_app.extensions['keycloak'])
_cache = LocalProxy(lambda: _keycloak.cache)


def custom_jwt_validation(token, leeway=0, exclude=None):
    """ perform custom jwt validation

        leeway number of seconds of skew that is allowed
        exclude is a list of claims to exclude from validation.
        jose jwt defaults to:

            defaults = {
                'verify_signature': True,
                'verify_aud': True,
                'verify_iat': True,
                'verify_exp': True,
                'verify_nbf': True,
                'verify_iss': True,
                'verify_sub': True,
                'verify_jti': True,
                'leeway': 0,
            }
    """

    options = {}
    exclude = exclude or []
    for key in exclude:
        options[key] = False

    if leeway != 0:
        options['leeway'] = leeway

    try:
        jwt.decode(
            token,
            _cache.get('keycloak_secret_key'),
            options=options,
            audience=current_app.config['KEYCLOAK_CLIENT_NAME']
        )
        return True
    except JWTError:
        raise
        return False
