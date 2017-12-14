import pytest

from httmock import response

from flask_rho_keycloak.exceptions import KeyCloakError, raise_error_from_response


class TestExceptions:

    def test_no_error_from_response(self):

        headers = {'content-type': 'application/json'}
        content = b'response_ok'

        resp = response(200, content, headers, None, 5)
        result = raise_error_from_response(resp, '')

        assert result == b'response_ok'

    def test_raises_error_from_response(self):

        headers = {'content-type': 'application/json'}
        content = b'request_failed'

        resp = response(404, content, headers, 'Not found', 5)

        message = 'error'
        with pytest.raises(KeyCloakError) as excinfo:
            resp = raise_error_from_response(resp, message)

        assert excinfo.value.message == 'error 404 Not found'
        assert excinfo.value.response_code == 404

    def test_raises_connection_error_from_response(self):

        headers = {'content-type': 'application/json'}
        content = b'Unable to connect to server'

        resp = response(503, content, headers, 'Unavailable', 5)

        message = 'error'
        with pytest.raises(KeyCloakError) as excinfo:
            resp = raise_error_from_response(resp, message)

        assert excinfo.value.message == 'error 503 Unavailable'
        assert excinfo.value.response_code == 503
