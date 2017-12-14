import pytest

from httmock import urlmatch, response, HTTMock, all_requests
from requests.exceptions import ConnectionError

from flask_rho_keycloak.connection import ConnectionManager
from flask_rho_keycloak.exceptions import KeyCloakError


class TestConnectionManager:

    def setup_class(cls):

        cls._conn = ConnectionManager(base_url='http://localhost/')

    @all_requests
    def response_content_success(self, url, request):
        headers = {'content-type': 'application/json'}
        content = b'response_ok'
        return response(200, content, headers, None, 5, request)

    @all_requests
    def connection_failure(self, url, request):
        raise ConnectionError

    def test_get(self):
        with HTTMock(self.response_content_success):
            resp = self._conn.get('/known_path')

        assert resp.content == b'response_ok'
        assert resp.status_code == 200

    def test_get_fail(self):

       with pytest.raises(KeyCloakError),\
               HTTMock(self.connection_failure):
           resp = self._conn.get('/known_path')

    def test_post(self):

        @urlmatch(path='/known_path', method='post')
        def response_post_success(url, request):
            headers = {'content-type': 'application/json'}
            content = 'response'.encode('utf-8')
            return response(201, content, headers, None, 5, request)

        with HTTMock(response_post_success):
            resp = self._conn.post('/known_path', data={'field': 'value'})

        assert resp.content == b'response'
        assert resp.status_code == 201

    def test_post_fail(self):

        with pytest.raises(KeyCloakError),\
                HTTMock(self.connection_failure):
            resp = self._conn.post('/known_path', data={'field': 'value'})

    def test_put(self):

        @urlmatch(path='/known_path', method='put')
        def response_put_success(url, request):
            headers = {'content-type': 'application/json'}
            content = 'response'.encode('utf-8')
            return response(200, content, headers, None, 5, request)

        with HTTMock(response_put_success):
            resp = self._conn.put('/known_path', data={'field': 'value'})

        assert resp.content == b'response'
        assert resp.status_code == 200

    def test_put_fail(self):

        with pytest.raises(KeyCloakError),\
                HTTMock(self.connection_failure):
            resp = self._conn.put('/known_path', data={'field': 'value'})

    def test_delete(self):

        with HTTMock(self.response_content_success):
            resp = self._conn.delete('/known_path')

        assert resp.content == b'response_ok'
        assert resp.status_code == 200

    def test_delete_fail(self):

        with pytest.raises(KeyCloakError),\
                HTTMock(self.connection_failure):
            resp = self._conn.delete('/known_path')
