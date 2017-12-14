import json


class TestCheckJWTAuth:

    def test_no_token(self, app):

        client = app.test_client()
        resp = client.get('/secure')
        assert resp.status_code == 401

        expected = {
            'status': 'error',
            'result': 'Not authorized'
        }
        assert json.loads(resp.data) == expected
