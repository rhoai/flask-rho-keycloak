import pytest

from mock import patch
from httmock import response
from flask_rho_keycloak.admin import KeyCloakAdminManager
from flask_rho_keycloak.exceptions import KeyCloakError
from .fixtures.mocks import MockConnectionManager, MockKeyCloakAuthManager


class TestAdminGetUers:

    class ConnManager(MockConnectionManager):

        ret_val = [
            {
                'username': 'user1',
                'email': 'user1@fake.com',
                'firstName': 'test',
                'lastName': 'user'
            },
            {
                'username': 'user2',
                'email': 'user2@fake.com',
                'firstName': 'test',
                'lastName': 'user'
            }
        ]

    def test_get_users(self, app):

        class ConnManager(self.ConnManager):

            def get(self, path, params=None, request_headers=None):

                headers = {'content-type': 'application/json'}
                return response(200, self.ret_val, headers, None, 5)

        with patch('flask_rho_keycloak.admin.ConnectionManager', ConnManager),\
                patch('flask_rho_keycloak.admin.KeyCloakAuthManager',
                      MockKeyCloakAuthManager):

            auth = KeyCloakAdminManager()
            users = auth.get_users()

        assert users == ConnManager.ret_val

    def test_get_users_limit(self, app):

        class ConnManager(self.ConnManager):

            def get(self, path, params=None, request_headers=None):

                headers = {'content-type': 'application/json'}
                return response(200, self.ret_val[:params['max']],
                                headers, None, 5)

        with patch('flask_rho_keycloak.admin.ConnectionManager', ConnManager),\
                patch('flask_rho_keycloak.admin.KeyCloakAuthManager',
                      MockKeyCloakAuthManager):

            auth = KeyCloakAdminManager()
            users = auth.get_users(limit=1)

        assert users == [ConnManager.ret_val[0]]

    def test_get_users_offset(self, app):

        class ConnManager(self.ConnManager):

            def get(self, path, params=None, request_headers=None):

                headers = {'content-type': 'application/json'}
                return response(200, self.ret_val[params['first']:],
                                headers, None, 5)

        with patch('flask_rho_keycloak.admin.ConnectionManager', ConnManager),\
                patch('flask_rho_keycloak.admin.KeyCloakAuthManager',
                      MockKeyCloakAuthManager):

            auth = KeyCloakAdminManager()
            users = auth.get_users(offset=1)
            
        assert users == [ConnManager.ret_val[1]]

    def test_get_users_email(self, app):

        class ConnManager(self.ConnManager):

            def get(self, path, params=None, request_headers=None):

                headers = {'content-type': 'application/json'}
                return response(200,
                                [v for v in self.ret_val
                                 if v['email'] == params['email']],
                                headers, None, 5)

        with patch('flask_rho_keycloak.admin.ConnectionManager', ConnManager),\
                patch('flask_rho_keycloak.admin.KeyCloakAuthManager',
                      MockKeyCloakAuthManager):

            auth = KeyCloakAdminManager()
            users = auth.get_users(email='user2@fake.com')
            
        assert users == [ConnManager.ret_val[1]]

    def test_get_users_count(self, app):

        class ConnManager(self.ConnManager):

            def get(self, path, params=None, request_headers=None):

                headers = {'content-type': 'application/json'}
                return response(200, str(len(self.ret_val)),
                                headers, None, 5)

        with patch('flask_rho_keycloak.admin.ConnectionManager', ConnManager),\
                patch('flask_rho_keycloak.admin.KeyCloakAuthManager',
                      MockKeyCloakAuthManager):

            auth = KeyCloakAdminManager()
            count = auth.get_user_count()
    
        assert count == len(ConnManager.ret_val)


class TestAdminUserAPI:

    def test_get_user(self, app):

        class ConnManager(MockConnectionManager):

            def get(self, path, params=None, request_headers=None):

                headers = {'content-type': 'application/json'}
                user = {
                    'id': '123456',
                    'username': 'user@fake.com',
                    'email': 'user@fake.com',
                    'firstName': 'test',
                    'lastName': 'user',
                    'enabled': True
                }
                return response(200, user, headers, None, 5)

        with patch('flask_rho_keycloak.admin.ConnectionManager', ConnManager),\
                patch.object(KeyCloakAdminManager, 'get_role_mappings',
                             return_value=['zm-api']),\
                patch('flask_rho_keycloak.admin.KeyCloakAuthManager',
                      MockKeyCloakAuthManager):

            auth = KeyCloakAdminManager()
            user = auth.get_user('123456')

        expected = {
            'id': '123456',
            'username': 'user@fake.com',
            'email': 'user@fake.com',
            'full_name': 'test user',
            'given_name': 'test',
            'surname': 'user',
            'active': True,
            'roles': ['zm-api']
        }
        assert user == expected

    def test_get_role_mappings(self, app):

        class ConnManager(MockConnectionManager):

            def get(self, path, params=None, request_headers=None):

                headers = {'content-type': 'application/json'}
                return response(200, ['zm-api'], headers, None, 5)

        with patch('flask_rho_keycloak.admin.ConnectionManager', ConnManager),\
                patch('flask_rho_keycloak.admin.KeyCloakAuthManager',
                      MockKeyCloakAuthManager):

            auth = KeyCloakAdminManager()
            roles = auth.get_role_mappings('123456')

        assert roles == ['zm-api']

    def test_add_user(self, app):

        class ConnManager(MockConnectionManager):

            user_id = '8d80d8e1-ffca-4d2e-b755-05f72be1321f'

            def post(self, path, data=None, json=None, request_headers=None):

                headers = {
                    'content-type': 'application/json',
                    'location': 'admin/realms/test-realm/users/{0}'
                    .format(self.user_id)
                }
                return response(204, None, headers, None, 5)

        with patch('flask_rho_keycloak.admin.ConnectionManager', ConnManager),\
                patch('flask_rho_keycloak.admin.KeyCloakAuthManager',
                      MockKeyCloakAuthManager),\
                patch.object(KeyCloakAdminManager, 'add_group_user'),\
                patch.object(KeyCloakAdminManager, 'add_role_mappings'),\
                patch.object(KeyCloakAdminManager, 'check_new_user',
                             return_value=[]):

            auth = KeyCloakAdminManager()
            user_id = auth.add_user(username='user@fake.com',
                                    password='password',
                                    first_name='test',
                                    last_name='user',
                                    roles=['zm-api-user'])

        assert user_id == ConnManager.user_id

    def test_add_existing_realm_user(self, app):

        class ConnManager(MockConnectionManager):

            user_id = '8d80d8e1-ffca-4d2e-b755-05f72be1321f'

            def post(self, path, data=None, json=None, request_headers=None):

                headers = {
                    'content-type': 'application/json',
                    'location': 'admin/realms/test-realm/users/{0}'
                    .format(self.user_id)
                }
                return response(204, None, headers, None, 5)

        user_data = [{
            'username': 'user@fake.com',
            'email': 'user@fake.com',
            'firstName': 'user',
            'lastName': 'test',
            'id': ConnManager.user_id
        }]

        with patch('flask_rho_keycloak.admin.ConnectionManager', ConnManager),\
                patch('flask_rho_keycloak.admin.KeyCloakAuthManager',
                      MockKeyCloakAuthManager),\
                patch.object(KeyCloakAdminManager, 'add_group_user'),\
                patch.object(KeyCloakAdminManager, 'add_role_mappings'),\
                patch.object(KeyCloakAdminManager, 'check_new_user',
                             return_value=user_data):

            auth = KeyCloakAdminManager()
            user_id = auth.add_user(username='user@fake.com',
                                    password='password',
                                    first_name='test',
                                    last_name='user',
                                    roles=['zm-api-user'])

        assert user_id == ConnManager.user_id

    def test_check_new_user(self, app):

        class ConnManager(MockConnectionManager):

            user_data = [{
                'username': 'user@fake.com',
                'email': 'user@fake.com',
                'firstName': 'user',
                'lastName': 'test',
                'id': '8d80d8e1-ffca-4d2e-b755-05f72be1321f'
            }]

            def get(self, path, params=None, request_headers=None):

                headers = {'content-type': 'application/json'}
                return response(200, self.user_data, headers, None, 5)

        with patch('flask_rho_keycloak.admin.ConnectionManager', ConnManager),\
                patch('flask_rho_keycloak.admin.KeyCloakAuthManager',
                      MockKeyCloakAuthManager):

            auth = KeyCloakAdminManager()
            users = auth.check_new_user('user@fake.com')

        assert users == ConnManager.user_data

    def test_add_group_user(self, app):

        class ConnManager(MockConnectionManager):

            def post(self, path, data=None, json=None, request_headers=None):

                headers = {'content-type': 'application/json'}
                return response(204, None, headers, None, 5)

        with patch('flask_rho_keycloak.admin.ConnectionManager', ConnManager),\
                patch('flask_rho_keycloak.admin.KeyCloakAuthManager',
                      MockKeyCloakAuthManager):

            auth = KeyCloakAdminManager()
            auth.add_group_user(app.config['KEYCLOAK_CLIENT_NAME'], '123456')

    def test_add_role_mappings(self, app):

        roles = {
            '123456': {
                'id': '123456',
                'name': 'zm-api-user',
                'containerId': 'zm-api'
            }
        }

        class ConnManager(MockConnectionManager):

            def post(self, path, data=None, json=None, request_headers=None):

                headers = {'content-type': 'application/json'}
                return response(204, None, headers, None, 5)

        with patch('flask_rho_keycloak.admin.ConnectionManager', ConnManager),\
                patch('flask_rho_keycloak.admin.KeyCloakAuthManager',
                      MockKeyCloakAuthManager),\
                patch.object(KeyCloakAdminManager, 'get_roles',
                             return_value=roles):

            auth = KeyCloakAdminManager()
            auth.add_role_mappings('23456', ['zm-api-user'])

    def test_get_roles(self, app):

        class ConnManager(MockConnectionManager):

            roles = [
                {
                    'id': '654321',
                    'name': 'zm-api-primary',
                    'containerId': 'zm-api'
                },
                {
                    'id': '754321',
                    'name': 'zm-api-secondary',
                    'containerId': 'zm-api'
                },
                {
                    'id': '000001',
                    'name': 'uma_authorization',
                    'containerId': 'zm-api'
                }
            ]

            def get(self, path, params=None, request_headers=None):

                headers = {'content-type': 'application/json'}
                return response(200, self.roles, headers, None, 5)

        with patch('flask_rho_keycloak.admin.ConnectionManager', ConnManager),\
                patch('flask_rho_keycloak.admin.KeyCloakAuthManager',
                      MockKeyCloakAuthManager):

            auth = KeyCloakAdminManager()
            roles = auth.get_roles()

        expected = {
            '654321': {
                'id': '654321',
                'name': 'zm-api-primary',
                'containerId': '123456'
            },
            '754321': {
                'id': '754321',
                'name': 'zm-api-secondary',
                'containerId': '123456'
            }
        }
        assert roles == expected

    def test_update_user(self, app):

        role_mappings = [
            {
                'id': '13579',
                'name': 'zm-api-user-primary',
                'containerId': '123456'
            },
            {
                'id': '13580',
                'name': 'zm-api-user-secondary',
                'containerId': '123456'
            }
        ]

        class ConnManager(MockConnectionManager):

            user_data = {
                'username': 'user@fake.com',
                'email': 'user@fake.com',
                'firstName': 'test',
                'lastName': 'user',
                'enabled': True,
                'credentials': [{
                    'type': 'password',
                    'value': 'password',
                    'temporary': False
                }]
            }

            def put(self, path, data=None, json=None, request_headers=None):

                assert json == self.user_data
                return response(204, None, None, None, 5)

        with patch('flask_rho_keycloak.admin.ConnectionManager', ConnManager),\
                patch('flask_rho_keycloak.admin.KeyCloakAuthManager',
                      MockKeyCloakAuthManager),\
                patch.object(KeyCloakAdminManager, 'get_role_mappings',
                             return_value=role_mappings),\
                patch.object(KeyCloakAdminManager, 'remove_role_mappings',
                             return_value=None),\
                patch.object(KeyCloakAdminManager, 'add_role_mappings',
                             return_value=None):

            user_data = {
                'id': '123456',
                'username': 'user@fake.com',
                'password': 'password',
                'given_name': 'test',
                'surname': 'user',
                'active': True
            }

            auth = KeyCloakAdminManager()
            user_id = auth.update_user(user_data)
            assert user_id == user_data['id']

            user_id = auth.update_user(user_data, ['13579'])
            assert user_id == user_data['id']

    def test_remove_role_mappings(self, app):

        class ConnManager(MockConnectionManager):

            roles = {
                '13579': {
                    'id': '13579',
                    'name': 'zm-api-user',
                    'containerId': '345678'
                }
            }

            def delete(self, path, json=None, request_headers=None):

                assert json == self.roles.values()
                return response(204, None, None, None, 5)

        with patch('flask_rho_keycloak.admin.ConnectionManager', ConnManager),\
                patch('flask_rho_keycloak.admin.KeyCloakAuthManager',
                      MockKeyCloakAuthManager),\
                patch.object(KeyCloakAdminManager, 'get_roles',
                             return_value=ConnManager.roles):

            auth = KeyCloakAdminManager()
            auth.remove_role_mappings('123456', {'13579'})

    def test_add_custom_user_attributes(self, app):

        class ConnManager(MockConnectionManager):

            user_data = {
                'id': '123456',
                'attributes': {
                    'reset_code': '13579',
                    'reset_code_expires': '000000000'
                }
            }

            def put(self, path, data=None, json=None, request_headers=None):

                assert json == self.user_data
                return response(204, None, None, None, 5)

        with patch('flask_rho_keycloak.admin.ConnectionManager', ConnManager),\
                patch('flask_rho_keycloak.admin.KeyCloakAuthManager',
                      MockKeyCloakAuthManager):

            attributes = {
                'reset_code': '13579',
                'reset_code_expires': '000000000'
            }

            auth = KeyCloakAdminManager()
            auth.add_custom_user_attributes('123456', attributes)

    def test_delete_user(self, app):

        class ConnManager(MockConnectionManager):

            def delete(self, path, json=None, request_headers=None):

                return response(204, None, None, None, 5)

        with patch('flask_rho_keycloak.admin.ConnectionManager', ConnManager),\
                patch('flask_rho_keycloak.admin.KeyCloakAuthManager',
                      MockKeyCloakAuthManager):

            auth = KeyCloakAdminManager()
            auth.delete_user('123456')

    def test_update_password(self, app):

        class ConnManager(MockConnectionManager):

            credentials = {
                'type': 'password',
                'value': 'password',
                'temporary': False
            }

            def put(self, path, data=None, json=None, request_headers=None):

                assert json == self.credentials
                return response(204, None, None, None, 5)

        with patch('flask_rho_keycloak.admin.ConnectionManager', ConnManager),\
                patch('flask_rho_keycloak.admin.KeyCloakAuthManager',
                      MockKeyCloakAuthManager):

            auth = KeyCloakAdminManager()
            auth.update_password('123456', 'password')

    def test_get_reset_password_code(self, app):

        class ConnManager(MockConnectionManager):

            code = {
                'code': '13579'
            }

            def get(self, path, params=None, request_headers=None):

                assert 'user_id' in params

                headers = {'content-type': 'application/json'}
                return response(200, self.code, headers, None, 5)

        with patch('flask_rho_keycloak.admin.ConnectionManager', ConnManager),\
                patch('flask_rho_keycloak.admin.KeyCloakAuthManager',
                      MockKeyCloakAuthManager):

            auth = KeyCloakAdminManager()
            code = auth.get_reset_password_code('123456')

            assert code == ConnManager.code

    def test_validate_reset_password_code(self, app):

        class ConnManager(MockConnectionManager):

            user_data = {
                'id': '123456',
                'username': 'user@fake.com',
                'password': 'password',
                'given_name': 'test',
                'surname': 'user',
                'active': True
            }

            def get(self, path, params=None, request_headers=None):

                assert 'code' in params

                headers = {'content-type': 'application/json'}
                return response(200, {'userInfo': self.user_data},
                                headers, None, 5)

        with patch('flask_rho_keycloak.admin.ConnectionManager', ConnManager),\
                patch('flask_rho_keycloak.admin.KeyCloakAuthManager',
                      MockKeyCloakAuthManager):

            auth = KeyCloakAdminManager()
            user = auth.validate_reset_password_code('13579')

            assert user == ConnManager.user_data

    def test_validate_reset_password_code_invalid(self, app):

        class ConnManager(MockConnectionManager):

             def get(self, path, params=None, request_headers=None):

                assert 'code' in params

                headers = {'content-type': 'application/json'}
                return response(200, {}, headers, None, 5)

        with patch('flask_rho_keycloak.admin.ConnectionManager', ConnManager),\
                patch('flask_rho_keycloak.admin.KeyCloakAuthManager',
                      MockKeyCloakAuthManager):

            auth = KeyCloakAdminManager()
            user = auth.validate_reset_password_code('13579')

            assert user == {}

    def test_validate_mobile_reset_password_code(self, app):

        class ConnManager(MockConnectionManager):

            user_data = {
                'id': '123456',
                'username': 'user@fake.com',
                'password': 'password',
                'given_name': 'test',
                'surname': 'user',
                'active': True
            }

            def get(self, path, params=None, request_headers=None):

                assert 'code' in params

                headers = {'content-type': 'application/json'}
                return response(200, {'userInfo': self.user_data},
                                headers, None, 5)

        with patch('flask_rho_keycloak.admin.ConnectionManager', ConnManager),\
                patch('flask_rho_keycloak.admin.KeyCloakAuthManager',
                      MockKeyCloakAuthManager):

            auth = KeyCloakAdminManager()
            user = auth.validate_mobile_reset_password_code('13579')

            assert user == ConnManager.user_data

    def test_validate_mobile_reset_password_code_invalid(self, app):

        class ConnManager(MockConnectionManager):

             def get(self, path, params=None, request_headers=None):

                assert 'code' in params

                headers = {'content-type': 'application/json'}
                return response(200, {}, headers, None, 5)

        with patch('flask_rho_keycloak.admin.ConnectionManager', ConnManager),\
                patch('flask_rho_keycloak.admin.KeyCloakAuthManager',
                      MockKeyCloakAuthManager):

            auth = KeyCloakAdminManager()
            user = auth.validate_mobile_reset_password_code('13579')

            assert user == {}


