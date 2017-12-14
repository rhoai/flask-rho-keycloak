from flask import current_app

import url_patterns
from .openid import KeyCloakAuthManager
from .connection import ConnectionManager
from .exceptions import raise_error_from_response


class KeyCloakAdminManager(object):

    def __init__(self, admin_client_name=None, admin_client_secret=None):

        client_name = admin_client_name or\
            current_app.config['KEYCLOAK_ADMIN_ACCOUNT']
        client_secret = admin_client_secret or\
            current_app.config['KEYCLOAK_ADMIN_SECRET']

        auth = KeyCloakAuthManager(client_name, client_secret)
        access_token_data = auth.get_access_token('client_credentials')
        self.access_token = access_token_data['access_token']
        self.refresh_token = access_token_data['refresh_token']

        conn = ConnectionManager(current_app.config['KEYCLOAK_HOST'])
        self._connection = conn

        self.admin_headers = {
            'authorization': 'Bearer {}'.format(self.access_token)
        }

    def get_users(self, limit=None, offset=None, email=None):

        path_params = {
            'realm-name': current_app.config['KEYCLOAK_REALM'],
            'group-name': current_app.config['KEYCLOAK_CLIENT_NAME']
        }

        params = {}
        if limit is not None:
            params['max'] = limit
        if offset is not None:
            params['first'] = offset
        if email is not None:
            params['email'] = email

        response = self._connection.get(
            url_patterns.URL_GROUP_USERS.format(**path_params),
            params=params, request_headers=self.admin_headers)

        message = 'Error while loading users'
        return raise_error_from_response(response, message)

    def get_user_count(self):

        path_params = {
            'realm-name': current_app.config['KEYCLOAK_REALM'],
            'group-name': current_app.config['KEYCLOAK_CLIENT_NAME']
        }

        response = self._connection.get(
            url_patterns.URL_GROUP_USERS_COUNT.format(**path_params),
            request_headers=self.admin_headers
        )

        message = 'Error while loading users'
        return raise_error_from_response(response, message)

    def check_new_user(self, username):
        """ check if user already exists in realm"""
        path_params = {
            'realm-name': current_app.config['KEYCLOAK_REALM']
        }

        qs = {
            'username': username
        }
        response = self._connection.get(
            url_patterns.URL_ADMIN_USERS.format(**path_params),
            params=qs, request_headers=self.admin_headers
        )

        message = 'Error while loading users'
        return raise_error_from_response(response, message)

    def get_user(self, user_id):
        """ get a user by id """

        path_params = {
            'realm-name': current_app.config['KEYCLOAK_REALM'],
            'user-id': user_id
        }

        response = self._connection.get(
            url_patterns.URL_ADMIN_USER.format(**path_params),
            request_headers=self.admin_headers)

        message = 'Error while loading user {}'.format(user_id)
        raw = raise_error_from_response(response, message)

        return {
            'id': raw['id'],
            'username': raw['username'],
            'email': raw['email'],
            'full_name': '{} {}'.format(raw['firstName'], raw['lastName']),
            'given_name': raw['firstName'],
            'surname': raw['lastName'],
            'active': raw['enabled'],
            'roles': self.get_role_mappings(user_id)
        }

    def get_role_mappings(self, user_id):

        path_params = {
            'realm-name': current_app.config['KEYCLOAK_REALM'],
            'user-id': user_id,
            'client-id': current_app.config['KEYCLOAK_CLIENT_ID']
        }

        response = self._connection.get(
            url_patterns.URL_ADMIN_ROLE_MAPPINGS.format(**path_params),
            request_headers=self.admin_headers)

        message = 'Error while retrieving role mappings'
        return raise_error_from_response(response, message)

    def add_user(self, username, password, first_name=None,
                 last_name=None, enabled=True, roles=None):

        path_params = {'realm-name': current_app.config['KEYCLOAK_REALM']}
        user_id = None

        # check if user already exists in realm
        users = self.check_new_user(username)
        if len(users) > 0:
            user = users[0]
            user_id = user['id']

        else:
            credentials = [{
                'type': 'password',
                'value': password,
                'temporary': False
            }]

            user = {
                'email': username,
                'enabled': enabled,
                'username': username,
                'firstName': first_name,
                'lastName': last_name,
                'credentials': credentials
            }
            response = self._connection.post(
                url_patterns.URL_ADMIN_USERS.format(**path_params),
                json=user, request_headers=self.admin_headers)

            message = 'Error while creating user'
            raise_error_from_response(response, message)
            user_id = response.headers['location'][-36:]
        
        self.add_group_user(
            current_app.config['KEYCLOAK_CLIENT_NAME'], user_id)

        if roles:
            self.add_role_mappings(user_id, roles)
        return user_id

    def add_group_user(self, group_name, user_id):
        """ Add a user to a group """

        path_params = {
            'realm-name': current_app.config['KEYCLOAK_REALM'],
            'group-name': group_name,
            'user-id': user_id
        }
        response = self._connection.post(
            url_patterns.URL_GROUP_USER_ADD.format(**path_params),
            request_headers=self.admin_headers)

        message = 'Error while adding user to group'
        return raise_error_from_response(response, message)

    def add_role_mappings(self, user_id, roles):
        """ Add a user to roles """

        path_params = {
            'realm-name': current_app.config['KEYCLOAK_REALM'],
            'user-id': user_id,
            'client-id': current_app.config['KEYCLOAK_CLIENT_ID']
        }

        client_roles = self.get_roles()

        rls = []
        for role in roles:
            rls.append(client_roles.get(role))

        response = self._connection.post(
            url_patterns.URL_ADMIN_ROLE_MAPPINGS.format(**path_params),
            json=rls, request_headers=self.admin_headers
        )

        message = 'Error adding user to role'
        return raise_error_from_response(response, message)

    def get_roles(self):

        path_params = {
            'realm-name': current_app.config['KEYCLOAK_REALM'],
            'client-id': current_app.config['KEYCLOAK_CLIENT_ID']
        }

        response = self._connection.get(
            url_patterns.URL_ADMIN_ROLES.format(**path_params),
            request_headers=self.admin_headers)

        message = 'Error while loading groups'
        raw = raise_error_from_response(response, message)

        roles = {}
        for role in raw:
            if role['name'].startswith('uma'):
                continue
            roles[role['id']] = {
                'id': role['id'],
                'name': role['name'],
                'containerId': current_app.config['KEYCLOAK_CLIENT_ID']
            }
        return roles

    def update_user(self, user_data, roles=None):

        user = {}
        if 'username' in user_data:
            user['username'] = user_data['username']
            user['email'] = user_data['username']

        if 'password' in user_data:
            user['credentials'] = [{
                'type': 'password',
                'value': user_data['password'],
                'temporary': False
            }]

        if 'given_name' in user_data:
            user['firstName'] = user_data['given_name']

        if 'surname' in user_data:
            user['lastName'] = user_data['surname']

        if 'active' in user_data:
            user['enabled'] = user_data['active']

        path_params = {
            'realm-name': current_app.config['KEYCLOAK_REALM'],
            'user-id': user_data['id']
        }
        response = self._connection.put(
            url_patterns.URL_ADMIN_USER.format(**path_params),
            json=user, request_headers=self.admin_headers)

        message = 'Error while updating user'
        raise_error_from_response(response, message)

        if not roles:
            return user_data['id']

        # update roles
        current_roles = self.get_role_mappings(user_data['id'])
        set_current_roles = set(role['id'] for role in current_roles)
        set_new_roles = set(roles)

        # remove roles
        to_remove = set_current_roles.difference(set_new_roles)
        self.remove_role_mappings(user_data['id'], to_remove)

        # add new roles
        to_add = set_new_roles.difference(set_current_roles)
        #self.add_role_mappings(user_data['id'], to_add)
        return user_data['id']

    def remove_role_mappings(self, user_id, roles):

        path_params = {
            'realm-name': current_app.config['KEYCLOAK_REALM'],
            'user-id': user_id,
            'client-id': current_app.config['KEYCLOAK_CLIENT_ID']
        }

        client_roles = self.get_roles()

        rls = []
        for role in roles:
            rls.append(client_roles[role])

        response = self._connection.delete(
            url_patterns.URL_ADMIN_ROLE_MAPPINGS.format(**path_params),
            json=rls, request_headers=self.admin_headers)

        message = 'Error while removing roles from user'
        return raise_error_from_response(response, message)

    def add_custom_user_attributes(self, user_id, attributes):

        path_params = {
            'realm-name': current_app.config['KEYCLOAK_REALM'],
            'user-id': user_id
        }

        data = {
            'attributes': attributes,
            'id': user_id
        }

        response = self._connection.put(
            url_patterns.URL_ADMIN_USER.format(**path_params),
            json=data, request_headers=self.admin_headers)

        message = 'Error while updating custom user attributes'
        raise_error_from_response(response, message)

    def delete_user(self, user_id):

        path_params = {
            'realm-name': current_app.config['KEYCLOAK_REALM'],
            'user-id': user_id
        }

        response = self._connection.delete(
            url_patterns.URL_ADMIN_USER.format(**path_params),
            request_headers=self.admin_headers)

        message = 'Error while deleting user'
        raise_error_from_response(response, message)

    def update_password(self, user_id, password):

        path_params = {
            'realm-name': current_app.config['KEYCLOAK_REALM'],
            'user-id': user_id
        }

        credentials = {
            'type': 'password',
            'value': password,
            'temporary': False
        }

        response = self._connection.put(
            url_patterns.URL_ADMIN_RESET_PASSWORD.format(**path_params),
            json=credentials, request_headers=self.admin_headers)

        message = 'Error while updating password'
        return raise_error_from_response(response, message)

    def get_reset_password_code(self, user_id):

        path_params = {
            'realm-name': current_app.config['KEYCLOAK_REALM'],
            'client-name': current_app.config['KEYCLOAK_CLIENT_NAME']
        }

        params = {
            'user_id': user_id
        }

        response = self._connection.get(
            url_patterns.URL_RESET_PASSWORD_CODE.format(**path_params),
            params=params, request_headers=self.admin_headers)

        message = 'Error retrieving reset password code'
        return raise_error_from_response(response, message)

    def validate_reset_password_code(self, code):

        path_params = {
            'realm-name': current_app.config['KEYCLOAK_REALM'],
            'client-name': current_app.config['KEYCLOAK_CLIENT_NAME']
        }

        params = {
            'code': code
        }

        url =  url_patterns.URL_VALIDATE_RESET_PASSWORD_CODE\
            .format(**path_params)
        response = self._connection.get(url, params=params,
                                        request_headers=self.admin_headers)

        message = 'Error while validating reset password code'
        raw = raise_error_from_response(response, message)
        return raw.get('userInfo', {})

    def validate_mobile_reset_password_code(self, code):

        path_params = {
            'realm-name': current_app.config['KEYCLOAK_REALM'],
            'client-name': current_app.config['KEYCLOAK_CLIENT_NAME']
        }

        params = {
            'code': code
        }

        url = url_patterns.URL_VALIDATE_RESET_MOBILE_PASSWORD_CODE\
            .format(**path_params)
        response = self._connection.get(url, params=params,
                                        request_headers=self.admin_headers)

        message = 'Error while validating mobile reset password code'
        raw = raise_error_from_response(response, message)
        return raw.get('userInfo', {})
