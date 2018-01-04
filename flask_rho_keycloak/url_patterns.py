# URL patterns used by flask-keycloak

# open id urls
URL_CERTS = 'realms/{realm-name}/protocol/openid-connect/certs'
URL_TOKEN = 'realms/{realm-name}/protocol/openid-connect/token'
URL_LOGOUT = 'realms/{realm-name}/protocol/openid-connect/logout'
URL_ENTITLEMENT = 'realms/{realm-name}/authz/entitlement/{client-name}'


# admin urls
URL_ADMIN_USERS = 'admin/realms/{realm-name}/users'
URL_ADMIN_USER = 'admin/realms/{realm-name}/users/{user-id}'
URL_ADMIN_ROLES = 'admin/realms/{realm-name}/clients/{client-id}/roles'
URL_ADMIN_ROLE_MAPPINGS = 'admin/realms/{realm-name}/users/{user-id}/role-mappings/clients/{client-id}'
URL_ADMIN_RESET_PASSWORD = 'admin/realms/{realm-name}/users/{user-id}/reset-password'

# custom admin
URL_GROUP_USERS = 'realms/{realm-name}/group-users/groups/{group-name}'
URL_GROUP_USERS_COUNT = 'realms/{realm-name}/group-users/groups/{group-name}/count'
URL_GROUP_USER_ADD = 'realms/{realm-name}/group-users/groups/{group-name}/user/{user-id}'
URL_RESET_PASSWORD_CODE = 'realms/{realm-name}/reset-password-code/clients/{client-name}'
URL_VALIDATE_RESET_PASSWORD_CODE = 'realms/{realm-name}/reset-password-code/clients/{client-name}/validate'
#URL_VALIDATE_RESET_MOBILE_PASSWORD_CODE = 'realms/{realm-name}/reset-password-code/clients/{client-name}/validate-mobile'
URL_VALIDATE_AUTH_CODE = 'realms/{realm-name}/auth-code/code/validate'
URL_SAFE_CUSTOM_ATTRIBUTES = 'realms/{realm-name}/safe-custom-attributes/users/{user-id}'
URL_SAFE_CUSTOM_ATTRIBUTES_SEARCH = 'realms/{realm-name}/safe-custom-attributes/users/search'