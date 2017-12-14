import pytest

from flask_rho_keycloak.settings import init_settings, validate_settings
from flask_rho_keycloak.exceptions import ConfigurationError


class TestInitSettings:

    def test_init(self):

        config = {}
        init_settings(config)

        assert config.get('KEYCLOAK_HOST') is None
        assert config.get('KEYCLOAK_REALM') is None
        assert config.get('KEYCLOAK_CLIENT_NAME') is None
        assert config.get('KEYCLOAK_CLIENT_ID') is None
        assert config.get('KEYCLOAK_CLIENT_SECRET') is None

        assert config.get('KEYCLOAK_ADMIN_ACCOUNT') == 'admin-cli'
        assert config.get('KEYCLOAK_ADMIN_SECRET') is None

        assert config.get('API_SIGNING_KEY') == 'secret'


class TestValidateSettings:

    def test_raises_exception_if_invalid_settings(self):

        config = {
            'KEYCLOAK_HOST': None
        }
        with pytest.raises(ConfigurationError) as excinfo:
            validate_settings(config)
            assert 'KEYCLOAK_HOST setting is required.' in str(excinfo)

        config['KEYCLOAK_HOST'] = 'http://localhost:8080'
        config['KEYCLOAK_REALM'] = None
        with pytest.raises(ConfigurationError) as excinfo:
            validate_settings(config)
            assert 'KEYCLOAK_REALM settings is required.' in str(excinfo)

        config['KEYCLOAK_REALM'] = 'rhoai'
        config['KEYCLOAK_CLIENT_NAME'] = None
        with pytest.raises(ConfigurationError) as excinfo:
            validate_settings(config)
            assert 'KEYCLOAK_CLIENT_NAME is required.' in str(excinfo)

        config['KEYCLOAK_CLIENT_NAME'] = 'client'
        config['KEYCLOAK_CLIENT_ID'] = None
        with pytest.raises(ConfigurationError) as excinfo:
            validate_settings(config)
            assert 'KEYCLOAK_CLIENT_ID is required.' in str(excinfo)

        config['KEYCLOAK_CLIENT_ID'] = '12345'
        config['KEYCLOAK_CLIENT_SECRET'] = None
        with pytest.raises(ConfigurationError) as excinfo:
            validate_settings(config)
            assert 'KEYCLOAK_CLIENT_SECRET is required.' in str(excinfo)

        config['KEYCLOAK_CLIENT_SECRET'] = 'client-secret'
        config['KEYCLOAK_ADMIN_SECRET'] = None
        with pytest.raises(ConfigurationError) as excinfo:
            validate_settings(config)
            assert 'KEYCLOAK_ADMIN_SECRET is required.' in str(excinfo)

    def test_valid_settings(self):
        config = {
            'KEYCLOAK_HOST': 'http://localhost:8080',
            'KEYCLOAK_REALM': 'rhoai',
            'KEYCLOAK_CLIENT_NAME': 'client',
            'KEYCLOAK_CLIENT_ID': '123456',
            'KEYCLOAK_CLIENT_SECRET': 'client-secret',
            'KEYCLOAK_ADMIN_SECRET': 'admin-secret'
        }
        validate_settings(config)
        return True
