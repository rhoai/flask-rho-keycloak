import re
import ast
import sys

from setuptools import setup, find_packages
from setuptools.command.test import test as TestCommand


class PyTest(TestCommand):
    user_options = [
       ('pytest-args=', 'a', 'Arguments to pass to py.test')
    ]

    def initialize_options(self):
        TestCommand.initialize_options(self)
        self.pytest_args = []

    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        import coverage
        import pytest

        if self.pytest_args and len(self.pytest_args) > 0:
            self.test_args.extend(self.pytest_args.strip().split(' '))
            self.test_args.append('tests/')

        cov = coverage.Coverage()
        cov.start()
        errno = pytest.main(self.test_args)
        cov.stop()
        cov.report()
        cov.html_report()
        print('Wrote coverage report to htmlcov directory')
        sys.exit(errno)


_version_re = re.compile(r'__version__\s+=\s+(.*)')

with open('flask_rho_keycloak/__init__.py', 'rb') as f:
    __version__ = str(ast.literal_eval(_version_re.search(
        f.read().decode('utf-8')).group(1)))

setup(
    name='flask-rho-keycloak',
    version=__version__,
    description='Library that provides integration with KeyCloak',
    long_description=open('README.md', 'r').read(),
    maintainer='RhoAI',
    license='',
    url='',
    packages=find_packages(exclude=['tests']),
    include_package_data=True,
    install_requires=[
        'requests >= 2.18.4',
        'python-jose==1.4.0',
        'Flask==0.12.2'
    ],
    tests_require=[
        'pytest >= 2.7.1',
        'coverage >= 4.0a5',
        'mock==1.0.1',
        'httmock==1.2.6'
    ],
    cmdclass={'test': PyTest}
)