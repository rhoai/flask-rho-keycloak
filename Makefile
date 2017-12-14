# Standard Usage, full suite:
# make test
#
# Single tests:
# make test ARG="-k test_method"
#
# Anything in ARG is passed to pytest

ENV_FILE := .env.test
ENV := $(shell cat ${ENV_FILE})
PYPI_SERVER ?= gemfury

all: clean test

test:
	${ENV} python setup.py test -a "-vv ${ARG}"

clean-pyc:
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '*~' -exec rm -f {} +

clean-test:
	rm -rf *.egg

clean:
	clean-pyc clean-test

build-upload:
	python setup.py register -r ${PYPI_SERVER} sdist upload -r $(PYPI_SERVER)

build:
	python setup.py sdist