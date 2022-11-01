# Targets for local development
install:: utl_activate ci_install
fmt::     install ci_fmt
lint::    fmt ci_lint
test::    fmt ci_lint ci_test

# Targets for CI
ci_install::
	pip3 install -qr dev-requirements.txt

ci_fmt::
	black panther_okta tests

ci_lint::
	mypy --config-file mypy.ini panther_okta

ci_test::
	nosetests -v --with-coverage --cover-package=panther_okta

# Utility targets
venv:
	python3 -m venv venv

utl_activate: venv
	. venv/bin/activate

publish: utl_activate
	rm -rf dist
	python3 setup.py sdist
	twine upload ./dist/panther_okta-*.tar.gz


# Targets for local development
shell::   pipenv shell
install:: ci_install
sync::    ci_sync 
fmt::     ci_fmt
lint::    fmt ci_lint
test::    fmt ci_lint ci_test

.SILENT: git_reset

# Targets for CI
ci_fmt::
	pipenv run black panther_okta tests

ci_lint::
	pipenv run mypy --config-file mypy.ini panther_okta tests

ci_test::
	pipenv run nosetests -v --with-coverage --cover-package=panther_okta

ci_install:
	pipenv install --dev

ci_sync:
	pipenv sync --dev

# Other targets
publish:
	rm -rf dist
	pipenv run python3 setup.py sdist
	pipenv run twine upload ./dist/panther_okta-*.tar.gz