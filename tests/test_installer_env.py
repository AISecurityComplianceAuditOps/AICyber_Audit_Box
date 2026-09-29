# -*- coding: utf-8 -*-
"""The offline installers create the database password before the first start.

    pytest tests/test_installer_env.py -v

docker-compose.customer.yml reads POSTGRES_PASSWORD from .env and stops with
"Set POSTGRES_PASSWORD in .env" when it is missing. install.sh and install.bat
never wrote one, so a from-scratch install of a full bundle stopped at
`docker compose up`. (Updates were never affected: they keep the .env the
installation already has.)

Both installers now write .env once, with a random password, before starting
the stack; keep one that exists; and refuse when .env is gone but the
installation's database volume is not, since a new password would lock the
application out of it.
"""
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(name):
    return open(os.path.join(ROOT, name), encoding="utf-8").read()


def test_install_sh_writes_env_once_before_starting():
    body = _read("install.sh")
    assert "if [ ! -f .env ]; then" in body, "an existing .env must be kept"
    assert "POSTGRES_PASSWORD=%s" in body
    assert body.index("POSTGRES_PASSWORD=%s") < body.index('up -d'), ".env must exist before the first start"
    assert "/dev/urandom" in body


def test_install_bat_writes_env_once_before_starting():
    body = _read("install.bat")
    assert "if exist .env goto :envready" in body, "an existing .env must be kept"
    assert ">.env echo POSTGRES_PASSWORD=!PW!" in body
    assert body.index(">.env echo") < body.index("up -d"), ".env must exist before the first start"
    assert "RandomNumberGenerator" in body


def test_both_refuse_a_new_password_for_an_existing_database():
    assert re.search(r'docker volume inspect "\$\{PROJECT\}_pgdata"', _read("install.sh"))
    assert "docker volume inspect !PROJECT!_pgdata" in _read("install.bat")


def test_the_bat_does_not_leave_the_placeholder_password_set():
    """The placeholder that lets `compose config` name the project must be
    cleared, or it would override .env at `docker compose up`."""
    body = _read("install.bat")
    placeholder = body.index("set POSTGRES_PASSWORD=unset")
    cleared = body.index("set POSTGRES_PASSWORD=\n", placeholder) if "set POSTGRES_PASSWORD=\n" in body \
        else body.index("set POSTGRES_PASSWORD=\r\n", placeholder)
    assert cleared < body.index("up -d")


def test_the_compose_still_requires_the_password():
    assert "${POSTGRES_PASSWORD:?" in _read("docker-compose.customer.yml")
