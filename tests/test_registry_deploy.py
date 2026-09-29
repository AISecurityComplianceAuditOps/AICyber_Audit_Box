# -*- coding: utf-8 -*-
"""The Artifact Registry deployment (docker-compose.registry.yml and
setup_registry.sh) is the offline stack with registry images -- nothing else.

    pytest tests/test_registry_deploy.py -v

Written for a customer install from the registry. The guide it replaces pulled registry images but
started docker-compose.customer.yml, which names local images, so
`up --no-build` found none; and it relied on ufw to keep the database and Redis
ports closed, which Docker's own firewall rules bypass.
"""
import os

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load(name):
    with open(os.path.join(ROOT, name), encoding="utf-8") as fh:
        return yaml.safe_load(fh)


REG = _load("docker-compose.registry.yml")
OFF = _load("docker-compose.customer.yml")


def test_the_registry_stack_is_the_offline_stack():
    assert set(REG["services"]) == set(OFF["services"])
    for name, off in OFF["services"].items():
        reg = REG["services"][name]
        for key in ("container_name", "command", "network_mode", "depends_on", "volumes",
                    "healthcheck", "restart"):
            assert reg.get(key) == off.get(key), (name, key)
        assert sorted(reg.get("environment") or []) == sorted(off.get("environment") or []), name
    assert REG["volumes"] == OFF["volumes"]


def test_the_images_come_from_the_registry_with_versions_from_env():
    for name, svc in REG["services"].items():
        if name == "redis":
            assert svc["image"] == OFF["services"]["redis"]["image"]
            continue
        assert svc["image"].startswith("${AICB_REGISTRY:-asia-south1-docker.pkg.dev/"), svc["image"]
        assert "_VERSION:-" in svc["image"], svc["image"]


def test_only_port_8000_is_open_to_the_network():
    for name, svc in REG["services"].items():
        for p in svc.get("ports") or []:
            assert p == "8000:8000" or str(p).startswith("127.0.0.1:"), (name, p)
    assert not REG["services"]["redis"].get("ports"), "Redis has no password; it must not be published"


def test_the_setup_script_runs_on_linux_and_protects_the_database_password():
    raw = open(os.path.join(ROOT, "setup_registry.sh"), "rb").read()
    assert b"\r" not in raw, "CRLF line endings break the script on Linux"
    assert raw.startswith(b"#!/bin/sh\n")
    text = raw.decode("utf-8")
    assert "--password-stdin" in text and "_json_key" in text      # the key is never on a command line
    assert '_pgdata$' in text, "a new password must never be written over an existing database"
    assert "docker-compose.registry.yml" in text
