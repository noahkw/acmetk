from pathlib import Path

import yaml

import pytest


@pytest.fixture
def db():
    doc = yaml.safe_load((Path(__file__).parent / "conf/debug.yml").open("rt"))
    v = doc["tests"]["LocalCA"]["ca"]["db"]
    return v
