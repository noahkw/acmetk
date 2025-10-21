import pytest


@pytest.fixture
def db():
    return "postgresql+asyncpg://acme-broker:acme-broker-debug-pw@localhost:55432/{database}"
