"""Shared pytest fixtures.

Every test gets an isolated in-memory store and a deterministic key wrapper, so
the suite never touches the filesystem and never needs ``KEYCHAIN_MASTER_KEY``
from the environment.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from keychain.config import KeyChainConfig  # noqa: E402
from keychain.keys import KeyWrapper  # noqa: E402
from keychain.service import KeyChainService  # noqa: E402
from keychain.store import KeyChainStore  # noqa: E402

TEST_MASTER_KEY = bytes(range(32))
TEST_API_TOKEN = "test-token"


@pytest.fixture
def store():
    with KeyChainStore(":memory:") as opened:
        yield opened


@pytest.fixture
def key_wrapper():
    return KeyWrapper(TEST_MASTER_KEY)


@pytest.fixture
def config():
    return KeyChainConfig(
        db_path=":memory:",
        api_token=TEST_API_TOKEN,
        auto_bootstrap_root=True,
        default_root_name="test-root",
    )


@pytest.fixture
def service(store, key_wrapper, config):
    return KeyChainService(store=store, key_wrapper=key_wrapper, config=config)


@pytest.fixture
def root(service):
    return service.resolve_root()


@pytest.fixture
def client(service):
    from server import create_app

    app = create_app(service=service, config=service.config)
    app.testing = True
    with app.test_client() as test_client:
        yield test_client


@pytest.fixture
def auth_headers():
    return {"Authorization": "Bearer %s" % TEST_API_TOKEN}
