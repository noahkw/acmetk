from pathlib import Path
import yaml

import pydantic

import pytest

from acmetk.main import Config

import acmetk.plugins.rfc2136_solver
from acmetk.plugin_base import PluginRegistry

PluginRegistry.load_plugins(r"plugins")


@pytest.fixture
def config_yaml():
    data = """
service:
  type: proxy
  hostname: '0.0.0.0'
  port: 8180
  db: 'postgresql+asyncpg://user:password@localhost:5432/acmetk'
  challenge_validators:
    - http01
    - tlsalpn01
  rsa_min_keysize: 2048
  ec_min_keysize: 256
  subnets:
    - '127.0.0.1/32' # localhost
  use_forwarded_header: true
  allow_wildcard: true
  eab:
    required: true
    type: plain
    header: x-user-id
  mgmt:
    authentication: true
    header: 'X-Acme-Proxy-Auth'
    group: 'acme-manager'
  client:
    directory: 'https://acme-staging-v02.api.letsencrypt.org/directory' # Let's Encrypt directory
    private_key: '/etc/acme_server/proxy_client_account.key'
    contact:
      email: 'acmetk@example.org'
    challenge_solver:
      type: rfc2136
      alg: hmac-sha512
      keyid: tsig-update-key
      secret: test
      server: 127.0.0.1
      dns_servers: ["127.1.2.3","127.2.3.4"]
logging:
  version: 1
  formatters:
    simple:
      format: '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    simple_root:
      format: '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
  handlers:
    root_console:
      class: logging.StreamHandler
      level: DEBUG
      formatter: simple_root
      stream: ext://sys.stdout
  root:
    level: DEBUG
    handlers: [root_console]
  disable_existing_loggers: no
"""
    return data


@pytest.fixture
def config_json(config_yaml):
    data = yaml.load(config_yaml, Loader=yaml.SafeLoader)
    return data


@pytest.fixture
def config_obj(config_json):
    data = Config.model_validate(config_json)
    return data


def test_config(config_obj):
    cfg = config_obj
    service = cfg.service
    mgmt = service.mgmt
    assert isinstance(service.db, pydantic.PostgresDsn)
    assert service.challenge_validators == ["http01", "tlsalpn01"]
    assert service.client.challenge_solver.type == "rfc2136"
    solver: acmetk.plugins.rfc2136_solver.RFC2136Client.Config = service.client.challenge_solver
    assert solver.dns_servers == ["127.1.2.3", "127.2.3.4"]
    assert (mgmt.authentication, mgmt.header, mgmt.group) == (True, "X-Acme-Proxy-Auth", "acme-manager")


@pytest.fixture
def example_config(request):
    return yaml.safe_load(request.param.read_text())


path = [i for i in Path("conf/").glob("*.sample.yml")]


@pytest.mark.parametrize("example_config", path, indirect=True, ids=[i.name for i in path])
def test_examples(example_config):
    from acmetk.main import Config

    Config.model_validate(example_config)
