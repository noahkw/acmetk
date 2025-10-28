import pytest
import pytest_asyncio

from acmetk.server import AcmeCA
from acmetk.server.metrics import PrometheusMetricsMixin
from .services import CAService, BrokerService, ProxyService


def pytest_generate_tests(metafunc):
    if "client" in metafunc.fixturenames:
        options = []
        #        ak = [f"{c}{l}" for c, l in sum(map(lambda x: list(itertools.product((x[0],), x[1])), {"rsa": (2048, 4096), "ec": (256, 384, 521)}.items()),[])]
        ak = ["ec256"]
        #        ck = [f"{c}{l}" for c, l in sum(map(lambda x: list(itertools.product((x[0],), x[1])), {"rsa": (2048, 4096), "ec": (256, 384, 521)}.items()), [])]
        options += [f"acmetk::{a}" for a in ak]

        #        ak = [f"{c}{l}" for c, l in sum(map(lambda x: list(itertools.product((x[0],), x[1])), {"rsa": (2048, ), "ec": (256, 384)}.items()),[])]
        #        ck = [f"{c}{l}" for c, l in sum(map(lambda x: list(itertools.product((x[0],), x[1])), {"rsa": (2048, 4096), "ec": (256, 384)}.items()), [])]
        #        options += [f"certbot::{a}" for a in ak]

        options += ["certbot::rsa4096"]
        options += ["acmez::rsa4096"]
        options += ["acmesh::ec256"]
        options += ["acmetiny::rsa4096"]
        options += ["dehydrated::rsa4096"]

        metafunc.parametrize("client", options, ids=options, indirect=True)

    if "service" in metafunc.fixturenames:
        options = ["CA", "Broker::CA", "Proxy::CA"]
        metafunc.parametrize("service", options, ids=options, indirect=True)


@pytest.fixture(scope="session")
def service_config():
    return AcmeCA.Config(
        challenge_validators=["dummy"], db="postgresql://none/none", metrics=PrometheusMetricsMixin.Config(enable=False)
    )


@pytest_asyncio.fixture(loop_scope="session")
async def service(request, unused_tcp_port_factory, tmp_path_factory, db, service_config):
    tmpdir = tmp_path_factory.mktemp(request.param)
    if request.param == "CA":
        s = CAService(tmpdir)
    elif request.param == "Broker::CA":
        s = BrokerService(tmpdir)
    elif request.param == "Proxy::CA":
        s = ProxyService(tmpdir)
    else:
        raise ValueError(request.param)

    await s.run(unused_tcp_port_factory(), db, service_config)
    yield s
    await s.shutdown()
    await s.cleanup()


@pytest.fixture
def db():
    return "postgresql+asyncpg://acme-broker:acme-broker-debug-pw@localhost:55432/{database}"
