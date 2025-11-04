import ipaddress
import typing

from aiohttp import web
from pydantic import Field
from pydantic_settings import BaseSettings

from collections.abc import Callable, Awaitable

from aiohttp.web_exceptions import HTTPException
from aiohttp.web_middlewares import middleware
from aiohttp.web_request import Request
from aiohttp.web_response import Response

if typing.TYPE_CHECKING:
    import acmetk.server

try:
    import prometheus_client

    def prometheus_middleware_factory(metrics_prefix="aiohttp", registry: prometheus_client.CollectorRegistry = None):
        """
        based on
        https://github.com/shizacat/aiohttp_prometheus_exporter/blob/6a53e68abe1b226bda8cc791eebdcb48a9867909/aiohttp_prometheus_exporter/middleware.py
        """
        used_registry = registry if registry else prometheus_client.REGISTRY

        requests_metrics = prometheus_client.Counter(
            name=f"{metrics_prefix}_requests",
            documentation="Total requests by method and route name.",
            labelnames=["method", "route_name"],
            registry=used_registry,
        )

        responses_metrics = prometheus_client.Counter(
            name=f"{metrics_prefix}_responses",
            documentation="Total responses by method, route name and status code.",
            labelnames=["method", "route_name", "status_code"],
            registry=used_registry,
        )

        exceptions_metrics = prometheus_client.Counter(
            name=f"{metrics_prefix}_exceptions",
            documentation="Total exceptions raised by method, route name and exception type.",
            labelnames=["method", "route_name", "exception_type"],
            registry=used_registry,
        )

        @middleware
        async def prometheus_middleware(request: Request, handler: Callable[[Request], Awaitable[Response]]):
            route_name = request.match_info.route.name

            if not route_name or route_name == "metrics" or route_name.startswith("mgmt-"):
                return await handler(request)

            requests_metrics.labels(
                method=request.method,
                route_name=route_name,
            ).inc()

            status_code = 0

            try:
                response = await handler(request)
                status_code = response.status
            except Exception as e:
                status_code = e.status if isinstance(e, HTTPException) else 500

                exceptions_metrics.labels(
                    method=request.method,
                    route_name=route_name,
                    exception_type=type(e).__name__,
                ).inc()

                raise e from None
            finally:
                responses_metrics.labels(
                    method=request.method,
                    route_name=route_name,
                    status_code=status_code,
                ).inc()
            return response

        return prometheus_middleware

except ImportError:

    def prometheus_middleware_factory(metrics_prefix="aiohttp", registry=None):
        raise RuntimeError("prometheus_client is not installed")


class PrometheusMetricsMixin:
    DEFAULT_NETWORKS = ["::1/128", "127.0.0.0/8"]
    """default networks to allow access to /metrics from"""

    class Config(BaseSettings, extra="forbid"):
        enable: bool = False
        """enable /metrics"""
        allow_from: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = Field(
            default_factory=lambda: list([ipaddress.ip_network(i) for i in PrometheusMetricsMixin.DEFAULT_NETWORKS])
        )
        """allow accessing /metrics from these networks"""
        disable_compression: bool = False

    def __init__(self, cfg: typing.Union[Config, "acmetk.server.AcmeCA.Config"]):
        super().__init__(cfg=cfg)

        # Use self._extract_mixin_config to extract metrics config
        self.__c: PrometheusMetricsMixin.Config = self._extract_mixin_config(
            cfg, "metrics", PrometheusMetricsMixin.Config
        )

        if not self.__c.enable:
            return
        from prometheus_client import CollectorRegistry
        from prometheus_client.aiohttp import make_aiohttp_handler

        self._metrics_registry = CollectorRegistry()
        self._metrics_handler = make_aiohttp_handler(self._metrics_registry, self.__c.disable_compression)

    async def metrics(self, request: web.Request) -> web.StreamResponse:
        if self.__c.enable is False:
            raise web.HTTPNotFound

        remote: ipaddress.IPv4Address | ipaddress.IPv6Address = request["actual_ip"]
        for i in filter(lambda x: x.version == remote.version, self.__c.allow_from):
            if remote in i:
                break
        else:
            raise web.HTTPForbidden()

        v = await self._metrics_handler(request)
        return v
