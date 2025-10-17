import ipaddress
import logging.config
import unittest

from acmetk.server import RequestIPDNSChallengeValidator

log = logging.getLogger("acmetk.test_requestipdns")


class TestRequestIPDNSValidator(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.requestipdns_validator = RequestIPDNSChallengeValidator()

    async def test_query_a_record(self):
        records_main = await self.requestipdns_validator.query_records("acmenoah.luis.uni-hannover.de")
        self.assertIn(ipaddress.IPv4Address("130.75.188.105"), records_main)

        records_sub = await self.requestipdns_validator.query_records("sub.acmenoah.luis.uni-hannover.de")
        self.assertIn(ipaddress.IPv4Address("130.75.188.105"), records_sub)
