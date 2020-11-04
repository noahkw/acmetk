import asyncio
import json
import unittest
from datetime import datetime

import josepy

from acme_broker import models, util
from acme_broker.database import Database
from acme_broker.main import load_config


class TestDatabase(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        with open(r"test_account.pub", "rb") as pem:
            b = pem.read()

        self.pubkey = josepy.util.ComparableRSAKey(util.deserialize_pubkey(b))

    async def asyncSetUp(self) -> None:
        self.loop = asyncio.get_event_loop()
        config = load_config("../debug.yml")
        db = Database(config["ca"]["db"])

        await db.begin()
        self.db = db
        self.session = db.session

    async def test_add_account(self):
        async with self.session() as session:
            account = models.Account(
                key=self.pubkey,
                kid=util.sha256_hex_digest(util.serialize_pubkey(self.pubkey)),
                status=models.AccountStatus.VALID,
                contact=json.dumps(()),
            )
            session.add(account)

            result = await self.db.get_account(session, self.pubkey)

            assert util.serialize_pubkey(result.key) == util.serialize_pubkey(
                account.key
            )
            assert result.key == account.key

            await session.commit()

    async def test_add_order_authz_chall(self):
        async with self.session() as session:
            account = models.Account(
                key=self.pubkey,
                kid=util.sha256_hex_digest(util.serialize_pubkey(self.pubkey)),
                status=models.AccountStatus.VALID,
                contact=json.dumps(()),
            )
            # session.add(account)

            identifiers = [
                models.Identifier(
                    type=models.IdentifierType.DNS,
                    value="test.uni-hannover.de",
                    authorizations=[
                        models.Authorization(
                            status=models.AuthorizationStatus.PENDING,
                            wildcard=False,
                            challenges=[
                                models.Challenge(
                                    type=models.ChallengeType.HTTP_01,
                                    status=models.ChallengeStatus.PENDING,
                                )
                            ],
                        ),
                    ],
                ),
                models.Identifier(
                    type=models.IdentifierType.DNS,
                    value="test2.uni-hannover.de",
                    authorizations=[
                        models.Authorization(
                            status=models.AuthorizationStatus.VALID,
                            wildcard=False,
                            challenges=[
                                models.Challenge(
                                    type=models.ChallengeType.DNS_01,
                                    status=models.ChallengeStatus.INVALID,
                                )
                            ],
                        ),
                    ],
                ),
            ]

            identifiers_ = [
                models.Identifier(
                    type=models.IdentifierType.DNS, value="test3.uni-hannover.de"
                ),
                models.Identifier(
                    type=models.IdentifierType.DNS, value="test4.uni-hannover.de"
                ),
            ]
            for identifier in identifiers_:
                identifier.authorizations = models.Authorization.create_all(identifier)

                for authorization in identifier.authorizations:
                    authorization.challenges = models.Challenge.create_all()

            identifiers.extend(identifiers_)

            order = models.Order(
                status=models.OrderStatus.PENDING,
                expires=datetime(2020, 11, 20),
                identifiers=identifiers,
                notBefore=datetime(2020, 10, 28),
                notAfter=datetime(2020, 12, 31),
                account=account,
            )
            session.add(order)

            self.assertEqual(len(account.orders[0].identifiers), 4)
            self.assertFalse(
                account.orders[0].identifiers[1].authorizations[0].wildcard
            )
            self.assertEqual(
                account.orders[0].identifiers[0].authorizations[0].challenges[0].type,
                models.ChallengeType.HTTP_01,
            )

            await session.flush()
            self.assertIsNotNone(
                account.orders[0].identifiers[1].authorizations[0].authorization_id
            )
            self.assertNotEqual(
                account.orders[0].identifiers[3].authorizations[0].challenges[0].type,
                account.orders[0].identifiers[3].authorizations[0].challenges[1].type,
            )

            await session.commit()
