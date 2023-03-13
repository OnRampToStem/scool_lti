import datetime
import unittest
from unittest.mock import patch

from scale_api import (
    keys,
    schemas,
)


class KeysTestCase(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.test_key_1 = schemas.AuthJsonWebKey(
            kid="1",
            data="test_key_1",
            valid_from=datetime.datetime(2021, 7, 1, 15, 23, 10, tzinfo=datetime.UTC),
            valid_to=datetime.datetime.now(tz=datetime.UTC)
            + datetime.timedelta(days=30),
        )
        self.test_key_2 = schemas.AuthJsonWebKey(
            kid="2",
            data="test_key_2",
            valid_from=datetime.datetime(2021, 7, 2, 10, 55, 27, tzinfo=datetime.UTC),
            valid_to=datetime.datetime.now(tz=datetime.UTC)
            + datetime.timedelta(days=90),
        )

    @patch("authlib.jose.JsonWebKey.import_key")
    @patch("scale_api.keys.private_keys")
    async def test_private_key_returns_newest_from_if_no_to(
        self,
        private_keys_mock,
        import_key_mock,
    ):
        self.test_key_1.valid_to = None
        self.test_key_2.valid_to = None
        private_keys_mock.return_value = [self.test_key_1, self.test_key_2]
        await keys.private_key()
        import_key_mock.assert_called_with(self.test_key_2.data.get_secret_value())

    @patch("authlib.jose.JsonWebKey.import_key")
    @patch("scale_api.keys.private_keys")
    async def test_private_key_returns_valid_to_none_if_other_has_valid_to(
        self,
        private_keys_mock,
        import_key_mock,
    ):
        self.test_key_1.valid_to = None
        self.assertIsNotNone(self.test_key_2.valid_to)
        private_keys_mock.return_value = [self.test_key_1, self.test_key_2]
        await keys.private_key()
        import_key_mock.assert_called_with(self.test_key_1.data.get_secret_value())

    @patch("authlib.jose.JsonWebKey.import_key")
    @patch("scale_api.keys.private_keys")
    async def test_private_key_returns_further_valid_to(
        self,
        private_keys_mock,
        import_key_mock,
    ):
        self.assertGreater(self.test_key_2.valid_to, self.test_key_1.valid_to)
        private_keys_mock.return_value = [self.test_key_1, self.test_key_2]
        await keys.private_key()
        import_key_mock.assert_called_with(self.test_key_2.data.get_secret_value())

    @patch("scale_api.keys.private_keys")
    async def test_private_key_raises_if_no_keys_found(
        self,
        private_keys_mock,
    ):
        private_keys_mock.return_value = []
        with self.assertRaises(RuntimeError):
            await keys.private_key()

    @patch("scale_api.db.store.json_web_keys_async")
    async def test_private_keys_returns_only_valid_keys(
        self,
        db_mock,
    ):
        now = datetime.datetime.now(tz=datetime.UTC)
        delta = datetime.timedelta(days=1)

        # valid_from < now < valid_to
        self.assertLess(self.test_key_1.valid_from, now)
        self.assertGreater(self.test_key_1.valid_to, now)
        db_mock.return_value = [self.test_key_1]
        rv = await keys.private_keys()
        self.assertListEqual(rv, [self.test_key_1])

        # valid_from < now
        self.test_key_1.valid_to = None
        db_mock.return_value = [self.test_key_1]
        rv = await keys.private_keys()
        self.assertListEqual(rv, [self.test_key_1])

        # now < valid_from
        self.test_key_1.valid_from = now + delta
        db_mock.return_value = [self.test_key_1]
        rv = await keys.private_keys()
        self.assertListEqual(rv, [])

        # valid_from <= valid_to < now  # noqa: ERA001
        self.test_key_1.valid_from = now - delta
        self.test_key_1.valid_to = now - delta
        db_mock.return_value = [self.test_key_1]
        rv = await keys.private_keys()
        self.assertListEqual(rv, [])
