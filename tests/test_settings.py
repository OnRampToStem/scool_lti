import unittest

from scale_api.settings import ScaleSettings


class SettingsTestCase(unittest.TestCase):
    def s(*args, **kwargs) -> ScaleSettings:
        data = {
            "ENV": "local",
            "DB_URL": "sqlite://test",
        }
        data.update(kwargs)
        return ScaleSettings(**data)

    def test_env_local(self):
        s = self.s(ENV="local")
        self.assertTrue(s.is_local)
        self.assertFalse(s.is_production)

    def test_env_prod(self):
        s = self.s(ENV="prod", DB_URL="postgres://test")
        self.assertFalse(s.is_local)
        self.assertTrue(s.is_production)

    def test_sqlite_local_only(self):
        s = self.s(ENV="local", DB_URL="sqlite://mem")
        self.assertEqual(s.ENV, "local")
        with self.assertRaises(ValueError):
            self.s(ENV="prod", DB_URL="sqlite://mem")

    def test_cors_from_string(self):
        s = self.s(BACKEND_CORS_ORIGINS="http://foo.org, http://bar.org")
        self.assertListEqual(
            s.BACKEND_CORS_ORIGINS, ["http://foo.org", "http://bar.org"]
        )

    def test_invalid_env(self):
        with self.assertRaises(ValueError):
            self.s(ENV="invalid")
