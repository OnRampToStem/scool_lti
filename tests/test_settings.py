import os
import unittest
from unittest.mock import patch

from scool.settings import APISettings


class SettingsTestCase(unittest.TestCase):
    def test_env_local(self):
        s = APISettings(env="local")
        self.assertTrue(s.is_local)
        self.assertFalse(s.is_production)

    def test_env_prod(self):
        with patch.dict(os.environ, {"SCOOL_DB_URL": "oracle://mem"}):
            s = APISettings(env="prod")
            self.assertFalse(s.is_local)
            self.assertTrue(s.is_production)

    def test_sqlite_local_only(self):
        with patch.dict(os.environ, {"SCOOL_DB_URL": "sqlite://mem"}):
            APISettings(env="local")
            with self.assertRaises(ValueError):
                APISettings(env="prod")

    def test_invalid_env(self):
        with self.assertRaises(ValueError):
            APISettings(env="invalid")
