# Student Centered Open Online Learning (SCOOL) LTI Integration
# Copyright (c) 2021-2024  Fresno State University, SCOOL Project Team
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import unittest
from unittest.mock import Mock, patch

from fastapi import HTTPException
from fastapi.security import HTTPBasicCredentials

from scool import schemas, security


class ScopePermissionTestCase(unittest.TestCase):
    def test_invalid_scopes(self):
        with self.assertRaises(ValueError):
            security.ScopePermission.from_string("foo:bar:baz:qux")
        with self.assertRaises(ValueError):
            security.ScopePermission.from_string("")

    def test_with_only_resource(self):
        sp = security.ScopePermission.from_string("org")
        self.assertEqual(sp.resource, "org")
        self.assertSetEqual(sp.actions, set())
        self.assertSetEqual(sp.items, set())

    def test_with_action(self):
        sp = security.ScopePermission.from_string("org:read")
        self.assertEqual(sp.resource, "org")
        self.assertSetEqual(sp.actions, {"read"})
        self.assertSetEqual(sp.items, set())

    def test_with_items(self):
        sp = security.ScopePermission.from_string("org:read:123")
        self.assertEqual(sp.resource, "org")
        self.assertSetEqual(sp.actions, {"read"})
        self.assertSetEqual(sp.items, {"123"})

    def test_write_implies_read(self):
        sp = security.ScopePermission.from_string("org:write")
        self.assertEqual(sp.resource, "org")
        self.assertSetEqual(sp.actions, {"read", "write"})

    def test_multiple_items(self):
        sp = security.ScopePermission.from_string("org:read:123,456,789")
        self.assertSetEqual(sp.items, {"123", "456", "789"})

    def test_star_allows_all_actions(self):
        sp = security.ScopePermission.from_string("org:*")
        other = security.ScopePermission.from_string("org:delete")
        self.assertTrue(sp.allows(other))

        other = security.ScopePermission.from_string("org:eradicate")
        self.assertTrue(sp.allows(other))

    def test_write_allows_read(self):
        sp = security.ScopePermission.from_string("org:write")
        other = security.ScopePermission.from_string("org:read")
        self.assertTrue(sp.allows(other))

    def test_read_disallows_write(self):
        sp = security.ScopePermission.from_string("org:read")
        other = security.ScopePermission.from_string("org:write")
        self.assertFalse(sp.allows(other))


class ScopeAuthUserAccessTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.test_user = {
            "id": "c51dac2cf12f4676a59571bdab80c73b",
            "client_id": "testuser@mail.fresnostate.edu",
            "client_secret_hash": "none",
            "is_active": True,
            "scopes": [],
        }

    def test_superuser_access(self):
        self.test_user["scopes"].append("role:superuser")
        user = schemas.AuthUser(**self.test_user)
        self.assertTrue(security.can_access(user, ["org"]))

    def test_inactive_user_disallowed(self):
        self.test_user["is_active"] = False
        user = schemas.AuthUser(**self.test_user)
        self.assertFalse(security.can_access(user, []))

    def test_no_scopes_is_allowed(self):
        user = schemas.AuthUser(**self.test_user)
        self.assertTrue(security.can_access(user, None))
        self.assertTrue(security.can_access(user, []))

    def test_scopes_required(self):
        user = schemas.AuthUser(**self.test_user)
        self.assertFalse(security.can_access(user, ["org"]))

        self.test_user["scopes"] = ["org:read"]
        user = schemas.AuthUser(**self.test_user)
        self.assertTrue(security.can_access(user, ["org"]))

    def test_multiple_user_scopes_with_match(self):
        self.test_user["scopes"] = ["foo:bar", "baz:qux", "org:write"]
        user = schemas.AuthUser(**self.test_user)
        self.assertTrue(security.can_access(user, ["org:read"]))

    def test_multiple_user_scopes_without_match(self):
        self.test_user["scopes"] = ["foo:bar", "baz:qux", "org:read"]
        user = schemas.AuthUser(**self.test_user)
        self.assertFalse(security.can_access(user, ["org:write"]))


class AuthorizeTestCase(unittest.IsolatedAsyncioTestCase):
    async def test_authorize_raise_if_no_valid_user(self):
        request = Mock()
        scopes = Mock()
        scopes.scopes = []
        basic = HTTPBasicCredentials(username="", password="")
        with self.assertRaises(HTTPException) as http_exc:
            await security.authorize(request, scopes, "", basic)
        self.assertTrue(http_exc.exception.status_code, 401)

    @patch("scool.schemas.ScoolUser")
    @patch("scool.security.can_access")
    @patch("scool.security.auth_user_from_token")
    async def test_authorize_from_bearer_token(
        self,
        token_mock,
        can_access_mock,
        scool_user_mock,
    ):
        token_mock.return_value = "test_user"
        request = Mock()
        scopes = Mock()
        scopes.scopes = []
        basic = HTTPBasicCredentials(username="", password="")
        await security.authorize(request, scopes, "test_token", basic)
        token_mock.assert_called_with("test_token")
        can_access_mock.assert_called_with("test_user", [])
        scool_user_mock.from_auth_user.assert_called_with("test_user")
