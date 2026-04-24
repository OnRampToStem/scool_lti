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

from typing import Any
from unittest.mock import Mock, patch

import pytest
from fastapi import HTTPException
from fastapi.security import HTTPBasicCredentials

from scool import schemas, security


def test_invalid_scopes() -> None:
    with pytest.raises(ValueError, match="SCOPE"):
        security.ScopePermission.from_string("foo:bar:baz:qux")
    with pytest.raises(ValueError, match="SCOPE"):
        security.ScopePermission.from_string("")


def test_with_only_resource() -> None:
    sp = security.ScopePermission.from_string("org")
    assert sp.resource == "org"
    assert sp.actions == set()
    assert sp.items == set()


def test_with_action() -> None:
    sp = security.ScopePermission.from_string("org:read")
    assert sp.resource == "org"
    assert sp.actions == {"read"}
    assert sp.items == set()


def test_with_items() -> None:
    sp = security.ScopePermission.from_string("org:read:123")
    assert sp.resource == "org"
    assert sp.actions == {"read"}
    assert sp.items == {"123"}


def test_write_implies_read() -> None:
    sp = security.ScopePermission.from_string("org:write")
    assert sp.resource == "org"
    assert sp.actions == {"read", "write"}


def test_multiple_items() -> None:
    sp = security.ScopePermission.from_string("org:read:123,456,789")
    assert sp.items == {"123", "456", "789"}


def test_star_allows_all_actions() -> None:
    sp = security.ScopePermission.from_string("org:*")
    other = security.ScopePermission.from_string("org:delete")
    assert sp.allows(other)

    other = security.ScopePermission.from_string("org:eradicate")
    assert sp.allows(other)


def test_write_allows_read() -> None:
    sp = security.ScopePermission.from_string("org:write")
    other = security.ScopePermission.from_string("org:read")
    assert sp.allows(other)


def test_read_disallows_write() -> None:
    sp = security.ScopePermission.from_string("org:read")
    other = security.ScopePermission.from_string("org:write")
    assert not sp.allows(other)


@pytest.fixture
def user_data() -> dict[str, Any]:
    return {
        "id": "c51dac2cf12f4676a59571bdab80c73b",
        "client_id": "testuser@mail.fresnostate.edu",
        "client_secret_hash": "none",
        "is_active": True,
        "scopes": [],
    }


def test_superuser_access(user_data: dict[str, Any]) -> None:
    user_data["scopes"].append("role:superuser")
    user = schemas.AuthUser(**user_data)
    assert security.can_access(user, ["org"])


def test_inactive_user_disallowed(user_data: dict[str, Any]) -> None:
    user_data["is_active"] = False
    user = schemas.AuthUser(**user_data)
    assert not security.can_access(user, [])


def test_no_scopes_is_allowed(user_data: dict[str, Any]) -> None:
    user = schemas.AuthUser(**user_data)
    assert security.can_access(user, None)
    assert security.can_access(user, [])


def test_scopes_required(user_data: dict[str, Any]) -> None:
    user = schemas.AuthUser(**user_data)
    assert not security.can_access(user, ["org"])

    user_data["scopes"] = ["org:read"]
    user = schemas.AuthUser(**user_data)
    assert security.can_access(user, ["org"])


def test_multiple_user_scopes_with_match(user_data: dict[str, Any]) -> None:
    user_data["scopes"] = ["foo:bar", "baz:qux", "org:write"]
    user = schemas.AuthUser(**user_data)
    assert security.can_access(user, ["org:read"])


def test_multiple_user_scopes_without_match(user_data: dict[str, Any]) -> None:
    user_data["scopes"] = ["foo:bar", "baz:qux", "org:read"]
    user = schemas.AuthUser(**user_data)
    assert not security.can_access(user, ["org:write"])


@pytest.mark.anyio
async def test_authorize_raise_if_no_valid_user() -> None:
    request = Mock()
    scopes = Mock()
    scopes.scopes = []
    basic = HTTPBasicCredentials(username="", password="")
    with pytest.raises(HTTPException) as http_exc:
        await security.authorize(request, scopes, "", basic)
    assert http_exc.value.status_code == 401


@patch("scool.schemas.ScoolUser")
@patch("scool.security.can_access")
@patch("scool.security.auth_user_from_token")
@pytest.mark.anyio
async def test_authorize_from_bearer_token(
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
