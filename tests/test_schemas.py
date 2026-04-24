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

import pytest

from scool.schemas import AuthUser, ScoolUser

type Data = dict[str, Any]


@pytest.fixture
def auth_user_data() -> Data:
    return {
        "id": "123",
        "client_id": "test@test.org",
        "client_secret_hash": "non",
    }


@pytest.fixture
def scool_user_data() -> Data:
    return {"email": "test@test.org"}


def test_auth_user_defaults(auth_user_data: Data) -> None:
    u = AuthUser(**auth_user_data)
    assert u.is_active
    assert not u.is_superuser
    assert u.scopes is None


def test_auth_user_scopes(auth_user_data: Data) -> None:
    scopes = ["role:foo", "role:bar"]
    u = AuthUser(**auth_user_data, scopes=" ".join(scopes))
    assert u.scopes == scopes

    u = AuthUser(**auth_user_data, scopes=scopes)
    assert u.scopes == scopes


def test_auth_user_superuser(auth_user_data: Data) -> None:
    scopes = ["role:foo"]
    u = AuthUser(**auth_user_data, scopes=scopes)
    assert not u.is_superuser

    scopes.append("role:superuser")
    u = AuthUser(**auth_user_data, scopes=scopes)
    assert u.is_superuser


def test_auth_user_from_scool_user() -> None:
    su = ScoolUser(
        id="123@xyz:lms",
        email="test@test.org",
        roles=["Learner"],
        context={"id": "123456", "title": "Math6"},
    )
    au = AuthUser.from_scool_user(su)
    assert au.id == "123@xyz:lms"
    assert au.client_id == "test@test.org"
    assert au.client_secret_hash == "none"
    assert au.scopes == ["role:Learner"]
    assert au.context == {"id": "123456", "title": "Math6"}


def test_scool_user_defaults(scool_user_data: Data) -> None:
    u = ScoolUser(**scool_user_data)
    assert u.roles == []
    assert u.context is None


def test_scool_user_roles_from_lti_launch(scool_user_data: Data) -> None:
    u = ScoolUser(
        roles=["http://purl.imsglobal.org/vocab/lis/v2/membership#Learner"],
        **scool_user_data,
    )
    assert u.roles == ["Learner"]


def test_scool_user_roles_from_auth_user(scool_user_data: Data) -> None:
    u = ScoolUser(
        roles=["Instructor", "developer"],
        **scool_user_data,
    )
    assert u.roles == ["Instructor", "developer"]


def test_scool_user_is_a(scool_user_data: Data) -> None:
    u = ScoolUser(
        roles=["http://purl.imsglobal.org/vocab/lis/v2/membership#Learner"],
        **scool_user_data,
    )
    assert u.is_student
    assert not u.is_instructor

    u = ScoolUser(
        roles=["http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor"],
        **scool_user_data,
    )
    assert not u.is_student
    assert u.is_instructor


def test_scool_user_user_id(scool_user_data: Data) -> None:
    # Format of a ScoolUser.id is ``<LMS uid>@<Platform.id>``
    u = ScoolUser(id="foo@bar", **scool_user_data)
    assert u.user_id == "foo"


def test_scool_user_id_if_from_auth_user(scool_user_data: Data) -> None:
    # AuthUser.id will be a uuid and have no ``@``
    u = ScoolUser(id="foo", **scool_user_data)
    assert u.user_id == "foo"


def test_scool_user_platform_id(scool_user_data: Data) -> None:
    u = ScoolUser(id="foo@bar", **scool_user_data)
    assert u.platform_id == "bar"


def test_scool_user_platform_id_if_from_auth_user(scool_user_data: Data) -> None:
    # AuthUser's should have a fixed value
    u = ScoolUser(id="foo", **scool_user_data)
    assert u.platform_id == "scool"


def test_scool_user_context_id(scool_user_data: Data) -> None:
    u = ScoolUser(
        id="foo@bar", context={"id": "123", "title": "Math6"}, **scool_user_data
    )
    assert u.context_id == "123"


def test_scool_user_context_id_if_from_auth_user(scool_user_data: Data) -> None:
    # AuthUser's should have a fixed value
    u = ScoolUser(id="foo", **scool_user_data)
    assert u.context_id == "scool"


def test_scool_user_from_auth_user() -> None:
    au = AuthUser(
        id="123",
        client_id="test@test.org",
        client_secret_hash="$1$foo.bar",
        scopes=["role:developer", "role:editor"],
        context={"id": "123456", "title": "Math6"},
    )
    su = ScoolUser.from_auth_user(au)
    assert su.id == "123"
    assert su.email == "test@test.org"
    assert su.roles == ["developer", "editor"]
    assert su.context == {"id": "123456", "title": "Math6"}
