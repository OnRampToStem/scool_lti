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

from scool.schemas import LtiLaunchRequest
from tests import load_text_file


def test_resource_link_load_from_string() -> None:
    msg_txt = load_text_file("lti/canvas_resource_link.json")
    msg = LtiLaunchRequest.loads(msg_txt)

    assert msg.platform.id == "7f2308ab9092411aafe7f47279b47dfa"

    assert msg.roles == ["Instructor"]
    assert msg.is_instructor
    assert not msg.is_student

    assert msg.context == {
        "id": "cfd70b5da3ce9018402b66c1d4ecfdc6b9d6eeef",
        "title": "Development MATH6 Pilot",
    }

    assert msg.message_type == "LtiResourceLinkRequest"
    assert msg.is_resource_link_launch
    assert not msg.is_deep_link_launch

    assert msg.names_role_service

    assert (
        msg.scool_user.id
        == "2b93d9e3-2bc8-4ded-a5a0-81202704e8f7@7f2308ab9092411aafe7f47279b47dfa"
    )
    assert msg.scool_user.email == "johnwa@csufresno.edu"
