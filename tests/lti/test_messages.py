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

from scool.schemas import LtiLaunchRequest
from tests import load_text_file


class LaunchMessageTestCase(unittest.TestCase):
    def test_resource_link_load_from_string(self) -> None:
        msg_txt = load_text_file("lti/canvas_resource_link.json")
        msg = LtiLaunchRequest.loads(msg_txt)

        self.assertEqual(msg.platform.id, "7f2308ab9092411aafe7f47279b47dfa")

        self.assertListEqual(msg.roles, ["Instructor"])
        self.assertTrue(msg.is_instructor)
        self.assertFalse(msg.is_student)

        self.assertDictEqual(
            msg.context,
            {
                "id": "cfd70b5da3ce9018402b66c1d4ecfdc6b9d6eeef",
                "title": "Development MATH6 Pilot",
            },
        )

        self.assertEqual(msg.message_type, "LtiResourceLinkRequest")
        self.assertTrue(msg.is_resource_link_launch)
        self.assertFalse(msg.is_deep_link_launch)

        self.assertIsNotNone(msg.names_role_service)

        self.assertEqual(
            msg.scool_user.id,
            "2b93d9e3-2bc8-4ded-a5a0-81202704e8f7@7f2308ab9092411aafe7f47279b47dfa",
        )
        self.assertEqual(msg.scool_user.email, "johnwa@csufresno.edu")
