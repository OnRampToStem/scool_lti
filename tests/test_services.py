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

from scool import services


class LtiServicesLinkHeaderTestCase(unittest.TestCase):
    def test_link_header_without_next(self) -> None:
        headers = {
            "Link": (
                "<https://fresnostate.instructure.com/api/lti/courses/79639/"
                'names_and_roles?page=1&per_page=50>; rel="current",'
                "<https://fresnostate.instructure.com/api/lti/courses/79639/"
                'names_and_roles?page=1&per_page=50>; rel="first",'
                "<https://fresnostate.instructure.com/api/lti/courses/79639/"
                'names_and_roles?page=1&per_page=50>; rel="last"'
            )
        }
        rv = services.next_page_link(headers)
        self.assertIsNone(rv)

    def test_link_header_next(self) -> None:
        headers = {
            "Link": (
                "<https://fresnostate.instructure.com/api/lti/courses/79639/"
                'names_and_roles?page=1&per_page=50>; rel="current",'
                "<https://fresnostate.instructure.com/api/lti/courses/79639/"
                'names_and_roles?page=2&per_page=50>; rel="next",'
                "<https://fresnostate.instructure.com/api/lti/courses/79639/"
                'names_and_roles?page=1&per_page=50>; rel="first",'
                "<https://fresnostate.instructure.com/api/lti/courses/79639/"
                'names_and_roles?page=3&per_page=50>; rel="last"'
            )
        }
        rv = services.next_page_link(headers)
        self.assertEqual(
            "https://fresnostate.instructure.com/api/lti/courses/79639/"
            "names_and_roles?page=2&per_page=50",
            rv,
        )
