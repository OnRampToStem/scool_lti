import unittest

from scale_api import services


class LtiServicesLinkHeaderTestCase(unittest.TestCase):
    def test_link_header_without_next(self):
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

    def test_link_header_next(self):
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
