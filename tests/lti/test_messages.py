import unittest

from scale_api.lti.messages import LtiLaunchRequest

from tests import load_text_file


class LaunchMessageTestCase(unittest.TestCase):

    def test_resource_link_load_from_string(self):
        msg_txt = load_text_file('lti/canvas_resource_link.json')
        msg = LtiLaunchRequest.loads(msg_txt)

        self.assertEqual(msg.platform.id, '7f2308ab9092411aafe7f47279b47dfa')

        self.assertListEqual(msg.roles, ['Instructor'])
        self.assertTrue(msg.is_instructor)
        self.assertFalse(msg.is_student)

        self.assertDictEqual(msg.context, {
            'id': 'cfd70b5da3ce9018402b66c1d4ecfdc6b9d6eeef',
            'title': 'Development MATH6 Pilot',
        })

        self.assertEqual(msg.message_type, 'LtiResourceLinkRequest')
        self.assertTrue(msg.is_resource_link_launch)
        self.assertFalse(msg.is_deep_link_launch)

        self.assertIsNotNone(msg.names_role_service)

        self.assertEqual(msg.scale_user.id, '2b93d9e3-2bc8-4ded-a5a0-81202704e8f7@7f2308ab9092411aafe7f47279b47dfa')
        self.assertEqual(msg.scale_user.email, 'johnwa@csufresno.edu')
