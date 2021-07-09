import unittest

from scale_api.schemas import AuthUser, ScaleUser


class AuthUserTestCase(unittest.TestCase):

    DEFAULTS = {
        'id': '123',
        'client_id': 'test@test.org',
        'client_secret_hash': 'non',
    }

    def test_defaults(self):
        u = AuthUser(**self.DEFAULTS)
        self.assertTrue(u.is_active)
        self.assertFalse(u.is_verified)
        self.assertFalse(u.is_superuser)
        self.assertIsNone(u.scopes)

    def test_scopes(self):
        scopes = ['role:foo', 'role:bar']
        u = AuthUser(**self.DEFAULTS, scopes=' '.join(scopes))
        self.assertListEqual(u.scopes, scopes)

        u = AuthUser(**self.DEFAULTS, scopes=scopes)
        self.assertListEqual(u.scopes, scopes)

    def test_superuser(self):
        scopes = ['role:foo']
        u = AuthUser(**self.DEFAULTS, scopes=scopes)
        self.assertFalse(u.is_superuser)

        scopes.append('role:superuser')
        u = AuthUser(**self.DEFAULTS, scopes=scopes)
        self.assertTrue(u.is_superuser)

    def test_from_scale_user(self):
        su = ScaleUser(id='123@xyz:lms', email='test@test.org', roles=['Learner'])
        au = AuthUser.from_scale_user(su)
        self.assertEqual(au.id, '123@xyz:lms')
        self.assertEqual(au.client_id, 'test@test.org')
        self.assertEqual(au.client_secret_hash, 'none')
        self.assertListEqual(au.scopes, ['role:Learner'])


class ScaleUserTestCase(unittest.TestCase):

    DEFAULTS = {
        'email': 'test@test.org',
    }

    def test_defaults(self):
        u = ScaleUser(**self.DEFAULTS)
        self.assertListEqual(u.roles, [])
        self.assertIsNone(u.context)

    def test_from_auth_user(self):
        au = AuthUser(
            id='123',
            client_id='test@test.org',
            client_secret_hash='$1$foo.bar',
            scopes=['role:developer', 'role:editor'],
        )
        su = ScaleUser.from_auth_user(au)
        self.assertEqual(su.id, '123')
        self.assertEqual(su.email, 'test@test.org')
        self.assertListEqual(su.roles, ['developer', 'editor'])
