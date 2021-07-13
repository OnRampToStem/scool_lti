import unittest
from unittest.mock import Mock, patch

from fastapi import HTTPException

from scale_api import (
    auth,
    schemas,
)


class ScopePermissionTestCase(unittest.TestCase):

    def test_invalid_scopes(self):
        with self.assertRaises(ValueError):
            auth.ScopePermission.from_string('foo:bar:baz:qux')
        with self.assertRaises(ValueError):
            auth.ScopePermission.from_string('')

    def test_with_only_resource(self):
        sp = auth.ScopePermission.from_string('org')
        self.assertEqual(sp.resource, 'org')
        self.assertSetEqual(sp.actions, set())
        self.assertSetEqual(sp.items, set())

    def test_with_action(self):
        sp = auth.ScopePermission.from_string('org:read')
        self.assertEqual(sp.resource, 'org')
        self.assertSetEqual(sp.actions, {'read'})
        self.assertSetEqual(sp.items, set())

    def test_with_items(self):
        sp = auth.ScopePermission.from_string('org:read:123')
        self.assertEqual(sp.resource, 'org')
        self.assertSetEqual(sp.actions, {'read'})
        self.assertSetEqual(sp.items, {'123'})

    def test_write_implies_read(self):
        sp = auth.ScopePermission.from_string('org:write')
        self.assertEqual(sp.resource, 'org')
        self.assertSetEqual(sp.actions, {'read', 'write'})

    def test_multiple_items(self):
        sp = auth.ScopePermission.from_string('org:read:123,456,789')
        self.assertSetEqual(sp.items, {'123', '456', '789'})

    def test_star_allows_all_actions(self):
        sp = auth.ScopePermission.from_string('org:*')
        other = auth.ScopePermission.from_string('org:delete')
        self.assertTrue(sp.allows(other))

        other = auth.ScopePermission.from_string('org:eradicate')
        self.assertTrue(sp.allows(other))

    def test_write_allows_read(self):
        sp = auth.ScopePermission.from_string('org:write')
        other = auth.ScopePermission.from_string('org:read')
        self.assertTrue(sp.allows(other))

    def test_read_disallows_write(self):
        sp = auth.ScopePermission.from_string('org:read')
        other = auth.ScopePermission.from_string('org:write')
        self.assertFalse(sp.allows(other))


class ScopeAuthUserAccessTestCase(unittest.TestCase):

    def setUp(self) -> None:
        self.test_user = {
            'id': 'c51dac2cf12f4676a59571bdab80c73b',
            'client_id': 'testuser@mail.fresnostate.edu',
            'client_secret_hash': 'none',
            'is_active': True,
            'is_verified': False,
            'scopes': [],
        }

    def test_superuser_access(self):
        self.test_user['scopes'].append('role:superuser')
        user = schemas.AuthUser(**self.test_user)
        self.assertTrue(auth.can_access(user, ['org']))

    def test_inactive_user_disallowed(self):
        self.test_user['is_active'] = False
        user = schemas.AuthUser(**self.test_user)
        self.assertFalse(auth.can_access(user, []))

    def test_no_scopes_is_allowed(self):
        user = schemas.AuthUser(**self.test_user)
        self.assertTrue(auth.can_access(user, None))
        self.assertTrue(auth.can_access(user, []))

    def test_scopes_required(self):
        user = schemas.AuthUser(**self.test_user)
        self.assertFalse(auth.can_access(user, ['org']))

        self.test_user['scopes'] = ['org:read']
        user = schemas.AuthUser(**self.test_user)
        self.assertTrue(auth.can_access(user, ['org']))

    def test_multiple_user_scopes_with_match(self):
        self.test_user['scopes'] = ['foo:bar', 'baz:qux', 'org:write']
        user = schemas.AuthUser(**self.test_user)
        self.assertTrue(auth.can_access(user, ['org:read']))

    def test_multiple_user_scopes_without_match(self):
        self.test_user['scopes'] = ['foo:bar', 'baz:qux', 'org:read']
        user = schemas.AuthUser(**self.test_user)
        self.assertFalse(auth.can_access(user, ['org:write']))


class AuthorizeTestCase(unittest.IsolatedAsyncioTestCase):

    async def test_authorize_raise_if_no_valid_user(self):
        request = Mock()
        scopes = Mock()
        request.session = {}
        scopes.scopes = []
        with self.assertRaises(HTTPException) as http_exc:
            await auth.authorize(request, scopes, '')
        self.assertTrue(http_exc.exception.status_code, 401)

    @patch('scale_api.auth.can_access')
    @patch('scale_api.auth.auth_user_from_token')
    async def test_authorize_from_bearer_token(self, token_mock, can_access_mock):
        token_mock.return_value = 'test_user'
        request = Mock()
        scopes = Mock()
        request.session = {'au': 'foo', 'scale_user': 'bar'}
        scopes.scopes = []
        await auth.authorize(request, scopes, 'test_token')
        token_mock.assert_called_with('test_token')
        can_access_mock.assert_called_with('test_user', [])

    @patch('scale_api.auth.can_access')
    async def test_authorize_from_auth_user_session(
            self,
            can_access_mock
    ):
        request = Mock()
        scopes = Mock()
        request.session = {
            'au': {
                'id': '1',
                'client_id': 'test@test.org',
                'client_secret_hash': 'none',
            },
            'scale_user': {}
        }
        scopes.scopes = []
        await auth.authorize(request, scopes, '')
        can_access_mock.assert_called_once()
        self.assertEqual(request.state.auth_user.client_id, 'test@test.org')

    @patch('scale_api.auth.can_access')
    async def test_authorize_from_scale_user_session(
            self,
            can_access_mock
    ):
        request = Mock()
        scopes = Mock()
        request.session = {
            'scale_user': {
                'id': '123456@789',
                'email': 'test_scale_user@test.org',
            },
            'au': {}
        }
        scopes.scopes = []
        await auth.authorize(request, scopes, '')
        can_access_mock.assert_called_once()
        self.assertEqual(request.state.auth_user.client_id, 'test_scale_user@test.org')
