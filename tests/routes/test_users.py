import unittest
from unittest.mock import AsyncMock, MagicMock, PropertyMock, call, patch

from fastapi import HTTPException, status

from scale_api.routes import users


class UsersRouteTestCase(unittest.IsolatedAsyncioTestCase):

    @patch('scale_api.routes.users.users_key')
    async def test_get_student_invalid_user_key(self, users_key_mock):
        users_key_mock.return_value = 'foo'
        mock_user = MagicMock()
        mock_user_is_student = PropertyMock(return_value=True)
        type(mock_user).is_student = mock_user_is_student
        with self.assertRaises(HTTPException) as exc:
            await users.get_user('bar', mock_user)
        self.assertEqual(exc.exception.status_code, status.HTTP_403_FORBIDDEN)
        users_key_mock.assert_called_with(mock_user)
        mock_user_is_student.assert_called_once_with()

    @patch('scale_api.db.user_store', new_callable=AsyncMock)
    @patch('scale_api.routes.users.users_key')
    async def test_get_student_not_created_yet(self, users_key_mock, user_store_mock):
        users_key_mock.return_value = 'foo'
        mock_user = MagicMock()
        mock_user_is_student = PropertyMock(return_value=True)
        type(mock_user).is_student = mock_user_is_student
        user_store_mock.user_async.side_effect = LookupError()
        rv = await users.get_user('foo', mock_user)
        self.assertDictEqual(rv, {})
        users_key_mock.assert_called_with(mock_user)
        mock_user_is_student.assert_has_calls([call(), call()])
