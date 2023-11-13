import unittest

from scool.schemas import AuthUser, ScoolUser


class AuthUserTestCase(unittest.TestCase):
    DEFAULTS = {
        "id": "123",
        "client_id": "test@test.org",
        "client_secret_hash": "non",
    }

    def test_defaults(self):
        u = AuthUser(**self.DEFAULTS)
        self.assertTrue(u.is_active)
        self.assertFalse(u.is_superuser)
        self.assertIsNone(u.scopes)

    def test_scopes(self):
        scopes = ["role:foo", "role:bar"]
        u = AuthUser(**self.DEFAULTS, scopes=" ".join(scopes))
        self.assertListEqual(u.scopes, scopes)

        u = AuthUser(**self.DEFAULTS, scopes=scopes)
        self.assertListEqual(u.scopes, scopes)

    def test_superuser(self):
        scopes = ["role:foo"]
        u = AuthUser(**self.DEFAULTS, scopes=scopes)
        self.assertFalse(u.is_superuser)

        scopes.append("role:superuser")
        u = AuthUser(**self.DEFAULTS, scopes=scopes)
        self.assertTrue(u.is_superuser)

    def test_from_scool_user(self):
        su = ScoolUser(
            id="123@xyz:lms",
            email="test@test.org",
            roles=["Learner"],
            context={"id": "123456", "title": "Math6"},
        )
        au = AuthUser.from_scool_user(su)
        self.assertEqual(au.id, "123@xyz:lms")
        self.assertEqual(au.client_id, "test@test.org")
        self.assertEqual(au.client_secret_hash, "none")
        self.assertListEqual(au.scopes, ["role:Learner"])
        self.assertDictEqual(au.context, {"id": "123456", "title": "Math6"})


class ScoolUserTestCase(unittest.TestCase):
    DEFAULTS = {
        "email": "test@test.org",
    }

    def test_defaults(self):
        u = ScoolUser(**self.DEFAULTS)
        self.assertListEqual(u.roles, [])
        self.assertIsNone(u.context)

    def test_roles_from_lti_launch(self):
        u = ScoolUser(
            roles=["http://purl.imsglobal.org/vocab/lis/v2/membership#Learner"],
            **self.DEFAULTS,
        )
        self.assertListEqual(u.roles, ["Learner"])

    def test_roles_from_auth_user(self):
        u = ScoolUser(
            roles=["Instructor", "developer"],
            **self.DEFAULTS,
        )
        self.assertListEqual(u.roles, ["Instructor", "developer"])

    def test_is_a(self):
        u = ScoolUser(
            roles=["http://purl.imsglobal.org/vocab/lis/v2/membership#Learner"],
            **self.DEFAULTS,
        )
        self.assertTrue(u.is_student)
        self.assertFalse(u.is_instructor)

        u = ScoolUser(
            roles=["http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor"],
            **self.DEFAULTS,
        )
        self.assertFalse(u.is_student)
        self.assertTrue(u.is_instructor)

    def test_user_id(self):
        # Format of a ScoolUser.id is ``<LMS uid>@<Platform.id>``
        u = ScoolUser(id="foo@bar", **self.DEFAULTS)
        self.assertEqual(u.user_id, "foo")

    def test_user_id_if_from_auth_user(self):
        # AuthUser.id will be a uuid and have no ``@``
        u = ScoolUser(id="foo", **self.DEFAULTS)
        self.assertEqual("foo", u.user_id)

    def test_platform_id(self):
        u = ScoolUser(id="foo@bar", **self.DEFAULTS)
        self.assertEqual("bar", u.platform_id)

    def test_platform_id_if_from_auth_user(self):
        # AuthUser's should have a fixed value
        u = ScoolUser(id="foo", **self.DEFAULTS)
        self.assertEqual("scool", u.platform_id)

    def test_context_id(self):
        u = ScoolUser(
            id="foo@bar", context={"id": "123", "title": "Math6"}, **self.DEFAULTS
        )
        self.assertEqual(u.context_id, "123")

    def test_context_id_if_from_auth_user(self):
        # AuthUser's should have a fixed value
        u = ScoolUser(id="foo", **self.DEFAULTS)
        self.assertEqual(u.context_id, "scool")

    def test_from_auth_user(self):
        au = AuthUser(
            id="123",
            client_id="test@test.org",
            client_secret_hash="$1$foo.bar",  # noqa: S106
            scopes=["role:developer", "role:editor"],
            context={"id": "123456", "title": "Math6"},
        )
        su = ScoolUser.from_auth_user(au)
        self.assertEqual(su.id, "123")
        self.assertEqual(su.email, "test@test.org")
        self.assertListEqual(su.roles, ["developer", "editor"])
        self.assertDictEqual(su.context, {"id": "123456", "title": "Math6"})
