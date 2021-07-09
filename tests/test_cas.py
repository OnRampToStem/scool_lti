import unittest

from scale_api import cas


class CasTestCase(unittest.TestCase):

    def setUp(self) -> None:
        self.cas_login_url = 'https://cas.fresnostate.edu/login'
        self.cas_validate_url = 'https://cas.fresnostate.edu/serviceValidate'
        self.cas_client = cas.CasClient(
            login_url=self.cas_login_url,
            validate_url=self.cas_validate_url,
        )

    def test_build_login_url(self):
        rv = self.cas_client.build_login_url('https://scale.foo.org/api/v1/messages')
        self.assertEqual(rv, f'{self.cas_login_url}?method=POST&service=https%3A%2F%2Fscale.foo.org%2Fapi%2Fv1%2Fmessages')

    def test_build_validate_url(self):
        rv = self.cas_client.build_validate_url('https://scale.foo.org/api/v1/messages', 'ST-123')
        self.assertEqual(rv, f'{self.cas_validate_url}?service=https%3A%2F%2Fscale.foo.org%2Fapi%2Fv1%2Fmessages&ticket=ST-123')

    def test_parse_valid_response(self):
        s = """
            <cas:serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'>
                <cas:authenticationSuccess>
                    <cas:user>johnwa</cas:user>
                    <cas:attributes>
                        <cas:credentialType>DuoSecurityCredential</cas:credentialType>
                        <cas:credentialType>UsernamePasswordCredential</cas:credentialType>
                        <cas:isFromNewLogin>false</cas:isFromNewLogin>
                        <cas:mail>johnwa@csufresno.edu</cas:mail>
                        <cas:bypassMultifactorAuthentication>false</cas:bypassMultifactorAuthentication>
                        <cas:authenticationDate>2021-07-09T18:56:56.804896Z</cas:authenticationDate>
                        <cas:authenticationMethod>LdapAuthenticationHandler</cas:authenticationMethod>
                        <cas:authenticationMethod>mfa-duo</cas:authenticationMethod>
                        <cas:authnContextClass>mfa-duo</cas:authnContextClass>
                        <cas:successfulAuthenticationHandlers>LdapAuthenticationHandler</cas:successfulAuthenticationHandlers>
                        <cas:successfulAuthenticationHandlers>mfa-duo</cas:successfulAuthenticationHandlers>
                        <cas:longTermAuthenticationRequestTokenUsed>false</cas:longTermAuthenticationRequestTokenUsed>
                        <cas:cn>John Wagenleitner</cas:cn>
                        </cas:attributes>
                </cas:authenticationSuccess>
            </cas:serviceResponse>
        """
        rv = self.cas_client.parse_username(s)
        self.assertEqual(rv, 'johnwa')

    def test_parse_exception_invalid_ticket_response(self):
        s = """
            <cas:serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'>
                <cas:authenticationFailure code="INVALID_TICKET">Ticket &#39;ST-28002-riWUAbDLvBtpyLqQDfvXN-dli9k-ip-10-20-36-238&#39; not recognized</cas:authenticationFailure>
            </cas:serviceResponse>
        """
        with self.assertRaises(cas.CasException) as cas_exc:
            self.cas_client.parse_username(s)
        self.assertEqual('INVALID_TICKET', cas_exc.exception.error_code)

    def test_parse_exception_invalid_service_response(self):
        s = """
            <cas:serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'>
                <cas:authenticationFailure code="INVALID_SERVICE">Ticket &#39;ST-28274-2nFe1E0Mlm0NMZv-H8ATWOw-OZU-ip-10-20-38-235&#39; does not match supplied service. The original service was &#39;https://foo.org&#39; and the supplied service was &#39;https://bar.org&#39;.</cas:authenticationFailure>
            </cas:serviceResponse>
        """
        with self.assertRaises(cas.CasException) as cas_exc:
            self.cas_client.parse_username(s)
        self.assertEqual('INVALID_SERVICE', cas_exc.exception.error_code)
