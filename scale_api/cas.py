"""
Central Authentication Service (CAS) client
"""
import logging
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

from .aio import http_client

logger = logging.getLogger(__name__)


class CasException(BaseException):
    def __init__(self, error_code: str, *args) -> None:
        super().__init__(error_code, *args)
        self.error_code = error_code


class CasClient:
    CAS_NS = {'cas': 'http://www.yale.edu/tp/cas'}

    def __init__(self, login_url: str, validate_url: str) -> None:
        self.login_url = login_url
        self.validate_url = validate_url

    async def validate(self, service_url: str, ticket: str) -> str:
        target_validate = self.build_validate_url(service_url, ticket)
        logger.debug('CasClient validating %s', target_validate)
        try:
            response = await http_client.get(target_validate)
            response.raise_for_status()
        except Exception as exc:
            raise CasException(repr(exc))
        else:
            cas_response = response.text
            logger.debug('CAS response:\n%s', cas_response)
            return self.parse_username(cas_response)

    def build_login_url(self, service: str) -> str:
        encoded_service = urllib.parse.quote(service)
        return f'{self.login_url}?method=POST&service={encoded_service}'

    def build_validate_url(self, service: str, ticket: str) -> str:
        encoded_service = urllib.parse.quote(service)
        return f'{self.validate_url}?service={encoded_service}&ticket={ticket}'

    def parse_username(self, cas_response: str) -> str:
        root = ET.fromstring(cas_response)
        user_elem = root.find('cas:authenticationSuccess/cas:user', self.CAS_NS)
        if user_elem is not None:
            return user_elem.text
        error_elem = root.find('cas:authenticationFailure', self.CAS_NS)
        if error_elem is not None:
            error_code = error_elem.attrib.get('code', 'UNKNOWN')
            error_text = error_elem.text
            raise CasException(error_code, error_text)
        raise CasException('UNKNOWN')


# TODO: use settings or make dynamic per provider
cas_client = CasClient(
    login_url='https://cas.csufresno.edu/login',
    validate_url='https://cas.csufresno.edu/p3/serviceValidate'
)
