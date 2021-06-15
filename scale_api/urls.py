import urllib.parse
from typing import Dict, Tuple


def parse(url: str) -> Tuple[urllib.parse.ParseResult, Dict[str, str]]:
    parsed = urllib.parse.urlparse(url)
    params = {}
    if qs := parsed.query:
        for param in qs.split('&'):
            parts = param.split('=')
            if len(parts) == 2:
                params[parts[0]] = urllib.parse.unquote_plus(parts[1])
            elif len(parts) == 1:
                params[parts[0]] = None
            else:
                raise ValueError(f'Invalid querystring param: {param}')
    return parsed, params


def base_url(parsed_url: urllib.parse.ParseResult) -> str:
    url = f'{parsed_url.scheme}://{parsed_url.hostname}'
    if parsed_url.port:
        url += f':{parsed_url.port}'
    url += parsed_url.path
    return url
