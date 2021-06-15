from pathlib import Path

from fastapi import Request, Response
from fastapi.templating import Jinja2Templates

TEMPLATE_PATH = Path(__file__).parent / 'templates'

_templates = Jinja2Templates(directory=str(TEMPLATE_PATH))


def render(request: Request, template: str, context: dict = None, **kwargs) -> Response:
    if context is None:
        context = {'request': request}
    else:
        if 'request' not in context:
            context['request'] = request
    return _templates.TemplateResponse(
        name=template,
        context=context,
        media_type='text/html',
        **kwargs
    )
