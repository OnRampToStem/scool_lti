"""
Templating library

Provides HTML rendering using Jinja2 templates.
"""
from pathlib import Path
from typing import Any

from fastapi import Request, Response
from fastapi.templating import Jinja2Templates

TEMPLATE_PATH = Path(__file__).parent / 'templates'

_templates = Jinja2Templates(directory=str(TEMPLATE_PATH))


def render(  # type: ignore[no-untyped-def]
        request: Request,
        template: str,
        context: dict[str, Any] | None = None,
        **kwargs
) -> Response:
    """Returns a Response with the content rendered from a template.

    Renders a `text/html` response using the given template and context. If
    the provided context does not contain the `request` key, one will be
    created using the provided request object.
    """
    if context is None:
        context = {'request': request}
    elif 'request' not in context:
        context['request'] = request
    return _templates.TemplateResponse(
        name=template,
        context=context,
        media_type='text/html',
        **kwargs
    )
