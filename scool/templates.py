"""
Templating library for HTML Responses
"""

from fastapi import Response


def redirect_lms_auth(target_url: str, token: str) -> Response:
    body = f"""\
    <!doctype html>
    <html lang="en">
    <head><title>SCOOL Launch</title></head>
    <body onload="document.launch.submit()">
        <form style="display: none;" name="launch" method="post" action="{target_url}">
            <input type="hidden" name="token" value="{token}">
        </form>
        <p>Please wait while we transfer you to the page you requested.</p>
        <p>
        Click <a href="#" onclick="document.launch.submit()">here</a>to transfer now.
        </p>
    </body>
    </html>
    """
    return Response(content=body, media_type="text/html")
