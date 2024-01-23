# Student Centered Open Online Learning (SCOOL) LTI Integration
# Copyright (c) 2021-2024  Fresno State University, SCOOL Project Team
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

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
