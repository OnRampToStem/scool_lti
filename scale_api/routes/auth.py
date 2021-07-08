"""
Authentication routes

Provides endpoints for authentication for ``AuthUser`` requests
and token services for ``ScaleUser`` requests.
"""
import logging
import uuid
from typing import Optional

from fastapi import (
    APIRouter,
    Depends,
    Form,
    HTTPException,
    Request,
    Response,
    status,
)
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPBasic

from scale_api import (
    app_config,
    auth,
    cas,
    db,
    schemas,
    templates,
)

logger = logging.getLogger(__name__)

router = APIRouter()

# Use this just for extracting the basic auth for the client_credentials auth
http_basic = HTTPBasic(auto_error=False)


@router.get('/', include_in_schema=False)
async def index_api(request: Request):
    context = build_context(request)
    return templates.render(request, 'index.html', context)


@router.get('/logout', include_in_schema=False)
async def logout(request: Request):
    # TODO: handle SSO logout?
    request.session.clear()
    index_page_url = request.url_for('index_api')
    return RedirectResponse(url=index_page_url, status_code=302)


@router.post('/login', include_in_schema=False)
async def login_post(
        request: Request,
        username: str = Form(...),
        password: str = Form(...),
        csrf_token: str = Form(...),
):
    verify_request(request, csrf_token)
    try:
        auth_user = await db.store.user_by_client_id_async(username)
    except LookupError:
        logger.info('login found no user for: %s', username)
        request.state.login_error = 'Incorrect username or password'
        return await index_api(request)

    if not auth.verify_password(password, auth_user.client_secret_hash):
        logger.error('login invalid password for: %s', username)
        request.state.login_error = 'Incorrect username or password'
        return await index_api(request)

    request.session['au'] = auth_user.session_dict()
    logger.info('Login AuthUser: %s', auth_user)
    index_page_url = request.url_for('index_api')
    return RedirectResponse(url=index_page_url, status_code=302)


@router.get('/token', include_in_schema=False)
async def session_user_token(
        request: Request,
        response: Response,
):
    """The ``ScaleUser`` token endpoint.

    This endpoint provides authentication tokens to the front-end
    webapp. The ``ScaleUser`` is stored in the web session so this
    requires that the request be generated from the same origin or
    if from cross-origin that ``withCredentials`` be specified in
    the xhr call.

    If a ``ScaleUser`` has not previously be set in the web session
    from an LTI launch, then an ``AuthUser`` will be returned if one
    is present in the web session.
    """
    session_user = request.session.get('scale_user')
    if session_user:
        scale_user = schemas.ScaleUser.parse_obj(session_user)
        logger.info('token request found ScaleUser: %s', scale_user)
    else:
        session_user = request.session.get('au')
        if not session_user:
            logger.error('token request no AuthUser found')
            response.status_code = status.HTTP_401_UNAUTHORIZED
            return {'error': 'Unable to authenticate'}
        auth_user = schemas.AuthUser.parse_obj(session_user)
        scale_user = schemas.ScaleUser.from_auth_user(auth_user)
        logger.info('token request found AuthUser: %s', auth_user)
        logger.info('token request return ScaleUser: %s', scale_user)

    user_token = auth.create_scale_user_token(scale_user)
    return {'token': user_token}


@router.post('/token')
async def scale_user_token_impersonate(
        request: Request,
        response: Response,
        scale_user_request: schemas.ScaleUserImpersonationRequest,
):
    """The ``ScaleUser`` impersonation token endpoint.

    This endpoint provides authentication tokens to the front-end
    webapp in non-production mode. This allows the developer to
    provide, via POST'd json payload, the values that they want
    the returned ``ScaleUser`` token to contain.
    """
    if app_config.is_production:
        logger.error('token impersonate called in production mode')
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    if not scale_user_request.secret_key.get_secret_value() == app_config.SECRET_KEY:
        logger.error('token impersonate invalid secret key: %s',
                     scale_user_request.secret_key.get_secret_value())
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return {'error': 'Unable to authenticate'}

    scale_user = schemas.ScaleUser(
        id=scale_user_request.id,
        email=scale_user_request.email,
        roles=scale_user_request.roles,
        context=scale_user_request.context,
    )

    request.session['scale_user'] = scale_user.session_dict()
    token = auth.create_scale_user_token(scale_user)
    logger.info('Return token impersonate for ScaleUser: %s', scale_user)
    return {
        'token': token,
    }


@router.post('/oauth/token')
async def oauth_token(
        request: Request,
        response: Response,
        grant_type: str = Form(...),
        scope: Optional[str] = Form(None),
        client_id: Optional[str] = Form(None),
        client_secret: Optional[str] = Form(None),
):
    """OAuth 2.0 Token Endpoint.

    This endpoint supports the ``client_credentials`` grant type and is
    used in order to authenticate ``AuthUser`` clients for API calls.
    """
    if grant_type != 'client_credentials':
        logger.error('oauth token unsupported grant_type [%s] requested',
                     grant_type)
        response.status_code = 400
        return {'error': 'invalid_request'}

    if not client_id or not client_secret:
        basic_auth = await http_basic(request)
        if basic_auth:
            client_id = basic_auth.username
            client_secret = basic_auth.password
        else:
            logger.error('oauth token request missing credentials')
            response.status_code = 400
            return {'error': 'invalid_client'}

    # TODO: verify scope?
    logger.info('oauth_token(scopes=%r)', scope)

    try:
        auth_user = await db.store.user_by_client_id_async(client_id)
    except LookupError:
        logger.error('oauth token client not found: %s', client_id)
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return {'error': 'invalid_client'}

    if not auth.verify_password(client_secret, auth_user.client_secret_hash):
        logger.error('oauth token invalid password AuthUser: %s', auth_user)
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return {'error': 'invalid_client'}

    token = auth.create_auth_user_token(auth_user)
    logger.info('Return token for AuthUser: %s', auth_user)
    return {
        'access_token': token,
        'token_type': 'bearer',
        'expires_in': app_config.OAUTH_ACCESS_TOKEN_EXPIRY,
    }


@router.get('/userinfo', dependencies=[Depends(auth.authorize)])
def user_info(request: Request):
    """User Info endpoint."""
    scale_user = request.session.get('scale_user')
    if scale_user is not None:
        return scale_user
    return request.state.auth_user


# TODO: indicate what provider (school) this is for so correct target urls can be gotten
@router.get('/cas', include_in_schema=False)
async def cas_login(request: Request, ticket: Optional[str] = None):
    """CAS login."""
    if ticket is not None:
        return await cas_validate(request, ticket)
    # TODO: need to save the sso provider, for now assume Fresno State CAS
    service_url = request.url_for('cas_login')
    cas_login_url = cas.cas_client.build_login_url(service_url)
    logger.info('Redirecting to CAS URL %s', cas_login_url)
    return RedirectResponse(url=cas_login_url)


@router.post('/cas', include_in_schema=False)
async def cas_validate(request: Request, ticket: str = Form(...)):
    """CAS Ticket Validation."""
    service_url = request.url_for('cas_login')
    try:
        cas_user = await cas.cas_client.validate(service_url, ticket)
        # TODO: we should be able to pull email from the response,
        # TODO: or we should store the user suffix per sso provider
        auth_user = await db.store.user_by_client_id_async(f'{cas_user}@mail.fresnostate.edu')
    except (LookupError, cas.CasException) as exc:
        logger.error('cas_validate error: %r', exc)
        request.state.sso_error = 'Not authorized'
        return await index_api(request)
    else:
        request.session['au'] = auth_user.session_dict()
        logger.info('CAS AuthUser: %s', auth_user)
        index_page_url = request.url_for('index_api')
        return RedirectResponse(url=index_page_url, status_code=302)


# TODO: handle CAS logout?

@router.get('/forgot-password', include_in_schema=False)
async def forgot_password(request: Request):
    context = build_context(request)
    return templates.render(request, 'forgot_password.html', context)


@router.post('/forgot-password', include_in_schema=False)
async def forgot_password_email(request: Request):
    form_data = await request.form()
    verify_request(request, form_data.get('csrf_token'))
    # TODO: generate one-time-password and email it
    return await reset_password(request)


@router.get('/reset-password', include_in_schema=False)
async def reset_password(request: Request):
    context = build_context(request)
    return templates.render(request, 'reset_password.html', context)


@router.post('/reset-password', include_in_schema=False)
async def reset_password_change(request: Request):
    form_data = await request.form()
    verify_request(request, form_data.get('csrf_token'))
    return {'p': 'post.reset_password_change'}


def verify_request(request: Request, form_token: str) -> None:
    """Verifies the CSRF form token matches the token stored in the web session."""
    csrf_token = request.session.get('csrf_token')
    if not csrf_token or form_token != csrf_token:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)


def build_context(request: Request) -> dict:
    """Provides a CSRF token for use in a template.

    Returns the CSRF token from the web session if one exists. Else
    generates a new token and sets it in the web session.
    """
    csrf_token = request.session.get('csrf_token')
    if csrf_token is None:
        request.session['csrf_token'] = csrf_token = uuid.uuid4().hex
    return {
        'app_config': app_config,
        'csrf_token': csrf_token,
    }
