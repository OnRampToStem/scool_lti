import logging
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
    request.session.pop('au', None)
    index_page_url = request.url_for('index_api')
    return RedirectResponse(url=index_page_url, status_code=302)


@router.post('/login', include_in_schema=False)
async def login_post(
        request: Request,
        username: str = Form(...),
        password: str = Form(...),
):
    form_data = await request.form()
    verify_request(request, form_data.get('csrf_token'))
    try:
        auth_user = await db.store.user_by_client_id_async(username)
    except LookupError:
        request.state.login_error = 'Incorrect username or password'
        return await index_api(request)

    if not auth.verify_password(password, auth_user.client_secret_hash):
        request.state.login_error = 'Incorrect username or password'
        return await index_api(request)

    request.session['au'] = auth_user.session_dict()
    index_page_url = request.url_for('index_api')
    return RedirectResponse(url=index_page_url, status_code=302)


@router.get('/token', include_in_schema=False)
async def scale_user_token_session(
        request: Request,
        response: Response,
):
    # TODO: this should return a ScaleUser instead of an AuthUser?
    try:
        auth_user = schemas.AuthUser.parse_obj(request.session['au'])
    except LookupError:
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return {'error': 'Unable to authenticate'}
    else:
        auth_user_token = auth.create_auth_user_token(auth_user)

    return {'token': auth_user_token}


@router.post('/token')
async def scale_user_token_impersonate(
        request: Request,
        response: Response,
        scale_user: schemas.ScaleUserImpersonationRequest,
):
    if app_config.is_production:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    if not scale_user.secret_key.get_secret_value() == app_config.SECRET_KEY:
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return {'error': 'Unable to authenticate'}

    auth_user = schemas.AuthUser(
        id=scale_user.email,
        client_id=scale_user.email,
        client_secret_hash='none',
        scopes=[f'role:{x}' for x in scale_user.roles],
    )

    token = auth.create_auth_user_token(auth_user)
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
    if grant_type != 'client_credentials':
        response.status_code = 400
        return {'error': 'invalid_request'}

    if not client_id or not client_secret:
        basic_auth = await http_basic(request)
        if basic_auth:
            client_id = basic_auth.username
            client_secret = basic_auth.password
        else:
            response.status_code = 400
            return {'error': 'invalid_client'}

    # TODO: verify scope?
    logger.info('oauth_token(scopes=%r)', scope)

    try:
        auth_user = await db.store.user_by_client_id_async(client_id)
    except LookupError:
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return {'error': 'invalid_client'}

    if not auth.verify_password(client_secret, auth_user.client_secret_hash):
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return {'error': 'invalid_client'}

    token = auth.create_auth_user_token(auth_user)
    return {
        'access_token': token,
        'token_type': 'bearer',
        'expires_in': app_config.OAUTH_ACCESS_TOKEN_EXPIRY,
    }


@router.get('/userinfo', response_model=schemas.AuthUser, dependencies=[Depends(auth.authorize)])
def user_info(request: Request):
    return request.state.auth_user


# TODO: indicate what provider (school) this is for so correct target urls can be gotten
@router.get('/cas', include_in_schema=False)
async def cas_login(request: Request, ticket: Optional[str] = None):
    if ticket is not None:
        return await cas_validate(request, ticket)
    # TODO: need to save the sso provider, for now assume Fresno State CAS
    service_url = request.url_for('cas_login')
    cas_login_url = cas.cas_client.build_login_url(service_url)
    logger.info('Redirecting to CAS URL %s', cas_login_url)
    return RedirectResponse(url=cas_login_url)


@router.post('/cas', include_in_schema=False)
async def cas_validate(request: Request, ticket: str = Form(...)):
    service_url = request.url_for('cas_login')
    try:
        cas_user = await cas.cas_client.validate(service_url, ticket)
        auth_user = await db.store.user_by_client_id_async(f'{cas_user}@mail.fresnostate.edu')
    except (LookupError, cas.CasException) as exc:
        logger.error('cas_validate error: %r', exc)
        request.state.sso_error = 'Not authorized'
        return await index_api(request)
    else:
        request.session['au'] = auth_user.session_dict()
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


def verify_request(request: Request, challenge: str) -> None:
    csrf_token = request.session.get('csrf_token')
    pk = auth.ProofKey(csrf_token)
    if not pk.verify(challenge):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)


def build_context(request: Request) -> dict:
    csrf_token = request.session.get('csrf_token')
    pk = auth.ProofKey(csrf_token)
    if csrf_token is None:
        request.session['csrf_token'] = pk.verifier
    return {'csrf_token': pk.challenge}
