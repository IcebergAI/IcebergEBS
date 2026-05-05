import hmac

from fastapi import HTTPException, Request
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from app.config import settings

_serializer = URLSafeTimedSerializer(settings.secret_key)


def create_session_cookie(username: str) -> str:
    return _serializer.dumps({"u": username})


def verify_credentials(username: str, password: str) -> bool:
    username_ok = hmac.compare_digest(
        username.encode(), settings.admin_username.encode()
    )
    password_ok = hmac.compare_digest(
        password.encode(), settings.admin_password.encode()
    )
    return username_ok and password_ok


def get_current_user(request: Request) -> str | None:
    cookie = request.cookies.get(settings.session_cookie_name)
    if not cookie:
        return None
    try:
        data = _serializer.loads(cookie, max_age=settings.session_max_age)
        return data["u"]
    except (SignatureExpired, BadSignature, KeyError):
        return None


async def require_auth(request: Request) -> str:
    user = get_current_user(request)
    if user is None:
        raise HTTPException(status_code=303, headers={"Location": "/login"})
    return user


def set_session(response, username: str) -> None:
    response.set_cookie(
        key=settings.session_cookie_name,
        value=create_session_cookie(username),
        max_age=settings.session_max_age,
        httponly=True,
        samesite="lax",
    )


def clear_session(response) -> None:
    response.delete_cookie(key=settings.session_cookie_name)
