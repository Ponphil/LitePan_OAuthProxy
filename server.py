from fastapi import APIRouter, HTTPException, Request, Query, Form
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from typing import Dict, Any, Optional
import asyncio
import uuid
import json
import base64
import os
import secrets
import hmac
import hashlib
from datetime import datetime, timedelta, date
from drivers import get_oauth_driver
from config import OAuthConfig
from drivers.guangyapan import GuangYaPanAuthDriver
from stats import stats

router = APIRouter()
templates = Jinja2Templates(directory="templates")

# 会话存储（生产环境建议使用Redis）
oauth_sessions: Dict[str, Dict] = {}


GUANGYAPAN_DRIVER_TYPES = {"光鸭云盘", "GuangYaPan", "guangyapan"}


def get_external_base_url(request: Request) -> str:
    return os.getenv("EXTERNAL_URL", str(request.base_url).rstrip("/")).rstrip("/")


# === 统计鉴权与展示辅助 ===

DRIVER_DISPLAY_NAMES = {
    "115": "115网盘Open",
    "baidu": "百度网盘Open",
    "123": "123云盘Open",
    "onedrive": "OneDrive",
    "guangyapan": "光鸭云盘",
    "xunlei": "迅雷云盘",
}

ACTION_LABELS = {
    "authorize": "发起授权",
    "token_exchange": "换取 Token",
    "refresh": "刷新 Token",
    "send_sms": "发送短信",
}

ACTION_COLORS = {
    "authorize": "blue",
    "token_exchange": "green",
    "refresh": "orange",
    "send_sms": "purple",
}

STATS_COOKIE_NAME = "stats_session"


def stats_password() -> str:
    """统计访问口令：STATS_PASSWORD 优先，未配置时默认 000000（请尽快改成复杂密码）。"""
    return os.getenv("STATS_PASSWORD", "").strip() or "000000"


def check_stats_token(value: str) -> bool:
    expected = stats_password()
    return bool(expected and secrets.compare_digest(value, expected))


def verify_stats_request(request: Request) -> bool:
    """统计接口鉴权：支持登录 Cookie / Basic / Bearer / ?token= 四种方式。"""
    cookie = request.cookies.get(STATS_COOKIE_NAME, "")
    if cookie and verify_stats_cookie(cookie):
        return True
    token = request.query_params.get("token", "")
    if token and check_stats_token(token):
        return True
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("basic "):
        try:
            decoded = base64.b64decode(auth.split(" ", 1)[1]).decode("utf-8")
        except Exception:
            return False
        _, _, pw = decoded.partition(":")
        return check_stats_token(pw)
    if auth.lower().startswith("bearer "):
        return check_stats_token(auth.split(" ", 1)[1].strip())
    return False


def _stats_cookie_secret() -> str:
    return os.getenv("STATS_SECRET", "").strip() or stats_password()


def make_stats_cookie() -> str:
    payload = secrets.token_hex(16)
    sig = hmac.new(_stats_cookie_secret().encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{sig}"


def verify_stats_cookie(value: str) -> bool:
    try:
        payload, sig = value.rsplit(".", 1)
    except (ValueError, AttributeError):
        return False
    expected = hmac.new(_stats_cookie_secret().encode(), payload.encode(), hashlib.sha256).hexdigest()
    return secrets.compare_digest(sig, expected)


def require_stats_auth(request: Request):
    if not verify_stats_request(request):
        raise HTTPException(
            status_code=401,
            detail="需要统计访问口令（Basic / Bearer / ?token=）",
            headers={"WWW-Authenticate": 'Basic realm="oauth-stats"'},
        )


def _aggregate_window(daily: Dict[str, Dict[str, Dict[str, int]]]) -> Dict[str, Dict[str, int]]:
    """把筛选窗口内的每日明细聚合为 {driver: {action: count}}。"""
    agg: Dict[str, Dict[str, int]] = {}
    for day_drivers in daily.values():
        for driver, actions in day_drivers.items():
            a = agg.setdefault(driver, {})
            for action, count in actions.items():
                a[action] = a.get(action, 0) + count
    return agg


def _sum_counts(mapping: Dict[str, Dict[str, int]]) -> int:
    return sum(sum(actions.values()) for actions in mapping.values())


def _driver_name(key: str) -> str:
    return DRIVER_DISPLAY_NAMES.get(key, key)


def _action_label(action: str) -> str:
    return ACTION_LABELS.get(action, action)


def using_default_stats_password() -> bool:
    return not os.getenv("STATS_PASSWORD", "").strip() and stats_password() == "000000"


def is_guangyapan_driver(driver_type: str) -> bool:
    return (driver_type or "").strip() in GUANGYAPAN_DRIVER_TYPES


def get_guangyapan_driver() -> GuangYaPanAuthDriver:
    return GuangYaPanAuthDriver({})


def build_guangyapan_login_url(request: Request, session_id: str) -> str:
    return f"{get_external_base_url(request)}/guangyapan/login?session_id={session_id}"


def build_popup_callback_url(request: Request, session_id: str) -> str:
    return f"{get_external_base_url(request)}/callback-popup?state={session_id}"


def build_oauth_callback_url(request: Request, _driver_type: str = "") -> str:
    return f"{get_external_base_url(request)}/callback-popup"


def render_oauth_result(request: Request, session: Dict[str, Any], success: bool,
                        token_data: Optional[Dict[str, Any]] = None,
                        error: Optional[str] = None,
                        session_id: Optional[str] = None):
    if is_popup_flow(session):
        return templates.TemplateResponse(request=request, name="oauth_callback_popup.html", context={
            "request": request,
            "success": success,
            "token_data": token_data,
            "driver_type": session.get("driver_type"),
            "error": error,
            "session_id": session_id
        })

    return templates.TemplateResponse(request=request, name="oauth_callback.html", context={
        "request": request,
        "success": success,
        "token_data": token_data,
        "driver_type": session.get("driver_type"),
        "error": error
    })


def build_guangyapan_form_data(session: Optional[Dict[str, Any]]) -> Dict[str, str]:
    session = session or {}
    return {
        "phone_number": session.get("phone_number", ""),
        "verification_id": session.get("verification_id", ""),
        "captcha_token": session.get("captcha_token", ""),
        "device_id": session.get("device_id", ""),
    }


def is_popup_flow(session: Optional[Dict[str, Any]]) -> bool:
    if not session:
        return False
    return session.get("source") in {"api", "quick_auth", "quick_start"}


class OAuthProxyServer:
    def __init__(self):
        self.config = OAuthConfig()
        self.cleanup_task = None

    async def start_cleanup_task(self):
        """启动会话清理任务"""
        self.cleanup_task = asyncio.create_task(self._cleanup_expired_sessions())

    async def _cleanup_expired_sessions(self):
        """定期清理过期会话"""
        while True:
            try:
                now = datetime.now()
                expired_sessions = [
                    session_id for session_id, session in oauth_sessions.items()
                    if session.get('expires_at', now) < now
                ]
                for session_id in expired_sessions:
                    oauth_sessions.pop(session_id, None)
                await asyncio.sleep(300)  # 每5分钟清理一次
            except Exception as e:
                print(f"清理会话失败: {e}")
                await asyncio.sleep(60)


oauth_proxy = OAuthProxyServer()


# === 网页界面路由 ===
@router.get("/", response_class=HTMLResponse)
async def oauth_index(request: Request):
    """OAuth获取工具主页面"""
    return templates.TemplateResponse(request=request, name="oauth_index.html", context={
        "request": request,
        "drivers": oauth_proxy.config.get_supported_drivers()
    })


@router.post("/start")
async def start_oauth_web(request: Request,
                          driver_type: str = Form(...),
                          server_use: bool = Form(False),
                          client_id: Optional[str] = Form(None),
                          client_secret: Optional[str] = Form(None)):
    """网页版：开始OAuth授权流程"""
    try:
        # 生成会话ID
        session_id = str(uuid.uuid4())

        if is_guangyapan_driver(driver_type):
            oauth_sessions[session_id] = {
                "driver_type": "光鸭云盘",
                "server_use": True,
                "client_id": None,
                "client_secret": None,
                "created_at": datetime.now(),
                "expires_at": datetime.now() + timedelta(minutes=15),
                "status": "pending",
                "source": "web",
                "phone_number": "",
                "verification_id": "",
                "captcha_token": "",
                "device_id": "",
            }
            stats.record("guangyapan", "authorize")
            return RedirectResponse(url=build_guangyapan_login_url(request, session_id), status_code=302)

        # 获取OAuth驱动
        oauth_driver = get_oauth_driver(driver_type)
        if not oauth_driver:
            raise HTTPException(status_code=400, detail=f"不支持的驱动类型: {driver_type}")

        callback_url = build_oauth_callback_url(request, driver_type)

        # 构建OAuth URL
        if server_use:
            # 使用内置凭据
            oauth_url = await oauth_driver.get_auth_url(
                session_id=session_id,
                callback_url=callback_url,
                use_builtin_credentials=True
            )
        else:
            # 使用用户提供的凭据
            if not client_id or not client_secret:
                raise HTTPException(status_code=400, detail="请提供Client ID和Client Secret")
            oauth_url = await oauth_driver.get_auth_url(
                session_id=session_id,
                callback_url=callback_url,
                client_id=client_id,
                client_secret=client_secret
            )

        # 存储会话信息
        oauth_sessions[session_id] = {
            "driver_type": driver_type,
            "server_use": server_use,
            "client_id": client_id,
            "client_secret": client_secret,
            "callback_url": callback_url,
            "created_at": datetime.now(),
            "expires_at": datetime.now() + timedelta(minutes=10),
            "status": "pending",
            "source": "web"
        }

        stats.record(driver_type, "authorize")
        return RedirectResponse(url=oauth_url, status_code=302)

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"启动OAuth失败: {str(e)}")


@router.get("/callback")
async def oauth_callback_legacy(request: Request):
    """旧 OAuth 回调地址兼容入口，统一转交给 /callback-popup 处理。"""
    target_url = f"{get_external_base_url(request)}/callback-popup"
    if request.url.query:
        target_url = f"{target_url}?{request.url.query}"
    return RedirectResponse(url=target_url, status_code=302)


# === API接口路由 ===
# 添加请求模型
class OAuthStartRequest(BaseModel):
    driver_type: str
    callback_url: str
    server_use: bool = True
    client_id: Optional[str] = None
    client_secret: Optional[str] = None


class OAuthRefreshRequest(BaseModel):
    driver_type: str
    refresh_token: str


@router.get("/guangyapan/login", response_class=HTMLResponse)
async def guangyapan_login_page(
    request: Request,
    session_id: str = Query(...),
    message: Optional[str] = Query(None),
    message_type: str = Query("info"),
):
    session = oauth_sessions.get(session_id)
    if not session:
        return templates.TemplateResponse(request=request, name="oauth_error.html", context={
            "request": request,
            "error": "会话不存在或已过期"
        })

    return templates.TemplateResponse(request=request, name="guangyapan_login.html", context={
        "request": request,
        "session_id": session_id,
        "message": message,
        "message_type": message_type,
        "form_data": build_guangyapan_form_data(session),
    })


@router.post("/guangyapan/login", response_class=HTMLResponse)
async def guangyapan_login_submit(
    request: Request,
    session_id: str = Form(...),
    action: str = Form(...),
    phone_number: str = Form(""),
    verify_code: str = Form(""),
    verification_id: str = Form(""),
    captcha_token: str = Form(""),
    device_id: str = Form(""),
):
    session = oauth_sessions.get(session_id)
    if not session:
        return templates.TemplateResponse(request=request, name="oauth_error.html", context={
            "request": request,
            "error": "会话不存在或已过期"
        })

    driver = get_guangyapan_driver()
    phone_number = (phone_number or "").strip()
    verify_code = (verify_code or "").strip()
    verification_id = (verification_id or "").strip() or session.get("verification_id", "")
    captcha_token = (captcha_token or "").strip() or session.get("captcha_token", "")
    device_id = (device_id or "").strip() or session.get("device_id", "")

    session["phone_number"] = phone_number
    if verification_id:
        session["verification_id"] = verification_id
    if captcha_token:
        session["captcha_token"] = captcha_token
    if device_id:
        session["device_id"] = device_id

    try:
        if action == "send_code":
            result = await driver.prepare_sms_code(phone_number, device_id=device_id)
            session["phone_number"] = result["phone_number"]
            session["verification_id"] = result["verification_id"]
            session["captcha_token"] = result["captcha_token"]
            session["device_id"] = result["device_id"]
            session["status"] = "pending"
            session["expires_at"] = datetime.now() + timedelta(minutes=15)

            stats.record("guangyapan", "send_sms")
            return templates.TemplateResponse(request=request, name="guangyapan_login.html", context={
                "request": request,
                "session_id": session_id,
                "message": "验证码已发送，请填写收到的短信验证码并点击“验证并获取 Token”。",
                "message_type": "success",
                "form_data": build_guangyapan_form_data(session),
            })

        if action == "login":
            token_data = await driver.login_by_sms_code(
                phone_number=phone_number,
                verify_code=verify_code,
                verification_id=verification_id,
                captcha_token=captcha_token,
                device_id=device_id,
            )
            session["status"] = "success"
            session["token_data"] = token_data
            session["completed_at"] = datetime.now()
            session["driver_type"] = "光鸭云盘"
            session["verification_id"] = ""

            stats.record("guangyapan", "token_exchange")
            if is_popup_flow(session):
                session["popup_confirmed"] = False
                return RedirectResponse(url=build_popup_callback_url(request, session_id), status_code=303)

            return templates.TemplateResponse(request=request, name="oauth_callback.html", context={
                "request": request,
                "success": True,
                "token_data": token_data,
                "driver_type": "光鸭云盘"
            })

        raise Exception("不支持的操作类型")

    except Exception as e:
        session["status"] = "error"
        session["error"] = str(e)
        return templates.TemplateResponse(request=request, name="guangyapan_login.html", context={
            "request": request,
            "session_id": session_id,
            "message": str(e),
            "message_type": "error",
            "form_data": build_guangyapan_form_data(session),
        })

@router.post("/api/oauth/start")
async def start_oauth_api(request: Request, oauth_request: OAuthStartRequest):
    """API版：开始OAuth授权流程"""
    # 生成会话ID
    session_id = str(uuid.uuid4())
    
    try:
        print(f"🔄 OAuth启动请求 - Session: {session_id}, Driver: {oauth_request.driver_type}, Source: {request.client.host if request.client else 'unknown'}")

        if is_guangyapan_driver(oauth_request.driver_type):
            oauth_sessions[session_id] = {
                "driver_type": "光鸭云盘",
                "server_use": True,
                "client_id": None,
                "client_secret": None,
                "callback_url": build_guangyapan_login_url(request, session_id),
                "created_at": datetime.now(),
                "expires_at": datetime.now() + timedelta(minutes=15),
                "status": "pending",
                "source": "api",
                "phone_number": "",
                "verification_id": "",
                "captcha_token": "",
                "device_id": "",
            }
            stats.record("guangyapan", "authorize")
            return JSONResponse(content={
                "success": True,
                "data": {
                    "session_id": session_id,
                    "oauth_url": build_guangyapan_login_url(request, session_id),
                    "expires_in": 900
                }
            })
        
        # 获取OAuth驱动
        oauth_driver = get_oauth_driver(oauth_request.driver_type)
        if not oauth_driver:
            error_msg = f"不支持的驱动类型: {oauth_request.driver_type}"
            print(f"❌ OAuth启动失败 - {error_msg}")
            # 先创建会话，再设置错误状态
            oauth_sessions[session_id] = {
                "driver_type": oauth_request.driver_type,
                "server_use": oauth_request.server_use,
                "client_id": oauth_request.client_id,
                "client_secret": oauth_request.client_secret,
                "callback_url": oauth_request.callback_url,
                "created_at": datetime.now(),
                "expires_at": datetime.now() + timedelta(minutes=10),
                "status": "error",
                "error": error_msg,
                "source": "api"
            }
            return JSONResponse(content={
                "success": True,
                "data": {
                    "session_id": session_id,
                    "oauth_url": None,
                    "expires_in": 600
                }
            })

        # 标准 OAuth 统一使用 popup 回调，由 /callback-popup 按 source 分流展示。
        if oauth_request.callback_url and (
            oauth_request.callback_url.endswith("/callback")
            or oauth_request.callback_url.endswith("/callback-popup")
        ):
            callback_url = f"{get_external_base_url(request)}/callback-popup"
        else:
            callback_url = build_oauth_callback_url(request, oauth_request.driver_type)
        
        print(f"🔗 使用回调URL: {callback_url}")
        
        # 构建OAuth URL
        if oauth_request.server_use:
            oauth_url = await oauth_driver.get_auth_url(
                session_id=session_id,
                callback_url=callback_url,
                use_builtin_credentials=True
            )
            print(f"🔐 使用内置凭据生成OAuth URL")
        else:
            if not oauth_request.client_id or not oauth_request.client_secret:
                error_msg = "请提供Client ID和Client Secret"
                print(f"❌ OAuth启动失败 - {error_msg}")
                # 先创建会话，再设置错误状态
                oauth_sessions[session_id] = {
                    "driver_type": oauth_request.driver_type,
                    "server_use": oauth_request.server_use,
                    "client_id": oauth_request.client_id,
                    "client_secret": oauth_request.client_secret,
                    "callback_url": callback_url,
                    "created_at": datetime.now(),
                    "expires_at": datetime.now() + timedelta(minutes=10),
                    "status": "error",
                    "error": error_msg,
                    "source": "api"
                }
                return JSONResponse(content={
                    "success": True,
                    "data": {
                        "session_id": session_id,
                        "oauth_url": None,
                        "expires_in": 600
                    }
                })
            oauth_url = await oauth_driver.get_auth_url(
                session_id=session_id,
                callback_url=callback_url,
                client_id=oauth_request.client_id,
                client_secret=oauth_request.client_secret
            )
            print(f"🔑 使用用户凭据生成OAuth URL")

        # 存储会话信息
        oauth_sessions[session_id] = {
            "driver_type": oauth_request.driver_type,
            "server_use": oauth_request.server_use,
            "client_id": oauth_request.client_id,
            "client_secret": oauth_request.client_secret,
            "callback_url": callback_url,  # 使用实际的回调URL
            "created_at": datetime.now(),
            "expires_at": datetime.now() + timedelta(minutes=10),
            "status": "pending",
            "source": "api"
        }

        print(f"✅ OAuth会话创建成功 - Session: {session_id}")
        stats.record(oauth_request.driver_type, "authorize")

        return JSONResponse(content={
            "success": True,
            "data": {
                "session_id": session_id,
                "oauth_url": oauth_url,
                "expires_in": 600  # 10分钟
            }
        })

    except Exception as e:
        error_msg = str(e)
        print(f"❌ OAuth启动异常 - Session: {session_id}, Error: {error_msg}")
        
        # 决定回调URL（异常处理中也要保持一致）
        if oauth_request.callback_url and (
            oauth_request.callback_url.endswith("/callback")
            or oauth_request.callback_url.endswith("/callback-popup")
        ):
            callback_url = f"{get_external_base_url(request)}/callback-popup"
        else:
            callback_url = build_oauth_callback_url(request, oauth_request.driver_type)
            
        # 确保会话被创建并设置错误状态
        oauth_sessions[session_id] = {
            "driver_type": oauth_request.driver_type,
            "server_use": oauth_request.server_use,
            "client_id": oauth_request.client_id,
            "client_secret": oauth_request.client_secret,
            "callback_url": callback_url,
            "created_at": datetime.now(),
            "expires_at": datetime.now() + timedelta(minutes=10),
            "status": "error",
            "error": error_msg,
            "source": "api"
        }
        return JSONResponse(content={
            "success": True,
            "data": {
                "session_id": session_id,
                "oauth_url": None,
                "expires_in": 600
            }
        })


@router.get("/api/oauth/status/{session_id}")
async def check_oauth_status(session_id: str):
    """API版：检查OAuth状态"""
    session = oauth_sessions.get(session_id)
    if not session:
        print(f"❌ OAuth状态查询失败 - Session不存在: {session_id}")
        return JSONResponse(
            status_code=404,
            content={"success": False, "message": "会话不存在或已过期"}
        )

    print(f"🔍 OAuth状态查询 - Session: {session_id}, Status: {session['status']}")
    
    # 如果是错误状态，输出详细错误信息
    if session.get('status') == 'error':
        print(f"📋 错误详情: {session.get('error', 'Unknown error')}")
    elif session.get('status') == 'success':
        print(f"✅ Token获取成功 - Session: {session_id}")

    return JSONResponse(content={
        "success": True,
        "data": {
            "status": session["status"],
            "token_data": session.get("token_data"),
            "error": session.get("error")
        }
    })


@router.post("/api/oauth/refresh")
async def refresh_oauth_token(oauth_request: OAuthRefreshRequest):
    """API版：使用refresh_token刷新访问令牌"""
    try:
        if is_guangyapan_driver(oauth_request.driver_type):
            token_data = await get_guangyapan_driver().refresh_token(oauth_request.refresh_token)
            stats.record("guangyapan", "refresh")
            return JSONResponse(content={
                "success": True,
                "data": token_data
            })

        oauth_driver = get_oauth_driver(oauth_request.driver_type)
        if not oauth_driver:
            return JSONResponse(
                status_code=400,
                content={"success": False, "message": f"不支持的驱动类型: {oauth_request.driver_type}"}
            )

        token_data = await oauth_driver.refresh_token(oauth_request.refresh_token)
        stats.record(oauth_request.driver_type, "refresh")
        return JSONResponse(content={
            "success": True,
            "data": token_data
        })
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"success": False, "message": f"刷新Token失败: {str(e)}"}
        )


# 在文件末尾添加新的API接口

@router.post("/api/oauth/quick-auth")
async def quick_oauth_auth(request: Request,
                          driver_type: str,
                          server_use: bool = True):
    """快速OAuth认证接口 - 用于前端按钮调用"""
    try:
        # 生成会话ID
        session_id = str(uuid.uuid4())

        if is_guangyapan_driver(driver_type):
            oauth_sessions[session_id] = {
                "driver_type": "光鸭云盘",
                "server_use": True,
                "callback_url": build_guangyapan_login_url(request, session_id),
                "created_at": datetime.now(),
                "expires_at": datetime.now() + timedelta(minutes=15),
                "status": "pending",
                "source": "quick_auth",
                "phone_number": "",
                "verification_id": "",
                "captcha_token": "",
                "device_id": "",
            }
            stats.record("guangyapan", "authorize")
            return JSONResponse(content={
                "success": True,
                "data": {
                    "session_id": session_id,
                    "oauth_url": build_guangyapan_login_url(request, session_id),
                    "expires_in": 900
                }
            })
        
        # 获取OAuth驱动
        oauth_driver = get_oauth_driver(driver_type)
        if not oauth_driver:
            return JSONResponse(
                status_code=400,
                content={"success": False, "message": f"不支持的驱动类型: {driver_type}"}
            )
        
        # 构建OAuth URL（使用内置凭据）
        oauth_url = await oauth_driver.get_auth_url(
            session_id=session_id,
            callback_url=f"{get_external_base_url(request)}/callback-popup",
            use_builtin_credentials=True
        )
        
        # 存储会话信息
        oauth_sessions[session_id] = {
            "driver_type": driver_type,
            "server_use": server_use,
            "callback_url": f"{get_external_base_url(request)}/callback-popup",
            "created_at": datetime.now(),
            "expires_at": datetime.now() + timedelta(minutes=10),
            "status": "pending",
            "source": "quick_auth"
        }

        stats.record(driver_type, "authorize")
        return JSONResponse(content={
            "success": True,
            "data": {
                "session_id": session_id,
                "oauth_url": oauth_url,
                "expires_in": 600
            }
        })
        
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"success": False, "message": f"启动OAuth失败: {str(e)}"}
        )


@router.get("/callback-popup")
async def oauth_callback_popup(request: Request,
                               code: Optional[str] = Query(None),
                               state: str = Query(...)):
    """OAuth回调处理 - 弹窗模式（用于主程序集成）"""
    try:
        session = oauth_sessions.get(state)
        if not session:
            return templates.TemplateResponse(request=request, name="oauth_callback_popup.html", context={
                "request": request,
                "success": False,
                "error": "会话不存在或已过期",
                "session_id": state
            })

        if is_guangyapan_driver(session.get("driver_type")):
            if session.get("status") == "success" and session.get("token_data"):
                session["popup_confirmed"] = False
                print(f"✅ 光鸭云盘认证成功 - Session: {state}, 等待主程序确认")
                return templates.TemplateResponse(request=request, name="oauth_callback_popup.html", context={
                    "request": request,
                    "success": True,
                    "token_data": session["token_data"],
                    "driver_type": session["driver_type"],
                    "session_id": state
                })

            return templates.TemplateResponse(request=request, name="oauth_callback_popup.html", context={
                "request": request,
                "success": False,
                "error": session.get("error") or "光鸭云盘认证尚未完成",
                "session_id": state
            })

        if not code:
            return render_oauth_result(
                request=request,
                session=session,
                success=False,
                error="缺少授权码",
                session_id=state
            )

        # 获取OAuth驱动
        oauth_driver = get_oauth_driver(session["driver_type"])
        if not oauth_driver:
            return render_oauth_result(
                request=request,
                session=session,
                success=False,
                error="不支持的驱动类型",
                session_id=state
            )

        callback_url = session.get("callback_url") or f"{get_external_base_url(request)}/callback-popup"

        # 交换授权码获取Token
        if session["server_use"]:
            token_data = await oauth_driver.exchange_code_for_token(
                code=code,
                callback_url=callback_url,
                use_builtin_credentials=True
            )
        else:
            token_data = await oauth_driver.exchange_code_for_token(
                code=code,
                callback_url=callback_url,
                client_id=session["client_id"],
                client_secret=session["client_secret"]
            )

        # 更新会话状态
        session["status"] = "success"
        session["token_data"] = token_data
        session["completed_at"] = datetime.now()
        if is_popup_flow(session):
            session["popup_confirmed"] = False  # 添加确认状态标记

        stats.record(session["driver_type"], "token_exchange")
        if is_popup_flow(session):
            print(f"✅ OAuth认证成功 - Session: {state}, 等待主程序确认")
        else:
            print(f"✅ OAuth认证成功 - Session: {state}, 显示网页结果")

        return render_oauth_result(
            request=request,
            session=session,
            success=True,
            token_data=token_data,
            session_id=state
        )

    except Exception as e:
        # 更新会话状态为失败
        if state in oauth_sessions:
            oauth_sessions[state]["status"] = "error" 
            oauth_sessions[state]["error"] = str(e)

        print(f"❌ OAuth认证失败 - Session: {state}, Error: {str(e)}")

        session = oauth_sessions.get(state)
        if session:
            return render_oauth_result(
                request=request,
                session=session,
                success=False,
                error=str(e),
                session_id=state
            )

        return templates.TemplateResponse(request=request, name="oauth_callback_popup.html", context={
            "request": request,
            "success": False,
            "error": str(e),
            "session_id": state
        })


@router.get("/api/oauth/check-service")
async def check_oauth_service():
    """检查OAuth代理服务状态"""
    return JSONResponse(content={
        "success": True,
        "data": {
            "status": "running",
            "supported_drivers": oauth_proxy.config.get_supported_drivers()
        }
    })


@router.get("/api/oauth/popup-status/{session_id}")
async def check_popup_status(session_id: str):
    """检查弹窗确认状态"""
    session = oauth_sessions.get(session_id)
    if not session:
        return JSONResponse(
            status_code=404,
            content={"success": False, "message": "会话不存在或已过期"}
        )

    return JSONResponse(content={
        "success": True,
        "data": {
            "confirmed": session.get("popup_confirmed", False),
            "status": session["status"]
        }
    })


@router.post("/api/oauth/confirm-received/{session_id}")
async def confirm_token_received(session_id: str):
    """主程序确认已收到Token"""
    session = oauth_sessions.get(session_id)
    if not session:
        return JSONResponse(
            status_code=404,
            content={"success": False, "message": "会话不存在或已过期"}
        )

    # 标记为已确认
    session["popup_confirmed"] = True
    session["confirmed_at"] = datetime.now()
    
    print(f"🎯 主程序确认收到Token - Session: {session_id}")

    return JSONResponse(content={
        "success": True,
        "data": {
            "message": "确认状态已更新"
        }
    })

# 在文件末尾添加新的快速启动路由

@router.get("/quick-start")
async def quick_start_oauth(request: Request,
                           driver_type: str = Query(...),
                           server_use: bool = Query(True)):
    """快速启动OAuth - 通过URL参数直接启动"""
    try:
        # 生成会话ID
        session_id = str(uuid.uuid4())
        
        print(f"🚀 快速OAuth启动 - Session: {session_id}, Driver: {driver_type}")

        if is_guangyapan_driver(driver_type):
            oauth_sessions[session_id] = {
                "driver_type": "光鸭云盘",
                "server_use": True,
                "callback_url": build_guangyapan_login_url(request, session_id),
                "created_at": datetime.now(),
                "expires_at": datetime.now() + timedelta(minutes=15),
                "status": "pending",
                "source": "quick_start",
                "phone_number": "",
                "verification_id": "",
                "captcha_token": "",
                "device_id": "",
            }
            stats.record("guangyapan", "authorize")
            return RedirectResponse(url=build_guangyapan_login_url(request, session_id), status_code=302)
        
        # 获取OAuth驱动
        oauth_driver = get_oauth_driver(driver_type)
        if not oauth_driver:
            return templates.TemplateResponse(request=request, name="oauth_error.html", context={
                "request": request,
                "error": f"不支持的驱动类型: {driver_type}"
            })
        
        # 构建OAuth URL（使用内置凭据）
        oauth_url = await oauth_driver.get_auth_url(
            session_id=session_id,
            callback_url=f"{get_external_base_url(request)}/callback-popup",
            use_builtin_credentials=True
        )
        
        # 存储会话信息
        oauth_sessions[session_id] = {
            "driver_type": driver_type,
            "server_use": server_use,
            "callback_url": f"{get_external_base_url(request)}/callback-popup",
            "created_at": datetime.now(),
            "expires_at": datetime.now() + timedelta(minutes=10),
            "status": "pending",
            "source": "quick_start"
        }
        
        print(f"✅ 快速OAuth会话创建成功 - Session: {session_id}")
        stats.record(driver_type, "authorize")

        # 直接重定向到OAuth授权页面
        return RedirectResponse(url=oauth_url, status_code=302)
        
    except Exception as e:
        error_msg = str(e)
        print(f"❌ 快速OAuth启动失败 - Error: {error_msg}")
        
        return templates.TemplateResponse(request=request, name="oauth_error.html", context={
            "request": request,
            "error": f"启动OAuth失败: {error_msg}"
        })


# === 统计 API ===

@router.get("/api/stats")
async def get_stats(request: Request, days: int = 0):
    """查看各驱动/操作调用次数统计（需口令）。days=0 返回全部累计，days>0 仅返回最近 N 天。"""
    require_stats_auth(request)
    data = stats.snapshot(days=None if days <= 0 else days)
    window = _aggregate_window(data.get("daily", {}))
    cumulative = data.get("drivers", {})
    data["totals"] = {
        "window_total": _sum_counts(window),
        "cumulative_total": _sum_counts(cumulative),
        "drivers": window,
        "cumulative_drivers": cumulative,
    }
    return JSONResponse(content={
        "success": True,
        "data": data,
    })


@router.post("/api/stats/reset")
async def reset_stats(request: Request):
    """重置调用统计（需统计口令）。"""
    require_stats_auth(request)
    stats.reset()
    return JSONResponse(content={
        "success": True,
        "data": {"message": "统计已重置"},
    })


@router.get("/stats", response_class=HTMLResponse)
async def stats_page(request: Request, days: int = 7):
    """调用统计页面：未登录显示密码登录页，登录成功后写入 Cookie。"""
    if not verify_stats_request(request):
        return templates.TemplateResponse(request=request, name="stats_login.html", context={
            "request": request,
            "error": "",
            "using_default_password": using_default_stats_password(),
        })
    data = stats.snapshot(days=None if days <= 0 else days)
    daily = data.get("daily", {})
    cumulative = data.get("drivers", {})
    window = _aggregate_window(daily)

    peak_daily = {}
    for day_drivers in daily.values():
        for driver, actions in day_drivers.items():
            for action, count in actions.items():
                key = f"{driver}|{action}"
                peak_daily[key] = max(peak_daily.get(key, 0), count)

    today = date.today().isoformat()
    summary = {
        "window_total": _sum_counts(window),
        "today_total": _sum_counts(daily.get(today, {})),
        "days_count": len(daily),
        "cumulative_total": _sum_counts(cumulative),
    }

    cards = []
    for driver, actions in window.items():
        max_action = max(actions.values(), default=0)
        rows = []
        for action, count in actions.items():
            rows.append({
                "key": action,
                "label": _action_label(action),
                "count": count,
                "peak": peak_daily.get(f"{driver}|{action}", 0),
                "width": round(count / max_action * 100) if max_action else 0,
                "color": ACTION_COLORS.get(action, "neutral"),
            })
        rows.sort(key=lambda r: r["count"], reverse=True)
        cards.append({
            "key": driver,
            "name": _driver_name(driver),
            "total": sum(r["count"] for r in rows),
            "actions": rows,
        })
    cards.sort(key=lambda c: c["total"], reverse=True)

    # 每日总调用趋势（展示最近 90 天）
    trend = []
    for day in sorted(daily.keys()):
        trend.append({"date": day, "total": _sum_counts(daily[day])})
    trend = trend[-90:]
    trend_max = max((t["total"] for t in trend), default=0)
    for t in trend:
        t["width"] = round(t["total"] / trend_max * 100) if trend_max else 0
        t["is_today"] = t["date"] == today

    # 每日明细表同样限制展示最近 90 天，避免“全部”时页面过长
    sorted_days = sorted(daily.keys())
    if len(sorted_days) > 90:
        daily = {k: daily[k] for k in sorted_days[-90:]}

    response = templates.TemplateResponse(request=request, name="stats.html", context={
        "request": request,
        "summary": summary,
        "cards": cards,
        "trend": trend,
        "trend_max": trend_max,
        "daily": daily,
        "updated_at": data.get("updated_at", ""),
        "days": days,
        "using_default_password": using_default_stats_password(),
    })
    response.set_cookie(STATS_COOKIE_NAME, make_stats_cookie(), max_age=7 * 24 * 3600,
                        httponly=True, samesite="lax")
    return response


@router.post("/stats/login", response_class=HTMLResponse)
async def stats_login(request: Request, password: str = Form("")):
    """统计页密码登录：只校验密码，不区分用户名。"""
    if check_stats_token(password):
        resp = RedirectResponse(url="/stats", status_code=303)
        resp.set_cookie(STATS_COOKIE_NAME, make_stats_cookie(), max_age=7 * 24 * 3600,
                        httponly=True, samesite="lax")
        return resp
    return templates.TemplateResponse(request=request, name="stats_login.html", context={
        "request": request,
        "error": "密码不正确",
        "using_default_password": using_default_stats_password(),
    })


@router.post("/stats/logout")
async def stats_logout():
    resp = RedirectResponse(url="/stats", status_code=303)
    resp.delete_cookie(STATS_COOKIE_NAME)
    return resp
