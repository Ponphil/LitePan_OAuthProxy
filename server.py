from fastapi import APIRouter, HTTPException, Request, Query, Form
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from typing import Dict, Any, Optional
import asyncio
import uuid
import json
import base64
from datetime import datetime, timedelta
from drivers import get_oauth_driver
from config import OAuthConfig

router = APIRouter()
templates = Jinja2Templates(directory="templates")

# 会话存储（生产环境建议使用Redis）
oauth_sessions: Dict[str, Dict] = {}


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
@router.get("/oauth", response_class=HTMLResponse)
async def oauth_index(request: Request):
    """OAuth获取工具主页面"""
    return templates.TemplateResponse("oauth_index.html", {
        "request": request,
        "drivers": oauth_proxy.config.get_supported_drivers()
    })


@router.post("/oauth/start")
async def start_oauth_web(request: Request,
                          driver_type: str = Form(...),
                          server_use: bool = Form(False),
                          client_id: Optional[str] = Form(None),
                          client_secret: Optional[str] = Form(None)):
    """网页版：开始OAuth授权流程"""
    try:
        # 生成会话ID
        session_id = str(uuid.uuid4())

        # 获取OAuth驱动
        oauth_driver = get_oauth_driver(driver_type)
        if not oauth_driver:
            raise HTTPException(status_code=400, detail=f"不支持的驱动类型: {driver_type}")

        # 构建OAuth URL
        if server_use:
            # 使用内置凭据
            oauth_url = await oauth_driver.get_auth_url(
                session_id=session_id,
                callback_url=f"{request.base_url}oauth/callback",
                use_builtin_credentials=True
            )
        else:
            # 使用用户提供的凭据
            if not client_id or not client_secret:
                raise HTTPException(status_code=400, detail="请提供Client ID和Client Secret")
            oauth_url = await oauth_driver.get_auth_url(
                session_id=session_id,
                callback_url=f"{request.base_url}oauth/callback",
                client_id=client_id,
                client_secret=client_secret
            )

        # 存储会话信息
        oauth_sessions[session_id] = {
            "driver_type": driver_type,
            "server_use": server_use,
            "client_id": client_id,
            "client_secret": client_secret,
            "created_at": datetime.now(),
            "expires_at": datetime.now() + timedelta(minutes=10),
            "status": "pending",
            "source": "web"
        }

        return RedirectResponse(url=oauth_url, status_code=302)

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"启动OAuth失败: {str(e)}")


@router.get("/oauth/callback")
async def oauth_callback(request: Request,
                         code: str = Query(...),
                         state: str = Query(...)):
    """OAuth回调处理"""
    try:
        session = oauth_sessions.get(state)
        if not session:
            raise HTTPException(status_code=404, detail="会话不存在或已过期")

        # 获取OAuth驱动
        oauth_driver = get_oauth_driver(session["driver_type"])
        if not oauth_driver:
            raise HTTPException(status_code=400, detail="不支持的驱动类型")

        # 在oauth_callback函数中（约第120-140行）
        # 交换授权码获取Token
        if session["server_use"]:
            token_data = await oauth_driver.exchange_code_for_token(
                code=code,
                callback_url=f"{request.base_url}oauth/callback",
                use_builtin_credentials=True
            )
        else:
            token_data = await oauth_driver.exchange_code_for_token(
                code=code,
                callback_url=f"{request.base_url}oauth/callback",
                client_id=session["client_id"],
                client_secret=session["client_secret"]
            )

        # 更新会话状态
        session["status"] = "success"
        session["token_data"] = token_data
        session["completed_at"] = datetime.now()

        # 显示Token结果页面
        return templates.TemplateResponse("oauth_callback.html", {
            "request": request,
            "success": True,
            "token_data": token_data,
            "driver_type": session["driver_type"]
        })

    except Exception as e:
        # 更新会话状态为失败
        if state in oauth_sessions:
            oauth_sessions[state]["status"] = "error"
            oauth_sessions[state]["error"] = str(e)

        return templates.TemplateResponse("oauth_callback.html", {
            "request": request,
            "success": False,
            "error": str(e)
        })


# === API接口路由 ===
# 添加请求模型
class OAuthStartRequest(BaseModel):
    driver_type: str
    callback_url: str
    server_use: bool = True
    client_id: Optional[str] = None
    client_secret: Optional[str] = None

@router.post("/api/oauth/start")
async def start_oauth_api(request: Request, oauth_request: OAuthStartRequest):
    """API版：开始OAuth授权流程"""
    # 生成会话ID
    session_id = str(uuid.uuid4())
    
    try:
        # 获取OAuth驱动
        oauth_driver = get_oauth_driver(oauth_request.driver_type)
        if not oauth_driver:
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
                "error": f"不支持的驱动类型: {oauth_request.driver_type}",
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

        # 构建OAuth URL
        if oauth_request.server_use:
            oauth_url = await oauth_driver.get_auth_url(
                session_id=session_id,
                callback_url=f"{request.base_url}oauth/callback",
                use_builtin_credentials=True
            )
        else:
            if not oauth_request.client_id or not oauth_request.client_secret:
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
                    "error": "请提供Client ID和Client Secret",
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
                callback_url=f"{request.base_url}oauth/callback",
                client_id=oauth_request.client_id,
                client_secret=oauth_request.client_secret
            )

        # 存储会话信息
        oauth_sessions[session_id] = {
            "driver_type": oauth_request.driver_type,
            "server_use": oauth_request.server_use,
            "client_id": oauth_request.client_id,
            "client_secret": oauth_request.client_secret,
            "callback_url": oauth_request.callback_url,
            "created_at": datetime.now(),
            "expires_at": datetime.now() + timedelta(minutes=10),
            "status": "pending",
            "source": "api"
        }

        return JSONResponse(content={
            "success": True,
            "data": {
                "session_id": session_id,
                "oauth_url": oauth_url,
                "expires_in": 600  # 10分钟
            }
        })

    except Exception as e:
        # 确保会话被创建并设置错误状态
        oauth_sessions[session_id] = {
            "driver_type": oauth_request.driver_type,
            "server_use": oauth_request.server_use,
            "client_id": oauth_request.client_id,
            "client_secret": oauth_request.client_secret,
            "callback_url": oauth_request.callback_url,
            "created_at": datetime.now(),
            "expires_at": datetime.now() + timedelta(minutes=10),
            "status": "error",
            "error": str(e),
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
        return JSONResponse(
            status_code=404,
            content={"success": False, "message": "会话不存在或已过期"}
        )

    return JSONResponse(content={
        "success": True,
        "data": {
            "status": session["status"],
            "token_data": session.get("token_data"),
            "error": session.get("error")
        }
    })


# 在文件末尾添加新的API接口

@router.post("/api/oauth/quick-auth")
async def quick_oauth_auth(request: Request,
                          driver_type: str,
                          server_use: bool = True):
    """快速OAuth认证接口 - 用于前端按钮调用"""
    try:
        # 生成会话ID
        session_id = str(uuid.uuid4())
        
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
            callback_url=f"{request.base_url}oauth/callback-popup",
            use_builtin_credentials=True
        )
        
        # 存储会话信息
        oauth_sessions[session_id] = {
            "driver_type": driver_type,
            "server_use": server_use,
            "callback_url": f"{request.base_url}oauth/callback-popup",
            "created_at": datetime.now(),
            "expires_at": datetime.now() + timedelta(minutes=10),
            "status": "pending",
            "source": "quick_auth"
        }
        
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