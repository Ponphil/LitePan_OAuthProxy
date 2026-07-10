import httpx
import urllib.parse
from typing import Dict, Any, Optional
from .base import BaseOAuthDriver


class BaiduPanOAuthDriver(BaseOAuthDriver):
    """百度网盘OAuth驱动"""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.auth_url = "https://openapi.baidu.com/oauth/2.0/authorize"
        self.token_url = "https://openapi.baidu.com/oauth/2.0/token"
        self.builtin_client_id = config.get("builtin_baidu_client_id")
        self.builtin_client_secret = config.get("builtin_baidu_client_secret")
        self.user_agent = "pan.baidu.com"

    async def get_auth_url(self,
                           session_id: str,
                           callback_url: str,
                           use_builtin_credentials: bool = True,
                           client_id: Optional[str] = None,
                           client_secret: Optional[str] = None) -> str:
        """获取百度网盘OAuth授权URL"""
        if use_builtin_credentials:
            client_id = self.builtin_client_id

        if not client_id:
            raise ValueError("缺少client_id")

        params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": callback_url,
            "scope": "basic,netdisk",
            "state": session_id
        }

        return f"{self.auth_url}?{urllib.parse.urlencode(params)}"

    async def exchange_code_for_token(self,
                                      code: str,
                                      callback_url: str,
                                      use_builtin_credentials: bool = True,
                                      client_id: Optional[str] = None,
                                      client_secret: Optional[str] = None) -> Dict[str, Any]:
        """交换授权码获取Token"""
        if use_builtin_credentials:
            client_id = self.builtin_client_id
            client_secret = self.builtin_client_secret

        if not client_id or not client_secret:
            raise ValueError("缺少client_id或client_secret")

        params = {
            "grant_type": "authorization_code",
            "code": code,
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": callback_url
        }

        async with httpx.AsyncClient() as client:
            response = await client.get(
                self.token_url,
                params=params,
                headers={"User-Agent": self.user_agent}
            )
            result = response.json()

        if "access_token" not in result:
            raise Exception(f"获取Token失败: {result.get('error_description') or result.get('error_msg') or result.get('error') or result}")

        return {
            "access_token": result["access_token"],
            "refresh_token": result.get("refresh_token", ""),
            "expires_in": result.get("expires_in", 2592000),
            "token_type": result.get("token_type", "Bearer"),
            "scope": result.get("scope", ""),
            "session_key": result.get("session_key", ""),
            "session_secret": result.get("session_secret", "")
        }

    async def refresh_token(self, refresh_token: str) -> Dict[str, Any]:
        """刷新百度网盘Token"""
        if not self.builtin_client_id or not self.builtin_client_secret:
            raise ValueError("缺少内置client_id或client_secret")

        params = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": self.builtin_client_id,
            "client_secret": self.builtin_client_secret
        }

        async with httpx.AsyncClient() as client:
            response = await client.get(
                self.token_url,
                params=params,
                headers={"User-Agent": self.user_agent}
            )
            result = response.json()

        if "access_token" not in result:
            raise Exception(f"刷新Token失败: {result.get('error_description') or result.get('error_msg') or result.get('error') or result}")

        return {
            "access_token": result["access_token"],
            "refresh_token": result.get("refresh_token", ""),
            "expires_in": result.get("expires_in", 2592000),
            "token_type": result.get("token_type", "Bearer"),
            "scope": result.get("scope", ""),
            "session_key": result.get("session_key", ""),
            "session_secret": result.get("session_secret", "")
        }
