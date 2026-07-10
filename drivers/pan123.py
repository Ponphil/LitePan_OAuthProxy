import urllib.parse
from typing import Any, Dict, Optional

import httpx

from .base import BaseOAuthDriver


class Pan123OAuthDriver(BaseOAuthDriver):
    """123云盘 OAuth 驱动。"""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.auth_url = "https://yun.123pan.com/auth"
        self.token_url = "https://open-api.123pan.com/api/v1/oauth2/access_token"
        self.builtin_client_id = config.get("builtin_123_client_id")
        self.builtin_client_secret = config.get("builtin_123_client_secret")
        self.builtin_scope = config.get(
            "builtin_123_scope",
            "user:base,file:all:read,file:all:write",
        )
        self.token_headers = {
            "Platform": "open_platform",
            "Content-Type": "application/json",
        }

    async def get_auth_url(
        self,
        session_id: str,
        callback_url: str,
        use_builtin_credentials: bool = True,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
    ) -> str:
        if use_builtin_credentials:
            client_id = self.builtin_client_id

        if not client_id:
            raise ValueError("缺少 client_id")

        params = {
            "client_id": client_id,
            "redirect_uri": callback_url,
            "scope": self.builtin_scope or "all",
            "state": session_id,
        }
        return f"{self.auth_url}?{urllib.parse.urlencode(params)}"

    async def exchange_code_for_token(
        self,
        code: str,
        callback_url: str,
        use_builtin_credentials: bool = True,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
    ) -> Dict[str, Any]:
        if use_builtin_credentials:
            client_id = self.builtin_client_id
            client_secret = self.builtin_client_secret

        if not client_id or not client_secret:
            raise ValueError("缺少 client_id 或 client_secret")

        params = {
            "client_id": client_id,
            "client_secret": client_secret,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": callback_url,
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(
                self.token_url,
                params=params,
                headers=self.token_headers,
            )
            result = response.json()

        return self._normalize_token_response(result, "获取 Token 失败")

    async def refresh_token(self, refresh_token: str) -> Dict[str, Any]:
        if not self.builtin_client_id or not self.builtin_client_secret:
            raise ValueError("缺少内置 client_id 或 client_secret")

        params = {
            "client_id": self.builtin_client_id,
            "client_secret": self.builtin_client_secret,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(
                self.token_url,
                params=params,
                headers=self.token_headers,
            )
            result = response.json()

        return self._normalize_token_response(result, "刷新 Token 失败")

    def _normalize_token_response(self, result: Dict[str, Any], prefix: str) -> Dict[str, Any]:
        if not isinstance(result, dict):
            raise Exception(f"{prefix}: 返回数据格式错误")

        data = result.get("data") if isinstance(result.get("data"), dict) else result
        access_token = data.get("accessToken") or data.get("access_token")
        refresh_token = data.get("refreshToken") or data.get("refresh_token")
        expires_in = data.get("expiresIn") or data.get("expires_in")
        token_type = data.get("tokenType") or data.get("token_type") or "Bearer"
        scope = data.get("scope", "")

        if not access_token:
            message = (
                result.get("message")
                or result.get("msg")
                or result.get("error_description")
                or result.get("error")
                or result
            )
            raise Exception(f"{prefix}: {message}")

        try:
            expires_in = int(expires_in) if expires_in is not None else 2592000
        except (TypeError, ValueError):
            expires_in = 2592000

        return {
            "access_token": access_token,
            "refresh_token": refresh_token or "",
            "expires_in": expires_in,
            "token_type": token_type,
            "scope": scope,
        }
