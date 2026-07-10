import urllib.parse
from typing import Any, Dict, Optional

import httpx

from .base import BaseOAuthDriver


class OneDriveOAuthDriver(BaseOAuthDriver):
    """OneDrive / Microsoft Graph OAuth 驱动。"""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.auth_url = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
        self.token_url = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
        self.builtin_client_id = config.get("builtin_onedrive_client_id")
        self.builtin_client_secret = config.get("builtin_onedrive_client_secret")
        self.builtin_scope = config.get(
            "builtin_onedrive_scope",
            "Files.ReadWrite.All offline_access",
        )

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
            "response_type": "code",
            "redirect_uri": callback_url,
            "response_mode": "query",
            "scope": self.builtin_scope,
            "state": session_id,
            "prompt": "select_account",
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

        data = {
            "client_id": client_id,
            "client_secret": client_secret,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": callback_url,
            "scope": self.builtin_scope,
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(self.token_url, data=data)
            result = response.json()

        return self._normalize_token_response(result, "获取 Token 失败")

    async def refresh_token(self, refresh_token: str) -> Dict[str, Any]:
        if not self.builtin_client_id or not self.builtin_client_secret:
            raise ValueError("缺少内置 client_id 或 client_secret")

        data = {
            "client_id": self.builtin_client_id,
            "client_secret": self.builtin_client_secret,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "scope": self.builtin_scope,
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(self.token_url, data=data)
            result = response.json()

        return self._normalize_token_response(result, "刷新 Token 失败")

    def _normalize_token_response(self, result: Dict[str, Any], prefix: str) -> Dict[str, Any]:
        if not isinstance(result, dict):
            raise Exception(f"{prefix}: 返回数据格式错误")

        access_token = result.get("access_token")
        if not access_token:
            message = (
                result.get("error_description")
                or result.get("error")
                or result
            )
            raise Exception(f"{prefix}: {message}")

        try:
            expires_in = int(result.get("expires_in") or 3600)
        except (TypeError, ValueError):
            expires_in = 3600

        return {
            "access_token": access_token,
            "refresh_token": result.get("refresh_token", ""),
            "expires_in": expires_in,
            "token_type": result.get("token_type", "Bearer"),
            "scope": result.get("scope", ""),
            "id_token": result.get("id_token", ""),
        }
