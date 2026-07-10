import secrets
from typing import Any, Dict, Optional

import httpx


ACCOUNT_BASE_URL = "https://account.guangyapan.com"
DEFAULT_CLIENT_ID = "aMe-8VSlkrbQXpUR"


class GuangYaPanAuthDriver:
    """光鸭云盘短信登录驱动。"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.client_id = (self.config.get("client_id") or DEFAULT_CLIENT_ID).strip() or DEFAULT_CLIENT_ID

    @staticmethod
    def normalize_device_id(device_id: str = "") -> str:
        candidate = (device_id or "").strip().lower()
        if len(candidate) == 32 and all(ch in "0123456789abcdef" for ch in candidate):
            return candidate
        return secrets.token_hex(16)

    @staticmethod
    def normalize_phone_e164(phone: str) -> str:
        phone = (phone or "").strip().replace(" ", "")
        if not phone:
            return ""
        if phone.startswith("+"):
            if phone.startswith("+86") and len(phone) > 3:
                return "+86 " + phone[3:]
            return phone

        digits = "".join(ch for ch in phone if ch.isdigit())
        if len(digits) == 11:
            return f"+86 {digits}"
        return phone

    def _build_account_headers(self, device_id: str, captcha_token: str = "") -> Dict[str, str]:
        headers = {
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/json",
            "X-Device-Model": "chrome%2F147.0.0.0",
            "X-Device-Name": "PC-Chrome",
            "X-Device-Sign": f"wdi10.{device_id}xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "X-Net-Work-Type": "NONE",
            "X-OS-Version": "MacIntel",
            "X-Platform-Version": "1",
            "X-Protocol-Version": "301",
            "X-Provider-Name": "NONE",
            "X-SDK-Version": "9.0.2",
            "X-Client-Id": self.client_id,
            "X-Client-Version": "0.0.1",
            "X-Device-Id": device_id,
        }
        if captcha_token:
            headers["X-Captcha-Token"] = captcha_token
        return headers

    async def _post_account(
        self,
        path: str,
        body: Dict[str, Any],
        device_id: str,
        *,
        captcha_token: str = "",
    ) -> Dict[str, Any]:
        headers = self._build_account_headers(device_id, captcha_token)
        async with httpx.AsyncClient(base_url=ACCOUNT_BASE_URL, timeout=20.0, follow_redirects=True) as client:
            response = await client.post(path, json=body, headers=headers)
            response.raise_for_status()
            return response.json()

    async def ensure_captcha_token(self, phone_number: str, device_id: str) -> str:
        normalized_phone = self.normalize_phone_e164(phone_number)
        payload = {
            "client_id": self.client_id,
            "action": "POST:/v1/auth/verification",
            "device_id": device_id,
            "meta": {
                "username": normalized_phone,
                "phone_number": normalized_phone,
                "VERIFICATION_PHONE": normalized_phone,
            },
        }
        result = await self._post_account("/v1/shield/captcha/init", payload, device_id)
        captcha_token = (result.get("captcha_token") or "").strip()
        if not captcha_token:
            error_message = (result.get("error_description") or result.get("error") or "初始化验证码令牌失败").strip()
            raise Exception(error_message)
        return captcha_token

    async def request_verification_id(
        self,
        phone_number: str,
        device_id: str,
        captcha_token: str,
    ) -> str:
        payload = {
            "phone_number": self.normalize_phone_e164(phone_number),
            "target": "ANY",
            "client_id": self.client_id,
        }
        result = await self._post_account(
            "/v1/auth/verification",
            payload,
            device_id,
            captcha_token=captcha_token,
        )
        verification_id = (result.get("verification_id") or "").strip()
        if not verification_id:
            error_message = (result.get("error_description") or result.get("error") or "发送短信验证码失败").strip()
            raise Exception(error_message)
        return verification_id

    async def prepare_sms_code(
        self,
        phone_number: str,
        *,
        device_id: str = "",
    ) -> Dict[str, str]:
        normalized_phone = self.normalize_phone_e164(phone_number)
        if not normalized_phone:
            raise Exception("手机号不能为空")

        normalized_device_id = self.normalize_device_id(device_id)
        captcha_token = await self.ensure_captcha_token(normalized_phone, normalized_device_id)
        verification_id = await self.request_verification_id(
            normalized_phone,
            normalized_device_id,
            captcha_token,
        )

        return {
            "phone_number": normalized_phone,
            "device_id": normalized_device_id,
            "captcha_token": captcha_token,
            "verification_id": verification_id,
        }

    async def login_by_sms_code(
        self,
        phone_number: str,
        verify_code: str,
        verification_id: str,
        *,
        captcha_token: str = "",
        device_id: str = "",
    ) -> Dict[str, Any]:
        normalized_phone = self.normalize_phone_e164(phone_number)
        verify_code = (verify_code or "").strip()
        verification_id = (verification_id or "").strip()
        normalized_device_id = self.normalize_device_id(device_id)

        if not normalized_phone:
            raise Exception("手机号不能为空")
        if not verify_code:
            raise Exception("验证码不能为空")
        if not verification_id:
            raise Exception("verification_id 为空，请先发送验证码")

        verify_result = await self._post_account(
            "/v1/auth/verification/verify",
            {
                "verification_id": verification_id,
                "verification_code": verify_code,
                "client_id": self.client_id,
            },
            normalized_device_id,
            captcha_token=captcha_token,
        )
        verification_token = (verify_result.get("verification_token") or "").strip()
        if not verification_token:
            error_message = (verify_result.get("error_description") or verify_result.get("error") or "验证码校验失败").strip()
            raise Exception(error_message)

        signin_result = await self._post_account(
            "/v1/auth/signin",
            {
                "verification_code": verify_code,
                "verification_token": verification_token,
                "username": normalized_phone,
                "client_id": self.client_id,
            },
            normalized_device_id,
            captcha_token=captcha_token,
        )

        access_token = (signin_result.get("access_token") or "").strip()
        refresh_token = (signin_result.get("refresh_token") or "").strip()
        if not access_token:
            error_message = (signin_result.get("error_description") or signin_result.get("error") or "登录失败").strip()
            raise Exception(error_message)

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": (signin_result.get("token_type") or "Bearer").strip() or "Bearer",
            "expires_in": signin_result.get("expires_in"),
            "sub": signin_result.get("sub"),
            "client_id": self.client_id,
            "device_id": normalized_device_id,
            "phone_number": normalized_phone,
        }

    async def refresh_token(self, refresh_token: str) -> Dict[str, Any]:
        refresh_token = (refresh_token or "").strip()
        if not refresh_token:
            raise Exception("refresh_token 不能为空")

        device_id = self.normalize_device_id()
        result = await self._post_account(
            "/v1/auth/token",
            {
                "client_id": self.client_id,
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
            },
            device_id,
        )

        access_token = (result.get("access_token") or "").strip()
        if not access_token:
            error_message = (result.get("error_description") or result.get("error") or "刷新 Token 失败").strip()
            raise Exception(error_message)

        return {
            "access_token": access_token,
            "refresh_token": (result.get("refresh_token") or refresh_token).strip(),
            "token_type": (result.get("token_type") or "Bearer").strip() or "Bearer",
            "expires_in": result.get("expires_in"),
            "sub": result.get("sub"),
            "client_id": self.client_id,
            "device_id": device_id,
        }
