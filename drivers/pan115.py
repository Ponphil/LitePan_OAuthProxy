import httpx
import urllib.parse
from typing import Dict, Any, Optional
from .base import BaseOAuthDriver

class Pan115OAuthDriver(BaseOAuthDriver):
    """115网盘OAuth驱动"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        # 使用正确的115网盘OAuth2端点（参考OpenList-APIPages）
        self.auth_url = "https://passportapi.115.com/open/authorize"
        self.token_url = "https://passportapi.115.com/open/authCodeToToken"
        self.refresh_url = "https://passportapi.115.com/open/refreshToken"
        
        # 内置开发者凭据（从环境变量或配置文件读取）
        self.builtin_client_id = config.get("builtin_115_client_id")
        self.builtin_client_secret = config.get("builtin_115_client_secret")
    
    async def get_auth_url(self, 
                      session_id: str,
                      callback_url: str,
                      use_builtin_credentials: bool = True,
                      client_id: Optional[str] = None,
                      client_secret: Optional[str] = None) -> str:
        """获取115网盘OAuth授权URL"""
        
        if use_builtin_credentials:
            client_id = self.builtin_client_id
        
        if not client_id:
            raise ValueError("缺少client_id")
        
        # 预检查应用状态
        test_url = f"{self.auth_url}?client_id={client_id}&redirect_uri={callback_url}&response_type=code&state=test"
        
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(test_url)
                if response.status_code == 200:
                    content = response.text
                    # 更全面的错误检测
                    if any(error_indicator in content for error_indicator in [
                        '"state":0',  # 115网盘错误状态
                        '40140108',   # 应用未审核通过错误码
                        'error',      # 通用错误字段
                        '应用未审核通过',  # 中文错误信息
                        '审核',       # 审核相关错误
                        'invalid_client'  # OAuth标准错误
                    ]):
                        raise Exception("115网盘应用未审核通过或存在其他错误，请联系管理员更新开发者凭据")
            except httpx.RequestError:
                # 网络错误，继续执行
                pass
        
        params = {
            "client_id": client_id,
            "redirect_uri": callback_url,
            "response_type": "code",
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
        
        data = {
            "client_id": client_id,
            "client_secret": client_secret,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": callback_url
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                self.token_url,
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            result = response.json()
            
            # 115网盘返回格式：{"state": 1, "data": {"access_token": ..., "refresh_token": ...}}
            if result.get("state") == 1:
                return {
                    "access_token": result["data"]["access_token"],
                    "refresh_token": result["data"]["refresh_token"],
                    "expires_in": result["data"].get("expires_in", 3600),
                    "token_type": "Bearer"
                }
            else:
                raise Exception(f"获取Token失败: {result.get('message', 'Unknown error')}")
    
    async def refresh_token(self, refresh_token: str) -> Dict[str, Any]:
        """刷新115网盘Token"""
        data = {
            "refresh_token": refresh_token
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                self.refresh_url,
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            result = response.json()
            
            if result.get("state") == 1:
                return {
                    "access_token": result["data"]["access_token"],
                    "refresh_token": result["data"]["refresh_token"],
                    "expires_in": result["data"].get("expires_in", 3600),
                    "token_type": "Bearer"
                }
            else:
                raise Exception(f"刷新Token失败: {result.get('message', 'Unknown error')}")