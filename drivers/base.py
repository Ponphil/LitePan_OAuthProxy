from abc import ABC, abstractmethod
from typing import Dict, Any, Optional

class BaseOAuthDriver(ABC):
    """OAuth驱动基类"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
    
    @abstractmethod
    async def get_auth_url(self, 
                          session_id: str,
                          callback_url: str,
                          use_builtin_credentials: bool = True,
                          client_id: Optional[str] = None,
                          client_secret: Optional[str] = None) -> str:
        """获取OAuth授权URL"""
        pass
    
    @abstractmethod
    async def exchange_code_for_token(self,
                                    code: str,
                                    use_builtin_credentials: bool = True,
                                    client_id: Optional[str] = None,
                                    client_secret: Optional[str] = None) -> Dict[str, Any]:
        """交换授权码获取Token"""
        pass
    
    @abstractmethod
    async def refresh_token(self, refresh_token: str) -> Dict[str, Any]:
        """刷新Token"""
        pass