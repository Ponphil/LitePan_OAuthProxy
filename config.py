import os
from typing import Dict, List

class OAuthConfig:
    def __init__(self):
        # 使用环境变量，提供默认值作为fallback
        self.builtin_credentials = {
            "115": {
                "client_id": os.getenv("OAUTH_115_CLIENT_ID", "your_115_client_id_here"),
                "client_secret": os.getenv("OAUTH_115_CLIENT_SECRET", "your_115_client_secret_here")
            },
        }

    def get_supported_drivers(self) -> List[Dict[str, str]]:
        """获取支持的驱动列表"""
        return [
            {
                "value": "115网盘Open",
                "name": "115网盘Open",
                "has_builtin": bool(
                    self.builtin_credentials["115"]["client_id"] and
                    self.builtin_credentials["115"]["client_id"] != "your_115_client_id_here"
                )
            },
        ]

    def get_driver_config(self, driver_name: str) -> dict:
        return {
            f"builtin_{driver_name}_client_id": self.builtin_credentials.get(driver_name, {}).get("client_id"),
            f"builtin_{driver_name}_client_secret": self.builtin_credentials.get(driver_name, {}).get("client_secret")
        }