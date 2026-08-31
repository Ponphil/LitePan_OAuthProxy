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
            "baidu": {
                "client_id": os.getenv("OAUTH_BAIDU_CLIENT_ID", "your_baidu_client_id_here"),
                "client_secret": os.getenv("OAUTH_BAIDU_CLIENT_SECRET", "your_baidu_client_secret_here")
            },
            "123": {
                "client_id": os.getenv("OAUTH_123_CLIENT_ID", "your_123_client_id_here"),
                "client_secret": os.getenv("OAUTH_123_CLIENT_SECRET", "your_123_client_secret_here")
            },
            "onedrive": {
                "client_id": os.getenv("OAUTH_ONEDRIVE_CLIENT_ID", "your_onedrive_client_id_here"),
                "client_secret": os.getenv("OAUTH_ONEDRIVE_CLIENT_SECRET", "your_onedrive_client_secret_here")
            },
        }

    def get_supported_drivers(self) -> List[Dict[str, object]]:
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
            {
                "value": "百度网盘Open",
                "name": "百度网盘Open",
                "has_builtin": bool(
                    self.builtin_credentials["baidu"]["client_id"] and
                    self.builtin_credentials["baidu"]["client_id"] != "your_baidu_client_id_here"
                )
            },
            {
                "value": "光鸭云盘",
                "name": "光鸭云盘",
                "has_builtin": True
            },
            {
                "value": "123云盘Open",
                "name": "123云盘Open",
                "has_builtin": bool(
                    self.builtin_credentials["123"]["client_id"] and
                    self.builtin_credentials["123"]["client_id"] != "your_123_client_id_here"
                )
            },
            {
                "value": "OneDrive",
                "name": "OneDrive",
                "has_builtin": bool(
                    self.builtin_credentials["onedrive"]["client_id"] and
                    self.builtin_credentials["onedrive"]["client_id"] != "your_onedrive_client_id_here"
                )
            },
        ]

    def get_driver_config(self, driver_name: str) -> dict:
        config = {
            f"builtin_{driver_name}_client_id": self.builtin_credentials.get(driver_name, {}).get("client_id"),
            f"builtin_{driver_name}_client_secret": self.builtin_credentials.get(driver_name, {}).get("client_secret")
        }
        project_id = self.builtin_credentials.get(driver_name, {}).get("project_id")
        if project_id is not None:
            config[f"builtin_{driver_name}_project_id"] = project_id
        scope = self.builtin_credentials.get(driver_name, {}).get("scope")
        if scope is not None:
            config[f"builtin_{driver_name}_scope"] = scope
        return config
