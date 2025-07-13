from typing import Optional
from .base import BaseOAuthDriver
from .pan115 import Pan115OAuthDriver
from config import OAuthConfig

# 驱动注册表
DRIVER_REGISTRY = {
    "115网盘Open": Pan115OAuthDriver,  # 统一使用这个名称
}

def get_oauth_driver(driver_type: str) -> Optional[BaseOAuthDriver]:
    """获取OAuth驱动实例"""
    driver_class = DRIVER_REGISTRY.get(driver_type)
    if not driver_class:
        return None

    config = OAuthConfig()
    # 统一使用"115"作为配置key
    if driver_type == "115网盘Open":
        driver_config = config.get_driver_config("115")
    else:
        driver_config = config.get_driver_config(driver_type)
    
    return driver_class(driver_config)

def get_supported_drivers():
    """获取支持的驱动类型列表"""
    return list(DRIVER_REGISTRY.keys())