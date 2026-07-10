from typing import Optional

from config import OAuthConfig

from .baidu_pan import BaiduPanOAuthDriver
from .base import BaseOAuthDriver
from .onedrive import OneDriveOAuthDriver
from .pan115 import Pan115OAuthDriver
from .pan123 import Pan123OAuthDriver


DRIVER_REGISTRY = {
    "115网盘Open": Pan115OAuthDriver,
    "百度网盘Open": BaiduPanOAuthDriver,
    "baidu_open": BaiduPanOAuthDriver,
    "百度网盘": BaiduPanOAuthDriver,
    "123云盘Open": Pan123OAuthDriver,
    "123云盘": Pan123OAuthDriver,
    "pan123": Pan123OAuthDriver,
    "pan123_open": Pan123OAuthDriver,
    "OneDrive": OneDriveOAuthDriver,
    "onedrive": OneDriveOAuthDriver,
    "OneDrive_Open": OneDriveOAuthDriver,
    "onedrive_open": OneDriveOAuthDriver,
    "微软OneDrive": OneDriveOAuthDriver,
}

DRIVER_CONFIG_MAPPING = {
    "115网盘Open": "115",
    "百度网盘Open": "baidu",
    "baidu_open": "baidu",
    "百度网盘": "baidu",
    "123云盘Open": "123",
    "123云盘": "123",
    "pan123": "123",
    "pan123_open": "123",
    "OneDrive": "onedrive",
    "onedrive": "onedrive",
    "OneDrive_Open": "onedrive",
    "onedrive_open": "onedrive",
    "微软OneDrive": "onedrive",
}


def get_oauth_driver(driver_type: str) -> Optional[BaseOAuthDriver]:
    """获取 OAuth 驱动实例。"""
    driver_class = DRIVER_REGISTRY.get(driver_type)
    if not driver_class:
        return None

    config = OAuthConfig()
    driver_config_key = DRIVER_CONFIG_MAPPING.get(driver_type, driver_type)
    driver_config = config.get_driver_config(driver_config_key)
    return driver_class(driver_config)


def get_supported_drivers():
    """获取支持的驱动类型列表。"""
    return list(DRIVER_REGISTRY.keys())
