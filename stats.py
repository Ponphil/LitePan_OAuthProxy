"""OAuth Proxy 调用统计，支持按日/累计查看，用于评估各网盘平台所需 API 配额。"""
import json
import os
import time
from datetime import datetime, date, timedelta
from typing import Dict, Optional

STATS_FILE = os.path.join(os.path.dirname(__file__), "oauth_stats.json")

DRIVER_KEY_ALIASES = {
    "115": "115",
    "115网盘open": "115",
    "baidu": "baidu",
    "baidu_open": "baidu",
    "百度网盘": "baidu",
    "百度网盘open": "baidu",
    "123": "123",
    "pan123": "123",
    "pan123_open": "123",
    "123云盘": "123",
    "123云盘open": "123",
    "onedrive": "onedrive",
    "onedrive_open": "onedrive",
    "微软onedrive": "onedrive",
    "guangyapan": "guangyapan",
    "光鸭云盘": "guangyapan",
}


def normalize_driver_key(driver: str) -> str:
    """统计只保留稳定内部键，避免中文显示名与历史别名被分成多个驱动。"""
    raw = str(driver or "").strip()
    if not raw:
        return "unknown"
    return DRIVER_KEY_ALIASES.get(raw.casefold(), raw)


def merge_driver_counters(raw: object) -> Dict[str, Dict[str, int]]:
    """归并 {driver: {action: count}}，未知驱动仍保留原键。"""
    merged: Dict[str, Dict[str, int]] = {}
    if not isinstance(raw, dict):
        return merged
    for driver, actions in raw.items():
        if not isinstance(actions, dict):
            continue
        target = merged.setdefault(normalize_driver_key(driver), {})
        for action, count in actions.items():
            try:
                value = int(count)
            except (TypeError, ValueError):
                continue
            action_key = str(action).strip()
            if not action_key:
                continue
            target[action_key] = target.get(action_key, 0) + value
    return merged


class StatsCollector:
    def __init__(self):
        self._counters: Dict[str, Dict[str, int]] = {}
        self._daily: Dict[str, Dict[str, Dict[str, int]]] = {}
        self._last_save = 0.0
        self._load()

    def record(self, driver: str, action: str):
        today = date.today().isoformat()
        driver = normalize_driver_key(driver)
        action = str(action or "").strip() or "unknown"
        d = self._counters.setdefault(driver, {})
        d[action] = d.get(action, 0) + 1
        dd = self._daily.setdefault(today, {}).setdefault(driver, {})
        dd[action] = dd.get(action, 0) + 1
        self._maybe_save()

    def snapshot(self, days: Optional[int] = None) -> dict:
        daily = dict(self._daily)
        if days is not None:
            cutoff = (date.today() - timedelta(days=days - 1)).isoformat()
            daily = {k: v for k, v in daily.items() if k >= cutoff}
        return {
            "drivers": dict(self._counters),
            "daily": daily,
            "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
        }

    def _maybe_save(self):
        # 高频记录时防抖落盘，避免每个请求都写文件；snapshot/reset 会强制 flush。
        now = time.monotonic()
        if now - self._last_save >= 2.0:
            self._last_save = now
            self.save()

    def save(self):
        try:
            with open(STATS_FILE, "w", encoding="utf-8") as f:
                json.dump(self.snapshot(), f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    def reset(self):
        self._counters.clear()
        self._daily.clear()
        self._last_save = 0.0
        self.save()

    def _load(self):
        try:
            if os.path.exists(STATS_FILE):
                with open(STATS_FILE, encoding="utf-8") as f:
                    data = json.load(f)
                    raw_counters = data.get("drivers", {})
                    raw_daily = data.get("daily", {})
                    self._counters = merge_driver_counters(raw_counters)
                    self._daily = {}
                    if isinstance(raw_daily, dict):
                        self._daily = {
                            str(day): merge_driver_counters(day_drivers)
                            for day, day_drivers in raw_daily.items()
                        }
                    # 立即回写已归并的历史别名，升级后无需手动重置统计。
                    if self._counters != raw_counters or self._daily != raw_daily:
                        self.save()
        except Exception:
            self._counters = {}
            self._daily = {}


stats = StatsCollector()
