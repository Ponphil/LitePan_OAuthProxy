"""OAuth Proxy 调用统计，支持按日/累计查看，用于评估各网盘平台所需 API 配额。"""
import json
import os
from datetime import datetime, date, timedelta
from typing import Dict, Optional

STATS_FILE = os.path.join(os.path.dirname(__file__), "oauth_stats.json")


class StatsCollector:
    def __init__(self):
        self._counters: Dict[str, Dict[str, int]] = {}
        self._daily: Dict[str, Dict[str, Dict[str, int]]] = {}
        self._load()

    def record(self, driver: str, action: str):
        today = date.today().isoformat()
        d = self._counters.setdefault(driver, {})
        d[action] = d.get(action, 0) + 1
        dd = self._daily.setdefault(today, {}).setdefault(driver, {})
        dd[action] = dd.get(action, 0) + 1
        self.save()

    def snapshot(self, days: Optional[int] = None) -> dict:
        daily = dict(self._daily)
        if days is not None:
            cutoff = (date.today() - timedelta(days=days - 1)).isoformat()
            daily = {k: v for k, v in daily.items() if k >= cutoff}
        return {
            "drivers": dict(self._counters),
            "daily": daily,
            "updated_at": datetime.now().isoformat(),
        }

    def save(self):
        try:
            with open(STATS_FILE, "w") as f:
                json.dump(self.snapshot(), f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    def reset(self):
        self._counters.clear()
        self._daily.clear()
        self.save()

    def _load(self):
        try:
            if os.path.exists(STATS_FILE):
                with open(STATS_FILE) as f:
                    data = json.load(f)
                    self._counters = data.get("drivers", {})
                    self._daily = data.get("daily", {})
        except Exception:
            self._counters = {}
            self._daily = {}


stats = StatsCollector()
