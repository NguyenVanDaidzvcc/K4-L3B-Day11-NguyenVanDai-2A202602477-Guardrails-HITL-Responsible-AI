"""Thống kê hoạt động và cảnh báo cho pipeline."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path


def default_metrics_path() -> str:
    root = Path(__file__).resolve().parents[2]
    return str(root / "outputs" / "metrics.json")


@dataclass
class Alert:
    metric: str
    value: float
    threshold: float
    message: str


@dataclass
class MonitoringAlert:
    block_rate_threshold: float = 0.5
    rate_limit_hit_threshold: int = 5
    judge_fail_rate_threshold: float = 0.3

    alerts: list[Alert] = field(default_factory=list)

    total_requests: int = 0
    blocked_requests: int = 0
    rate_limit_hits: int = 0
    judge_checks: int = 0
    judge_fails: int = 0

    redacted_requests: int = 0
    error_requests: int = 0

    def record_request(
        self,
        *,
        blocked: bool = False,
        layer: str | None = None,
        redacted: bool = False,
        error: bool = False,
    ):
        self.total_requests += 1

        if blocked:
            self.blocked_requests += 1

        if layer == "rate_limiter":
            self.rate_limit_hits += 1

        if redacted:
            self.redacted_requests += 1

        if error:
            self.error_requests += 1

    def check_metrics(self) -> list[Alert]:
        # Đây là danh sách cảnh báo hiện tại, không cộng lặp
        # cùng một cảnh báo mỗi lần gọi hàm.
        current_alerts = []

        block_rate = (
            self.blocked_requests / self.total_requests
            if self.total_requests
            else 0.0
        )

        judge_fail_rate = (
            self.judge_fails / self.judge_checks
            if self.judge_checks
            else 0.0
        )

        if (
            self.total_requests
            and block_rate >= self.block_rate_threshold
        ):
            current_alerts.append(
                Alert(
                    metric="block_rate",
                    value=block_rate,
                    threshold=self.block_rate_threshold,
                    message="Tỷ lệ request bị chặn đạt ngưỡng cảnh báo.",
                )
            )

        if self.rate_limit_hits >= self.rate_limit_hit_threshold:
            current_alerts.append(
                Alert(
                    metric="rate_limit_hits",
                    value=float(self.rate_limit_hits),
                    threshold=float(self.rate_limit_hit_threshold),
                    message="Nhiều request vượt giới hạn tốc độ.",
                )
            )

        if (
            self.judge_checks
            and judge_fail_rate >= self.judge_fail_rate_threshold
        ):
            current_alerts.append(
                Alert(
                    metric="judge_fail_rate",
                    value=judge_fail_rate,
                    threshold=self.judge_fail_rate_threshold,
                    message="Tỷ lệ phản hồi không vượt qua Judge cao.",
                )
            )

        self.alerts = current_alerts
        return list(self.alerts)

    def snapshot(self) -> dict:
        self.check_metrics()

        return {
            "total_requests": self.total_requests,
            "blocked_requests": self.blocked_requests,
            "block_rate": (
                self.blocked_requests / self.total_requests
                if self.total_requests
                else 0.0
            ),
            "rate_limit_hits": self.rate_limit_hits,
            "redacted_requests": self.redacted_requests,
            "error_requests": self.error_requests,
            "judge_checks": self.judge_checks,
            "judge_fails": self.judge_fails,
            "judge_fail_rate": (
                self.judge_fails / self.judge_checks
                if self.judge_checks
                else 0.0
            ),
            "alerts": [asdict(alert) for alert in self.alerts],
        }

    def export_json(self, filepath: str | None = None):
        path = Path(filepath or default_metrics_path())
        path.parent.mkdir(parents=True, exist_ok=True)

        path.write_text(
            json.dumps(
                self.snapshot(),
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )

        return str(path)