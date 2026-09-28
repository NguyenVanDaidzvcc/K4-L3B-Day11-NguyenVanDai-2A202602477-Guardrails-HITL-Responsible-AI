"""Ghi nhật ký request và response cho pipeline."""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from guardrails.output_guardrails import content_filter


def default_audit_log_path() -> str:
    root = Path(__file__).resolve().parents[2]
    return str(root / "outputs" / "audit_log.json")


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class AuditLogPlugin:
    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []

        # Lưu request theo request_id.
        self._open: dict[str, dict] = {}

        # Map user_id -> request_id cho trường hợp
        # caller không truyền request_id ở record_output.
        self._user_requests: dict[str, str] = {}

    def record_input(
        self,
        *,
        user_id: str,
        text: str,
        request_id: str | None = None,
    ):
        actual_id = request_id or str(uuid4())

        # Không cho trùng request_id.
        if actual_id in self._open:
            raise ValueError(
                f"Request {actual_id} đang được xử lý."
            )

        # Nếu không truyền request_id thì chỉ hỗ trợ
        # một request đang mở cho mỗi user.
        if request_id is None and user_id in self._user_requests:
            raise ValueError(
                "Request đang được xử lý. "
                "Hãy dùng request_id riêng cho request đồng thời."
            )

        filtered_input = content_filter(text)

        self._open[actual_id] = {
            "request_id": actual_id,
            "user_id": user_id,
            "input": filtered_input["redacted"],
            "started_at": utc_now_iso(),
            "_start_time": time.monotonic(),
        }

        if request_id is None:
            self._user_requests[user_id] = actual_id

        return actual_id

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        # Nếu caller có request_id thì tìm trực tiếp.
        # Nếu không thì lấy request đang mở của user.
        actual_id = request_id

        if actual_id is None:
            actual_id = self._user_requests.get(user_id)

        if actual_id is None or actual_id not in self._open:
            raise ValueError("Chưa gọi record_input cho request này.")

        pending = self._open[actual_id]

        if pending["user_id"] != user_id:
            raise ValueError("user_id không khớp request đã ghi.")

        # Lọc output trước khi đóng request.
        filtered_output = content_filter(text)
        redacted_output = filtered_output["redacted"]

        pending = self._open.pop(actual_id)
        start_time = pending.pop("_start_time")

        # Xóa mapping user nếu đây là request mặc định của user.
        if self._user_requests.get(user_id) == actual_id:
            self._user_requests.pop(user_id, None)

        entry = {
            **pending,
            "output": redacted_output,
            "blocked": bool(blocked),
            "layer": layer,
            "finished_at": utc_now_iso(),
            "latency_ms": round(
                (time.monotonic() - start_time) * 1000,
                3,
            ),
        }

        self.logs.append(entry)

        return entry

    def export_json(self, filepath: str | None = None):
        path = Path(filepath or default_audit_log_path())

        path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        path.write_text(
            json.dumps(
                self.logs,
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )

        return str(path)