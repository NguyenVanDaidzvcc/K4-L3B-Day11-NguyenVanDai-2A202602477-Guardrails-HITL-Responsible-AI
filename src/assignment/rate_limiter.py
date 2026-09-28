"""Checkpoint 3: Sliding-window rate limiter theo từng user."""

from __future__ import annotations

import math
import time
from collections import defaultdict, deque

from google.adk.plugins import base_plugin
from google.genai import types


class RateLimitPlugin(base_plugin.BasePlugin):
    """Chặn request khi user vượt giới hạn trong cửa sổ thời gian."""

    def __init__(
        self,
        max_requests: int = 10,
        window_seconds: int = 60,
    ):
        super().__init__(name="rate_limiter")

        if (
            isinstance(max_requests, bool)
            or not isinstance(max_requests, int)
            or max_requests <= 0
        ):
            raise ValueError("max_requests phải là số nguyên dương.")

        if (
            isinstance(window_seconds, bool)
            or not isinstance(window_seconds, (int, float))
            or not math.isfinite(window_seconds)
            or window_seconds <= 0
        ):
            raise ValueError("window_seconds phải là số dương hữu hạn.")

        self.max_requests = max_requests
        self.window_seconds = window_seconds

        self.user_windows: dict[str, deque] = defaultdict(deque)
        self.blocked_count = 0
        self.total_count = 0

    def _block_response(self, message: str) -> types.Content:
        return types.Content(
            role="model",
            parts=[types.Part.from_text(text=message)],
        )

    def _get_user_id(self, invocation_context) -> str:
        # Runtime OpenAI/OpenRouter của lab đặt user_id trực tiếp.
        user_id = getattr(invocation_context, "user_id", None)

        # Hỗ trợ context có user_id trong session.
        if not user_id:
            session = getattr(invocation_context, "session", None)
            user_id = getattr(session, "user_id", None)

        return str(user_id) if user_id else "anonymous"

    async def on_user_message_callback(
        self,
        *,
        invocation_context,
        user_message,
    ) -> types.Content | None:
        self.total_count += 1

        user_id = self._get_user_id(invocation_context)

        # monotonic không bị ảnh hưởng khi đồng hồ hệ thống đổi giờ.
        now = time.monotonic()
        cutoff = now - self.window_seconds
        window = self.user_windows[user_id]

        # Bỏ request đã hết hạn.
        while window and window[0] <= cutoff:
            window.popleft()

        if len(window) >= self.max_requests:
            self.blocked_count += 1

            wait_seconds = max(
                1,
                math.ceil(
                    self.window_seconds - (now - window[0])
                ),
            )

            return self._block_response(
                "Rate limit exceeded. "
                f"Try again in {wait_seconds}s."
            )

        window.append(now)
        return None