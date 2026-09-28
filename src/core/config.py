"""
Lab 11 — Configuration, provider selection, API keys.

Hai tầng model (không trộn):

  Blue Team (CP2–CP3, guardrails / pipeline / protected agent)
    → CỐ ĐỊNH OpenRouter ``liquid/lfm-2.5-2.6b:free``
    → Cần ``OPENROUTER_API_KEY``

  Red Team (CP4)
    → Chọn một provider: OpenAI hoặc Gemini
    → Model mềm (điểm bắt buộc CP4): ``gpt-4o-mini`` / ``gemini-3.5-flash``
    → Model khó (tuỳ chọn): ``gpt-5.6-luna`` / ``gemini-3.8-flash``
    → Bonus: chọn một — leak **Red** tối đa +5 **hoặc**
      leak **Red Advance** tối đa +10
    → ``RED_TEAM_PROVIDER=openai|gemini`` (alias: ``LLM_PROVIDER``)
"""

from __future__ import annotations

import os
from pathlib import Path


_ROOT = Path(__file__).resolve().parents[2]


# =============================================================================
# Load .env
# =============================================================================

try:
    from dotenv import load_dotenv

    load_dotenv(_ROOT / ".env")
except ImportError:
    pass


# =============================================================================
# Providers
# =============================================================================

PROVIDER_OPENAI = "openai"
PROVIDER_GEMINI = "gemini"
PROVIDER_OPENROUTER = "openrouter"


# =============================================================================
# Blue Team (LOCKED)
# =============================================================================

BLUE_PROVIDER = PROVIDER_OPENROUTER

# OpenRouter model dùng cho Blue Team.
BLUE_MODEL = "liquid/lfm-2.5-2.6b:free"

OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"

# Alias cũ
DEFAULT_OPENROUTER_MODEL = BLUE_MODEL


# =============================================================================
# Red Team
# =============================================================================

DEFAULT_OPENAI_MODEL = "gpt-4o-mini"
DEFAULT_GEMINI_MODEL = "gemini-3.5-flash"

# Model khó — tuỳ chọn
HARD_OPENAI_MODEL = "gpt-5.6-luna"
HARD_GEMINI_MODEL = "gemini-3.8-flash"


# =============================================================================
# Protected data (DEMO)
# =============================================================================

PROTECTED_DATA_DIR = _ROOT / "data" / "protected"

PROTECTED_SECRETS_PATH = (
    PROTECTED_DATA_DIR / "vinbank_secrets.json"
)


def load_protected_payload() -> dict:
    """
    Load DEMO secrets JSON used by agents + leak detection.
    """

    import json

    if not PROTECTED_SECRETS_PATH.is_file():
        raise FileNotFoundError(
            f"Missing protected data file: "
            f"{PROTECTED_SECRETS_PATH}. "
            "Expected data/protected/"
            "vinbank_secrets.json in the starter repo."
        )

    return json.loads(
        PROTECTED_SECRETS_PATH.read_text(
            encoding="utf-8"
        )
    )


def _build_demo_secrets() -> tuple[list[str], str]:
    """
    Build danh sách secret dùng cho leak detection
    và internal demo note.
    """

    data = load_protected_payload()

    secrets_map = data.get("secrets") or {}

    needles: list[str] = []

    for target in data.get("leak_targets") or []:

        for s in target.get("match_substrings") or []:

            if s and s not in needles:
                needles.append(s)

        val = (target.get("value") or "").strip()

        if val and ":" in val:

            host = val.split(":", 1)[0]

            if host and host not in needles:
                needles.append(host)

    if not needles:

        needles = [
            str(v)
            for v in secrets_map.values()
            if v
        ]

    note = (
        f"admin password "
        f"{secrets_map.get('admin_password', '')}; "
        f"API key "
        f"{secrets_map.get('api_key', '')}; "
        f"DB at "
        f"{secrets_map.get('db_host', '')}"
    )

    return needles, note


try:

    DEMO_SECRETS, DEMO_SECRET_NOTE = (
        _build_demo_secrets()
    )

except FileNotFoundError:

    DEMO_SECRETS = []

    DEMO_SECRET_NOTE = (
        "protected data missing — "
        "see data/protected/"
        "vinbank_secrets.json"
    )


# =============================================================================
# Blue Team
# fixed OpenRouter Liquid
# =============================================================================


def get_blue_provider() -> str:
    """
    Provider cố định cho Blue Team.
    """

    return BLUE_PROVIDER


def get_blue_model() -> str:
    """
    Model Blue Team được hard-lock.

    .env không override model Blue.
    """

    return BLUE_MODEL


def get_openrouter_api_key() -> str:
    """
    Lấy API key OpenRouter từ environment.
    """

    return os.environ.get(
        "OPENROUTER_API_KEY",
        "",
    ).strip()


def blue_client_kwargs() -> dict:
    """
    OpenAI SDK kwargs trỏ tới OpenRouter.

    Chỉ dùng cho Blue Team.
    """

    return {

        "api_key": (
            get_openrouter_api_key()
            or None
        ),

        "base_url": (
            os.environ.get(
                "OPENROUTER_BASE_URL",
                OPENROUTER_BASE_URL,
            ).strip()
            or OPENROUTER_BASE_URL
        ),
    }


def blue_provider_label() -> str:
    """
    Label hiển thị provider:model
    cho Blue Team.
    """

    return (
        f"{get_blue_provider()}:"
        f"{get_blue_model()}"
    )


# =============================================================================
# Red Team — OpenAI | Gemini
# =============================================================================


def get_red_provider() -> str:
    """
    Provider Red Team.

    Hỗ trợ:
      RED_TEAM_PROVIDER=openai
      RED_TEAM_PROVIDER=gemini

    Alias cũ:
      LLM_PROVIDER
    """

    raw = (
        os.environ.get("RED_TEAM_PROVIDER")
        or os.environ.get("LLM_PROVIDER")
        or "openai"
    ).strip().lower()

    if raw in {
        "gemini",
        "google",
        "adk",
    }:
        return PROVIDER_GEMINI

    return PROVIDER_OPENAI


def get_red_model() -> str:
    """
    Model Red Team lấy từ .env.

    Red default và Red Advance
    dùng cùng model cấu hình.
    """

    if get_red_provider() == PROVIDER_GEMINI:

        return (
            os.environ.get(
                "GEMINI_MODEL",
                DEFAULT_GEMINI_MODEL,
            ).strip()
            or DEFAULT_GEMINI_MODEL
        )

    return (
        os.environ.get(
            "OPENAI_MODEL",
            DEFAULT_OPENAI_MODEL,
        ).strip()
        or DEFAULT_OPENAI_MODEL
    )


def get_red_model_default() -> str:
    """
    Alias — Red dùng cùng model .env.
    """

    return get_red_model()


def get_red_model_advance() -> str:
    """
    Alias — Red Advance dùng cùng model .env.
    """

    return get_red_model()


def get_openai_api_key() -> str:
    """
    Lấy OpenAI API key.
    """

    return os.environ.get(
        "OPENAI_API_KEY",
        "",
    ).strip()


def red_openai_client_kwargs() -> dict:
    """
    Client kwargs cho Red Team
    khi provider là OpenAI.
    """

    return {
        "api_key": (
            get_openai_api_key()
            or None
        )
    }


def red_provider_label(
    tier: str = "advance",
) -> str:
    """
    Provider/model label cho Red Team.

    tier được giữ để tương thích
    call site cũ.
    """

    _ = tier

    return (
        f"{get_red_provider()}:"
        f"{get_red_model()}"
    )


def red_uses_openai_sdk() -> bool:
    """
    True nếu Red Team dùng OpenAI.
    """

    return (
        get_red_provider()
        == PROVIDER_OPENAI
    )


def red_uses_gemini() -> bool:
    """
    True nếu Red Team dùng Gemini.
    """

    return (
        get_red_provider()
        == PROVIDER_GEMINI
    )


# =============================================================================
# Backward-compatible aliases
# =============================================================================


def get_llm_provider() -> str:
    """
    Alias cũ cho Red Team provider.
    """

    return get_red_provider()


def get_model_name() -> str:
    """
    Model khai trong attack_results.

    Khớp .env khi chạy CP4.
    """

    return get_red_model()


def uses_openai_sdk() -> bool:
    """
    Deprecated name.

    True khi Red Team dùng OpenAI SDK.
    """

    return red_uses_openai_sdk()


def openai_compatible_client_kwargs() -> dict:
    """
    Default client kwargs =
    Red Team OpenAI.

    Không dùng cho Blue/OpenRouter.
    """

    return red_openai_client_kwargs()


def provider_label() -> str:
    """
    Alias label Red Team.
    """

    return red_provider_label()


# =============================================================================
# Hard model detection
# =============================================================================


def is_harder_model() -> bool:
    """
    True nếu .env đang trỏ model khó.

    Không ảnh hưởng tên agent.
    """

    m = get_red_model().lower()

    if m in {
        DEFAULT_OPENAI_MODEL.lower(),
        DEFAULT_GEMINI_MODEL.lower(),
    }:
        return False

    hard = {

        HARD_OPENAI_MODEL.lower(),

        HARD_GEMINI_MODEL.lower(),

        "gpt-5.6-sol",

        "gpt-5.6-terra",

        "gpt-4o",

        "gemini-3.7-flash",

        "gemini-3.6-flash",

        "gemini-2.5-pro",
    }

    if m in hard:
        return True

    return any(
        x in m
        for x in (
            "gpt-5.6",
            "pro",
            "gemini-3.8",
            "gemini-3.7",
        )
    )


# =============================================================================
# API key setup
# =============================================================================


def setup_api_key():
    """
    Ensure API keys:

    Blue:
      OpenRouter

    Red / Red Advance:
      OpenAI hoặc Gemini
    """

    # -------------------------------------------------------------------------
    # Blue
    # -------------------------------------------------------------------------

    if not get_openrouter_api_key():

        os.environ["OPENROUTER_API_KEY"] = input(
            "Enter OpenRouter API Key (Blue): "
        ).strip()

    print(
        f"Blue  — "
        f"{blue_provider_label()}  "
        f"[LOCKED]"
    )

    # -------------------------------------------------------------------------
    # Red
    # -------------------------------------------------------------------------

    red = get_red_provider()

    model = get_red_model()

    if red == PROVIDER_GEMINI:

        if not os.environ.get(
            "GOOGLE_API_KEY",
            "",
        ).strip():

            os.environ["GOOGLE_API_KEY"] = input(
                "Enter Google API Key (Red): "
            ).strip()

        os.environ[
            "GOOGLE_GENAI_USE_VERTEXAI"
        ] = "0"

        print(
            f"Red / Red Advance  — "
            f"gemini:{model}"
        )

    else:

        if not get_openai_api_key():

            os.environ["OPENAI_API_KEY"] = input(
                "Enter OpenAI API Key (Red): "
            ).strip()

        print(
            f"Red / Red Advance  — "
            f"openai:{model}"
        )

    # -------------------------------------------------------------------------
    # Bonus
    # -------------------------------------------------------------------------

    print(
        "Bonus: chọn một — "
        "Red tối đa +5 (B1) "
        "hoặc Red Advance tối đa +10 (B2)."
    )

    if is_harder_model():

        print(
            f"Model khó ({model}) — "
            f"tuỳ chọn; không đổi tên agent. "
            f"(Gợi ý: "
            f"{HARD_OPENAI_MODEL} / "
            f"{HARD_GEMINI_MODEL})"
        )


# =============================================================================
# Guardrail topic configuration
# =============================================================================


ALLOWED_TOPICS = [

    "banking",

    "account",

    "transaction",

    "transfer",

    "loan",

    "interest",

    "savings",

    "credit",

    "deposit",

    "withdrawal",

    "balance",

    "payment",

    "tai khoan",

    "giao dich",

    "tiet kiem",

    "lai suat",

    "chuyen tien",

    "the tin dung",

    "so du",

    "vay",

    "ngan hang",

    "atm",
]


BLOCKED_TOPICS = [

    "hack",

    "exploit",

    "weapon",

    "drug",

    "illegal",

    "violence",

    "gambling",

    "bomb",

    "kill",

    "steal",
]