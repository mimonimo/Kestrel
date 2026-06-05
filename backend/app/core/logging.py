import logging
import sys
from typing import Any

import structlog


# 토큰·비밀번호 redact 대상 키. processor 가 모든 log event 의 dict 를 훑어
# 이 키들의 값을 ``***`` 로 치환. 부분 매칭이라 ``X-NVD-API-Key``,
# ``nvdApiKey``, ``github_token``, ``access_token``, ``password`` 등 자동 잡힘.
_REDACT_TOKENS = (
    "api_key", "apikey",
    "nvd_api_key", "nvdapikey", "x-nvd-api-key",
    "github_token", "githubtoken", "x-github-token",
    "access_token", "accesstoken",
    "refresh_token", "refreshtoken",
    "jwt", "secret", "password",
    "anthropic_api_key", "anthropicapikey",
)


def _redact_secrets(_logger: Any, _name: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    """모든 event 의 dict 키를 lowercase 매칭해 토큰 값 ``***`` 치환."""
    for k in list(event_dict.keys()):
        if not isinstance(k, str):
            continue
        low = k.lower()
        if any(t in low for t in _REDACT_TOKENS):
            event_dict[k] = "***"
    return event_dict


def configure_logging(debug: bool = False) -> None:
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(format="%(message)s", stream=sys.stdout, level=level)

    # root 가 INFO 면 SQLAlchemy 의 ``sqlalchemy.engine`` 로거가 이를 상속받아
    # echo=False 여도 모든 쿼리를 INFO 로 토해낸다(대량 수집 시 로그 폭증·오버헤드).
    # echo 는 database.py 의 ``settings.debug and env==development`` 가 제어하므로,
    # 여기선 엔진/풀 로거를 WARNING 으로 눌러 의도치 않은 SQL echo 를 차단한다.
    # debug 모드에서 정말 SQL 을 보고 싶으면 echo=True 가 직접 INFO 로 올린다.
    for noisy in ("sqlalchemy.engine", "sqlalchemy.pool", "sqlalchemy.dialects"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            _redact_secrets,  # 토큰/비번 값 자동 마스킹 (PR 10-CQ)
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.dev.ConsoleRenderer() if debug else structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    return structlog.get_logger(name) if name else structlog.get_logger()
