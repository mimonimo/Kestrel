"""클라이언트 IP 추출 헬퍼.

Caddy reverse_proxy 뒤에 있는 backend 컨테이너는 ``request.client.host`` 가
항상 docker bridge 내부의 Caddy 컨테이너 IP(예: ``172.19.0.7``) 로만 잡혀서
모든 사용자의 접속 IP 가 동일하게 기록되는 회귀가 있었다. 실제 클라이언트
IP 는 Caddy 가 자동 부여하는 ``X-Forwarded-For`` 헤더에 들어온다.

``X-Forwarded-For`` 는 "client, proxy1, proxy2" 형식이라 *leftmost* 가 원본
클라이언트. 헤더가 없으면(직접 호출) ``request.client.host`` 로 폴백한다.

주의: 외부에서 임의로 ``X-Forwarded-For`` 헤더를 직접 박을 수도 있지만, 우리
환경은 Caddy 외에는 backend 포트가 호스트 외부로 노출되지 않으므로
신뢰 가능하다. 이후 다중 프록시가 추가될 경우엔 IP 화이트리스트 검증이
필요해질 수 있다.
"""

from __future__ import annotations

from starlette.requests import Request


def client_ip(request: Request) -> str | None:
    xff = request.headers.get("x-forwarded-for")
    if xff:
        first = xff.split(",", 1)[0].strip()
        if first:
            return first[:45]  # IPv6 최대 길이
    real = request.headers.get("x-real-ip")
    if real:
        return real.strip()[:45]
    return request.client.host if request.client else None
