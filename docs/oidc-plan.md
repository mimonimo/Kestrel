# 외부 OIDC 로그인 도입 계획 (장기)

> 상태: **계획(Plan)** — 미구현. 현재 인증은 자체 이메일/비밀번호 + HttpOnly 쿠키 JWT.
> 목적: Google / GitHub / 일반 OIDC IdP 로 소셜 로그인 + (선택) 조직 SSO 를 추가하되,
> 기존 쿠키-JWT 세션 구조와 권한 모델을 그대로 재사용한다.

## 1. 목표 / 비목표

**목표**
- Authorization Code + PKCE 기반 외부 OIDC 로그인 (Google, GitHub OAuth, 그리고 generic OIDC discovery 지원).
- 기존 로컬 계정과 **계정 연결(account linking)** — 같은 이메일이면 한 사용자로 수렴.
- 발급 결과는 **기존과 동일한 자체 세션 쿠키(JWT)** — 다운스트림(권한·미들웨어) 무변경.

**비목표(초기)**
- 자체 OIDC Provider 가 되는 것(우리가 IdP 노릇). 우리는 **Relying Party(RP)** 만.
- SAML. 필요 시 별도.
- 토큰 introspection/refresh 회전 고도화 — 1차는 로그인 시점 1회 교환만.

## 2. 표준 흐름 (Authorization Code + PKCE)

```
브라우저            Kestrel 백엔드(RP)             IdP(Google 등)
  |  GET /auth/oidc/{provider}/start              |
  |------------------------------>|  state+nonce+PKCE 생성, 세션에 저장
  |   302 to IdP authorize url ---|-------------->|
  |  (사용자 IdP 로그인/동의)                      |
  |<--------- 302 callback?code&state ------------|
  |  GET /auth/oidc/{provider}/callback?code&state|
  |------------------------------>|  state 검증 → code+verifier 로 token 교환
  |                               |--- token endpoint --->|
  |                               |<-- id_token(JWT)+access -|
  |                               |  id_token 서명검증(JWKS)+nonce+aud+iss+exp
  |                               |  이메일/ sub 추출 → 사용자 upsert + 연결
  |   302 to / (Set-Cookie: access_token=우리JWT)|
  |<------------------------------|
```

핵심 검증(보안): `state`(CSRF), `nonce`(replay), `iss`/`aud`/`exp`/서명(JWKS) 전부 확인.
PKCE 로 code interception 방지. state/nonce/verifier 는 **단기 Redis 키**(TTL 10분)에 저장.

## 3. 데이터 모델 변경

신규 테이블 `user_identities` (한 사용자에 여러 IdP 연결):

```
user_identities
  id            uuid pk
  user_id       uuid fk -> users.id  (on delete cascade)
  provider      text   -- 'google' | 'github' | 'oidc:<name>'
  subject       text   -- IdP 의 sub (provider 내 고유)
  email         text   -- 연결 당시 이메일(참고용)
  created_at    timestamptz
  UNIQUE(provider, subject)
```

`users` 테이블:
- `password_hash` 를 **nullable** 로 (소셜 전용 계정은 비번 없음).
- 소셜 전용 계정이 비밀번호 변경 시도하면 "비밀번호 미설정 — 먼저 설정하세요" 분기.
- `email_verified bool` 추가 권장(IdP 가 verified 준 경우 신뢰).

Alembic 마이그레이션 1개. 기존 행은 `password_hash` 유지(로컬 계정).

## 4. 계정 연결(Linking) 규칙

1. `(provider, subject)` 가 이미 있으면 → 그 사용자로 로그인.
2. 없고, IdP 이메일이 **verified** 이며 기존 로컬 사용자와 일치 → 자동 연결(같은 사람).
   - 보안 주의: 이메일 verified=false IdP 는 자동 연결 **금지**(계정 탈취 방지) → 비번 확인 요구.
3. 둘 다 없으면 → 신규 사용자 생성(`password_hash=NULL`), `user_identities` 행 추가.
4. 로그인 상태에서 `/settings`의 "계정 연결"로 명시적 연결도 지원(2차).

`is_admin_email()` 자동 admin 부여 규칙은 그대로 적용(소셜 가입에도 동일).

## 5. 백엔드 설계 (FastAPI)

- 라이브러리: **`authlib`** (OIDC discovery + JWKS 캐시 + token 교환 검증 내장) 권장.
- 신규 모듈 `app/core/oidc.py`: provider 레지스트리(설정 기반), discovery 문서/JWKS 캐싱.
- 신규 라우터 `app/api/v1/oidc.py`:
  - `GET /auth/oidc/{provider}/start` → 302 redirect
  - `GET /auth/oidc/{provider}/callback` → 검증 후 `_set_auth_cookie()` 재사용 → 302 `/`
- **세션 발급은 기존 `issue_access_token()` + `_set_auth_cookie()` 그대로** → deps/권한 무변경.
- 설정(env): provider별 `client_id`/`client_secret`/`issuer`/`scopes`/`redirect_uri`.
  - secret 은 기존 패턴대로 `.env`(prod 는 user_data 주입 또는 Secrets Manager).

## 6. 설정/인프라

- redirect_uri: `https://kestrel.day/api/v1/auth/oidc/{provider}/callback` (도메인 확정 후).
- Caddy 는 이미 `/api/*` 를 backend 로 보내므로 추가 라우팅 불필요.
- IdP 콘솔에 redirect_uri 등록 필요(Google Cloud Console / GitHub OAuth App).
- CORS 무관(서버사이드 redirect 흐름이라 브라우저 직접 호출 아님).

## 7. 프론트엔드

- 로그인/회원가입 페이지에 "Google 로 계속하기 / GitHub 로 계속하기" 버튼.
- 버튼 → `window.location = /api/v1/auth/oidc/{provider}/start` (단순 redirect).
- 콜백 후 백엔드가 쿠키 심고 `/` 로 보내면, 기존 `auth-context` 가 `/auth/me` 로 사용자 로드.
- `/settings` 에 "연결된 로그인" 섹션(연결/해제, 마지막 사용 IdP).

## 8. 보안 체크리스트

- [ ] state(CSRF) + nonce(replay) + PKCE 필수, 단기 TTL.
- [ ] id_token: 서명(JWKS), `iss`/`aud`/`exp`/`iat`/`nonce` 전부 검증.
- [ ] 미검증 이메일 IdP 자동 계정연결 금지.
- [ ] open redirect 방지 — 로그인 후 `next` 파라미터는 **자체 도메인 경로만** 허용(화이트리스트).
- [ ] 소셜 전용 계정 비밀번호 없음 → 로컬 로그인 분기 처리.
- [ ] IdP client_secret 은 로그/응답 비노출(기존 토큰 유출 방지 원칙 준수).
- [ ] 로그인 콜백에도 기존 rate limit 유사 보호 적용(콜백 남용 방지).

## 9. 단계별 롤아웃

1. **M1 — 모델/마이그레이션**: `user_identities` + `users.password_hash` nullable + `email_verified`.
2. **M2 — Google 1종**: authlib 연동, start/callback, 자동 연결(verified 한정), 쿠키 발급.
3. **M3 — 프론트**: 로그인 버튼 + 콜백 UX + 설정 "연결된 로그인".
4. **M4 — GitHub + generic OIDC**: provider 레지스트리 일반화(issuer discovery).
5. **M5 — 계정 관리**: 명시적 연결/해제, 소셜 전용 계정 비번 설정 플로우, 감사 로그.

## 10. 현재 코드와의 접점(재사용)

- `app/core/security.py::issue_access_token` / `auth.py::_set_auth_cookie` → 세션 발급 동일.
- `deps.py::get_current_user` / `require_admin` → 무변경.
- `is_admin_email()` → 소셜 가입 admin 매핑 동일.
- 쿠키 정책(HttpOnly/Secure/SameSite=Lax) → 그대로.

> 요약: 외부 IdP 는 "**로그인 수단 추가**"일 뿐, 세션·권한 체계는 지금 것을 100% 재사용한다.
> 가장 작은 1차 범위는 **M1 + M2(Google) + M3** 이며, 도메인(kestrel.day) 확정 후 시작하는 것이 redirect_uri 등록상 깔끔하다.
