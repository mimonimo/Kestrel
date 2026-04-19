"""Bootstrap seed data.

Populates the DB with a curated set of realistic CVEs so the dashboard
always has something visible before real ingestion has a chance to run.
Idempotent: exits early if *any* vulnerabilities exist.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlalchemy import func, select

from app.core.database import SessionLocal
from app.core.logging import get_logger
from app.models import (
    AffectedProduct,
    OsFamily,
    RefType,
    Severity,
    Source,
    Vulnerability,
    VulnerabilityReference,
    VulnerabilityType,
)
from app.services.search_service import index_many

log = get_logger(__name__)


@dataclass
class _SeedProduct:
    vendor: str
    product: str
    os_family: OsFamily = OsFamily.OTHER
    version_range: str | None = None


@dataclass
class _SeedRef:
    url: str
    ref_type: RefType = RefType.ADVISORY


@dataclass
class _SeedVuln:
    cve_id: str
    title: str
    description: str
    summary: str
    cvss_score: float | None
    severity: Severity | None
    source: Source
    source_url: str
    published_at: datetime
    modified_at: datetime
    cvss_vector: str | None = None
    type_labels: list[str] = field(default_factory=list)
    products: list[_SeedProduct] = field(default_factory=list)
    refs: list[_SeedRef] = field(default_factory=list)


def _dt(iso: str) -> datetime:
    return datetime.fromisoformat(iso.replace("Z", "+00:00"))


SEED: list[_SeedVuln] = [
    _SeedVuln(
        cve_id="CVE-2026-31415",
        title="OpenSSL 3.5 — Heap buffer overflow in TLS 1.3 handshake",
        description=(
            "OpenSSL 3.5.0 이전 버전의 TLS 1.3 핸드셰이크 처리에서 힙 버퍼 오버플로가 발생하여 "
            "원격 공격자가 임의 코드를 실행할 수 있습니다. 특수하게 조작된 ClientHello "
            "메시지를 통해 트리거됩니다."
        ),
        summary="OpenSSL 3.5 이전의 TLS 1.3 핸드셰이크에서 힙 버퍼 오버플로. 원격 코드 실행 가능. 즉시 패치 권장.",
        cvss_score=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        severity=Severity.CRITICAL,
        source=Source.NVD,
        source_url="https://nvd.nist.gov/vuln/detail/CVE-2026-31415",
        published_at=_dt("2026-04-17T09:15:00Z"),
        modified_at=_dt("2026-04-18T12:00:00Z"),
        type_labels=["RCE"],
        products=[
            _SeedProduct("OpenSSL", "OpenSSL", OsFamily.LINUX, "< 3.5.0"),
            _SeedProduct("OpenSSL", "OpenSSL", OsFamily.WINDOWS, "< 3.5.0"),
            _SeedProduct("OpenSSL", "OpenSSL", OsFamily.MACOS, "< 3.5.0"),
        ],
        refs=[
            _SeedRef("https://www.openssl.org/news/secadv/20260417.txt", RefType.ADVISORY),
            _SeedRef("https://github.com/openssl/openssl/commit/deadbeef", RefType.PATCH),
        ],
    ),
    _SeedVuln(
        cve_id="CVE-2026-20482",
        title="Microsoft Windows Kernel — Elevation of Privilege via NTFS race",
        description=(
            "Windows 11 24H2 및 Windows Server 2025의 NTFS 드라이버에서 TOCTOU 레이스 "
            "컨디션이 존재하여 로컬 공격자가 SYSTEM 권한을 획득할 수 있습니다."
        ),
        summary="Windows 11/Server 2025 NTFS TOCTOU. 로컬 권한 상승 (SYSTEM). 2026년 4월 패치데이 반영.",
        cvss_score=7.8,
        cvss_vector="CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H",
        severity=Severity.HIGH,
        source=Source.NVD,
        source_url="https://nvd.nist.gov/vuln/detail/CVE-2026-20482",
        published_at=_dt("2026-04-15T18:00:00Z"),
        modified_at=_dt("2026-04-15T18:00:00Z"),
        type_labels=["Auth"],
        products=[
            _SeedProduct("Microsoft", "Windows 11", OsFamily.WINDOWS, "24H2"),
            _SeedProduct("Microsoft", "Windows Server", OsFamily.WINDOWS, "2025"),
        ],
        refs=[
            _SeedRef("https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-20482"),
        ],
    ),
    _SeedVuln(
        cve_id="CVE-2026-0081",
        title="Next.js Middleware — Authorization bypass via crafted header",
        description=(
            "Next.js 15.0.3 이전 버전의 미들웨어가 특정 헤더 조합을 처리할 때 인증 검사를 "
            "건너뛰어 보호된 라우트에 인증 없이 접근할 수 있는 취약점입니다."
        ),
        summary="Next.js 15.0.3 미만 미들웨어 인가 우회. 보호 라우트 무인증 접근 가능.",
        cvss_score=8.2,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        severity=Severity.HIGH,
        source=Source.GITHUB_ADVISORY,
        source_url="https://github.com/vercel/next.js/security/advisories/GHSA-xxxx-xxxx-xxxx",
        published_at=_dt("2026-04-10T10:00:00Z"),
        modified_at=_dt("2026-04-12T08:30:00Z"),
        type_labels=["Auth"],
        products=[_SeedProduct("Vercel", "Next.js", OsFamily.OTHER, "< 15.0.3")],
        refs=[
            _SeedRef("https://github.com/vercel/next.js/security/advisories/GHSA-xxxx-xxxx-xxxx"),
            _SeedRef("https://github.com/vercel/next.js/pull/99999", RefType.PATCH),
        ],
    ),
    _SeedVuln(
        cve_id="CVE-2026-11007",
        title="WordPress Plugin CommentPro — Stored XSS in comment field",
        description=(
            "인기 WordPress 댓글 플러그인에서 입력 검증 미흡으로 저장형 XSS가 발생합니다. "
            "로그인한 관리자가 댓글을 열람하면 공격자 스크립트가 실행됩니다."
        ),
        summary="WordPress 플러그인 저장형 XSS. 관리자 계정 탈취 경로 존재.",
        cvss_score=6.1,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        severity=Severity.MEDIUM,
        source=Source.EXPLOIT_DB,
        source_url="https://www.exploit-db.com/exploits/52001",
        published_at=_dt("2026-04-08T00:00:00Z"),
        modified_at=_dt("2026-04-08T00:00:00Z"),
        type_labels=["XSS"],
        products=[_SeedProduct("Acme", "CommentPro", OsFamily.OTHER, "< 4.2.1")],
        refs=[_SeedRef("https://www.exploit-db.com/exploits/52001", RefType.EXPLOIT)],
    ),
    _SeedVuln(
        cve_id="CVE-2026-8822",
        title="Apache Tomcat — SQL injection in management console",
        description=(
            "Apache Tomcat 11.0.x 관리 콘솔의 사용자 조회 엔드포인트에서 파라미터 바인딩 "
            "누락으로 SQL 인젝션이 발생합니다."
        ),
        summary="Apache Tomcat 11.0.x 관리 콘솔 SQL 인젝션. 외부 노출 시 즉시 차단 권장.",
        cvss_score=8.8,
        severity=Severity.HIGH,
        source=Source.NVD,
        source_url="https://nvd.nist.gov/vuln/detail/CVE-2026-8822",
        published_at=_dt("2026-04-05T14:00:00Z"),
        modified_at=_dt("2026-04-06T09:00:00Z"),
        type_labels=["SQLi"],
        products=[_SeedProduct("Apache", "Tomcat", OsFamily.LINUX, "11.0.0 - 11.0.5")],
        refs=[_SeedRef("https://tomcat.apache.org/security-11.html")],
    ),
    _SeedVuln(
        cve_id="CVE-2026-7711",
        title="macOS 15 — Sandbox escape via XPC service",
        description=(
            "macOS Sequoia 15 이전의 특정 시스템 XPC 서비스에서 권한 검증 결함으로 앱 "
            "샌드박스 탈출이 가능합니다."
        ),
        summary="macOS 15 미만 XPC 샌드박스 탈출. App Store 앱으로도 악용 가능성.",
        cvss_score=7.5,
        severity=Severity.HIGH,
        source=Source.NVD,
        source_url="https://nvd.nist.gov/vuln/detail/CVE-2026-7711",
        published_at=_dt("2026-03-28T00:00:00Z"),
        modified_at=_dt("2026-03-30T00:00:00Z"),
        type_labels=["Auth"],
        products=[_SeedProduct("Apple", "macOS", OsFamily.MACOS, "< 15.0")],
        refs=[_SeedRef("https://support.apple.com/en-us/HT215000")],
    ),
    _SeedVuln(
        cve_id="CVE-2026-4455",
        title="Linux Kernel io_uring — Use-after-free in submission path",
        description=(
            "Linux 커널 6.12 미만의 io_uring 서브시스템에서 Use-after-free 결함이 존재하여 "
            "비특권 사용자가 권한 상승을 수행할 수 있습니다."
        ),
        summary="Linux io_uring UAF. 비특권 사용자 → root 권한 상승. 여러 배포판 패치 배포 중.",
        cvss_score=7.8,
        cvss_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        severity=Severity.HIGH,
        source=Source.NVD,
        source_url="https://nvd.nist.gov/vuln/detail/CVE-2026-4455",
        published_at=_dt("2026-03-20T00:00:00Z"),
        modified_at=_dt("2026-03-22T00:00:00Z"),
        type_labels=["Auth"],
        products=[_SeedProduct("Linux", "Kernel", OsFamily.LINUX, "< 6.12")],
        refs=[
            _SeedRef("https://kernel.org/security/CVE-2026-4455"),
            _SeedRef("https://lore.kernel.org/io-uring/patch-url", RefType.PATCH),
        ],
    ),
    _SeedVuln(
        cve_id="CVE-2026-2301",
        title="Chrome V8 — Type confusion leads to RCE (0-day exploited ITW)",
        description=(
            "Google Chrome 128 이전 버전의 V8 엔진에서 Type Confusion 취약점이 야생에서 "
            "악용되고 있습니다. 악성 웹페이지 방문만으로 임의 코드 실행이 가능합니다."
        ),
        summary="Chrome V8 제로데이 (ITW 악용 중). 페이지 방문만으로 RCE. 브라우저 즉시 업데이트.",
        cvss_score=9.6,
        severity=Severity.CRITICAL,
        source=Source.NVD,
        source_url="https://nvd.nist.gov/vuln/detail/CVE-2026-2301",
        published_at=_dt("2026-03-18T12:00:00Z"),
        modified_at=_dt("2026-03-19T00:00:00Z"),
        type_labels=["RCE"],
        products=[
            _SeedProduct("Google", "Chrome", OsFamily.WINDOWS, "< 128.0.6613.84"),
            _SeedProduct("Google", "Chrome", OsFamily.MACOS, "< 128.0.6613.84"),
            _SeedProduct("Google", "Chrome", OsFamily.LINUX, "< 128.0.6613.84"),
        ],
        refs=[
            _SeedRef("https://chromereleases.googleblog.com/2026/03/stable-channel-update-for-desktop.html"),
        ],
    ),
    _SeedVuln(
        cve_id="CVE-2026-13500",
        title="Spring Framework — SpEL injection in data binding",
        description=(
            "Spring Framework 6.3.x의 파라미터 바인딩 처리에서 SpEL 식이 평가되어 원격 코드 "
            "실행이 가능합니다. Spring Boot 3.5 기반 애플리케이션 다수 영향."
        ),
        summary="Spring Framework SpEL 인젝션. Spring Boot 3.5 기반 앱 RCE 가능.",
        cvss_score=9.1,
        severity=Severity.CRITICAL,
        source=Source.GITHUB_ADVISORY,
        source_url="https://github.com/spring-projects/spring-framework/security/advisories/GHSA-xxxx-2026-13500",
        published_at=_dt("2026-03-12T00:00:00Z"),
        modified_at=_dt("2026-03-14T00:00:00Z"),
        type_labels=["RCE"],
        products=[_SeedProduct("VMware", "Spring Framework", OsFamily.OTHER, "6.3.0 - 6.3.7")],
        refs=[_SeedRef("https://spring.io/security/cve-2026-13500")],
    ),
    _SeedVuln(
        cve_id="CVE-2026-9912",
        title="Android MediaServer — Integer overflow in H.265 decoder",
        description=(
            "Android 15의 MediaServer 프로세스 H.265 디코더에서 정수 오버플로가 발생, "
            "조작된 영상 파일을 재생하면 미디어 권한으로 코드가 실행됩니다."
        ),
        summary="Android 15 MediaServer H.265 정수 오버플로. 악성 영상 재생 시 RCE.",
        cvss_score=8.8,
        severity=Severity.HIGH,
        source=Source.NVD,
        source_url="https://nvd.nist.gov/vuln/detail/CVE-2026-9912",
        published_at=_dt("2026-03-05T00:00:00Z"),
        modified_at=_dt("2026-03-07T00:00:00Z"),
        type_labels=["RCE"],
        products=[_SeedProduct("Google", "Android", OsFamily.ANDROID, "15.0 - 15.2")],
        refs=[_SeedRef("https://source.android.com/security/bulletin/2026-03-01")],
    ),
    _SeedVuln(
        cve_id="CVE-2026-5566",
        title="iOS WebKit — Memory corruption via malicious SVG",
        description=(
            "iOS 18.3 이전의 WebKit 엔진에서 특수 SVG 처리 시 메모리 변조가 발생, 악성 "
            "웹페이지 방문만으로 임의 코드 실행이 가능합니다."
        ),
        summary="iOS 18.3 WebKit 제로데이. 악성 SVG 페이지 방문 시 RCE.",
        cvss_score=9.0,
        severity=Severity.CRITICAL,
        source=Source.NVD,
        source_url="https://nvd.nist.gov/vuln/detail/CVE-2026-5566",
        published_at=_dt("2026-02-28T00:00:00Z"),
        modified_at=_dt("2026-03-01T00:00:00Z"),
        type_labels=["RCE"],
        products=[_SeedProduct("Apple", "iOS", OsFamily.IOS, "< 18.3")],
        refs=[_SeedRef("https://support.apple.com/en-us/HT215100")],
    ),
    _SeedVuln(
        cve_id="CVE-2026-7022",
        title="GitLab CE/EE — SSRF via import from URL",
        description=(
            "GitLab 17.6 이전 버전의 프로젝트 URL 가져오기 기능에서 서버 측 요청 위조(SSRF)"
            "가 발생합니다. 내부망 엔드포인트 스캐닝에 악용 가능."
        ),
        summary="GitLab 17.6 미만 SSRF. 내부망 스캐닝/메타데이터 접근에 악용 가능.",
        cvss_score=7.7,
        severity=Severity.HIGH,
        source=Source.GITHUB_ADVISORY,
        source_url="https://about.gitlab.com/releases/2026/02/20/security-release/",
        published_at=_dt("2026-02-20T00:00:00Z"),
        modified_at=_dt("2026-02-21T00:00:00Z"),
        type_labels=["SSRF"],
        products=[_SeedProduct("GitLab", "GitLab CE/EE", OsFamily.LINUX, "< 17.6")],
        refs=[_SeedRef("https://gitlab.com/gitlab-org/cves/-/blob/master/2026/CVE-2026-7022.json")],
    ),
    _SeedVuln(
        cve_id="CVE-2026-3388",
        title="Cisco IOS XE — Authentication bypass in Web UI",
        description=(
            "Cisco IOS XE의 웹 UI에서 인증 우회 취약점이 발견되어 비인증 원격 공격자가 "
            "관리자 권한으로 명령을 실행할 수 있습니다."
        ),
        summary="Cisco IOS XE 웹 UI 인증 우회. 비인증 RCE. 공공기관 집중 타겟팅 정황.",
        cvss_score=10.0,
        severity=Severity.CRITICAL,
        source=Source.NVD,
        source_url="https://nvd.nist.gov/vuln/detail/CVE-2026-3388",
        published_at=_dt("2026-02-15T00:00:00Z"),
        modified_at=_dt("2026-02-16T00:00:00Z"),
        type_labels=["Auth", "RCE"],
        products=[_SeedProduct("Cisco", "IOS XE", OsFamily.OTHER, "< 17.14.2")],
        refs=[
            _SeedRef(
                "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-webui-2026"
            )
        ],
    ),
    _SeedVuln(
        cve_id="CVE-2026-1800",
        title="PostgreSQL — Privilege escalation via CREATE SCHEMA race",
        description=(
            "PostgreSQL 17.2 이전 버전의 CREATE SCHEMA 처리에서 권한 체크 레이스가 발생하여 "
            "일반 사용자가 다른 스키마 객체에 대한 권한을 우회할 수 있습니다."
        ),
        summary="PostgreSQL 17.2 미만 CREATE SCHEMA 권한 우회. 권한 분리 정책 무력화 가능.",
        cvss_score=6.5,
        severity=Severity.MEDIUM,
        source=Source.NVD,
        source_url="https://nvd.nist.gov/vuln/detail/CVE-2026-1800",
        published_at=_dt("2026-02-08T00:00:00Z"),
        modified_at=_dt("2026-02-10T00:00:00Z"),
        type_labels=["Auth"],
        products=[_SeedProduct("PostgreSQL", "PostgreSQL", OsFamily.LINUX, "< 17.2")],
        refs=[_SeedRef("https://www.postgresql.org/support/security/CVE-2026-1800/")],
    ),
    _SeedVuln(
        cve_id="CVE-2026-0502",
        title="nginx — Request smuggling via malformed Content-Length",
        description=(
            "nginx 1.27 이전 버전이 업스트림 서버로 요청을 전달할 때 Content-Length 헤더를 "
            "잘못 파싱하여 요청 밀반입(request smuggling)이 가능합니다."
        ),
        summary="nginx 1.27 미만 HTTP request smuggling. WAF 우회 및 세션 가로채기 가능.",
        cvss_score=7.5,
        severity=Severity.HIGH,
        source=Source.NVD,
        source_url="https://nvd.nist.gov/vuln/detail/CVE-2026-0502",
        published_at=_dt("2026-01-25T00:00:00Z"),
        modified_at=_dt("2026-01-26T00:00:00Z"),
        type_labels=["Auth"],
        products=[_SeedProduct("F5", "nginx", OsFamily.LINUX, "< 1.27.0")],
        refs=[_SeedRef("https://nginx.org/en/security_advisories.html")],
    ),
]


async def seed_missing() -> None:
    """Insert any curated seed CVEs that aren't yet in the DB.

    Idempotent. Matches on ``cve_id`` so operator restarts don't duplicate rows,
    and prior partial ingestion runs don't block the seed from filling in the
    metadata-rich reference set the dashboard needs to demo filters."""
    inserted_ids: list[str] = []
    async with SessionLocal() as session:
        seed_ids = [s.cve_id for s in SEED]
        existing_ids = set(
            (
                await session.execute(
                    select(Vulnerability.cve_id).where(Vulnerability.cve_id.in_(seed_ids))
                )
            )
            .scalars()
            .all()
        )
        to_insert = [s for s in SEED if s.cve_id not in existing_ids]
        if not to_insert:
            log.info("seed.all_present", total=len(SEED))
            return

        # Resolve / create VulnerabilityType rows shared across the seed set.
        label_set = {lbl for v in to_insert for lbl in v.type_labels}
        if label_set:
            existing_types = (
                (
                    await session.execute(
                        select(VulnerabilityType).where(VulnerabilityType.name.in_(label_set))
                    )
                )
                .scalars()
                .all()
            )
            by_name = {t.name: t for t in existing_types}
            for label in label_set - set(by_name):
                t = VulnerabilityType(name=label)
                session.add(t)
                by_name[label] = t
            await session.flush()
        else:
            by_name = {}

        for sv in to_insert:
            products = [
                AffectedProduct(
                    vendor=p.vendor,
                    product=p.product,
                    os_family=p.os_family,
                    version_range=p.version_range,
                )
                for p in sv.products
            ]
            refs = [VulnerabilityReference(url=r.url, ref_type=r.ref_type) for r in sv.refs]
            types = [by_name[lbl] for lbl in sv.type_labels if lbl in by_name]
            vuln = Vulnerability(
                cve_id=sv.cve_id,
                title=sv.title,
                description=sv.description,
                summary=sv.summary,
                cvss_score=sv.cvss_score,
                cvss_vector=sv.cvss_vector,
                severity=sv.severity,
                published_at=sv.published_at,
                modified_at=sv.modified_at,
                source=sv.source,
                source_url=sv.source_url,
                raw_data={"seeded": True},
                types=types,
                affected_products=products,
                references=refs,
            )
            session.add(vuln)
            inserted_ids.append(sv.cve_id)

        await session.commit()
        log.info("seed.inserted", count=len(inserted_ids))

    # Push the newly-inserted rows into Meilisearch.
    if inserted_ids:
        async with SessionLocal() as session:
            from sqlalchemy.orm import selectinload

            rows = (
                (
                    await session.execute(
                        select(Vulnerability)
                        .where(Vulnerability.cve_id.in_(inserted_ids))
                        .options(
                            selectinload(Vulnerability.types),
                            selectinload(Vulnerability.affected_products),
                            selectinload(Vulnerability.references),
                        )
                    )
                )
                .scalars()
                .unique()
                .all()
            )
            try:
                index_many(list(rows))
            except Exception:
                log.warning("seed.meili_index_failed", message="will retry on next ingest cycle")


# Backwards-compat alias — older callers expect seed_if_empty().
seed_if_empty = seed_missing


def _now() -> datetime:
    return datetime.now(timezone.utc)
