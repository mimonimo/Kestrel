"""Smoke test for domain_classifier — covers fixture cases AND a real-DB
sample to detect regression and surface obvious gaps before backfill.

Fixture cases are deliberately picked to exercise BOTH signal layers
(vendor/product strong rules + title/description text rules) and the
"crossover" the user called out (audio + ssh).
"""
from __future__ import annotations

import asyncio
import sys
from collections import Counter

from sqlalchemy import select, text
from sqlalchemy.orm import selectinload

from app.core.database import SessionLocal
from app.models import Vulnerability
from app.services.domain_classifier import (
    DOMAINS,
    infer_domains_from_row,
)


# --- Fixtures: (label, title, description, products, expected_subset) ---
# expected_subset = domain strings that MUST be in the inferred set.
FIXTURES: list[tuple[str, str, str, list[tuple[str, str]], set[str]]] = [
    (
        "linux kernel use-after-free",
        "Linux Kernel use-after-free in netfilter",
        "An issue in the Linux kernel netfilter subsystem allows a local "
        "user to trigger a use-after-free via crafted nf_tables rules. "
        "kernel-mode privilege escalation possible.",
        [("linux", "linux_kernel")],
        {"kernel"},
    ),
    (
        "openssh auth bypass",
        "OpenSSH server authentication bypass",
        "A flaw in OpenSSH sshd allows authentication bypass when GSSAPI "
        "negotiation fails on a particular client greeting.",
        [("openbsd", "openssh")],
        {"auth"},
    ),
    (
        "audio codec → ssh process crossover",
        "Heap overflow in libopus codec embedded in remote shell client",
        "A malformed Opus audio frame causes a heap overflow in libopus. "
        "When processed by an SSH client that uses libopus for voice over "
        "SSH, the corruption can compromise the SSH session keys.",
        [("xiph", "libopus")],
        {"media", "auth"},
    ),
    (
        "firefox JS engine RCE",
        "Mozilla Firefox JavaScript engine type confusion",
        "A type confusion in the SpiderMonkey JIT compiler allows arbitrary "
        "code execution when rendering a crafted web page.",
        [("mozilla", "firefox")],
        {"browser"},
    ),
    (
        "wordpress plugin SQLi",
        "WordPress plugin SQL injection",
        "A SQL injection vulnerability in a WordPress plugin allows "
        "authenticated users to read arbitrary database rows.",
        [("wordpress", "wordpress")],
        {"web-framework", "database"},
    ),
    (
        "openssl cert validation",
        "OpenSSL X.509 certificate parser memory corruption",
        "A malformed X.509 certificate triggers a heap overflow in the "
        "OpenSSL certificate parser during TLS handshake.",
        [("openssl", "openssl")],
        {"crypto"},
    ),
    (
        "vmware esxi VM escape",
        "VMware ESXi guest-to-host escape",
        "A vulnerability in VMware ESXi hypervisor allows a guest VM "
        "to execute code on the host. Container escape from VM possible.",
        [("vmware", "esxi")],
        {"virtualization"},
    ),
    (
        "qualcomm baseband firmware",
        "Qualcomm baseband firmware overflow on Android handsets",
        "A buffer overflow in the Qualcomm cellular baseband firmware "
        "allows a remote attacker to execute code on Android mobile devices.",
        [("qualcomm", "msm_baseband")],
        {"iot", "mobile"},
    ),
    (
        "no signal — generic library",
        "Generic Foo library buffer overflow",
        "An overflow in libfoo allows arbitrary code execution.",
        [("foo_corp", "libfoo")],
        set(),
    ),
]


def run_fixtures() -> int:
    failures = 0
    for label, title, desc, products, expected in FIXTURES:
        got = set(infer_domains_from_row(title, desc, products))
        ok = expected.issubset(got)
        marker = "PASS" if ok else "FAIL"
        print(f"  [{marker}] {label}: got={sorted(got)} expected⊇{sorted(expected)}")
        if not ok:
            failures += 1
    return failures


async def run_db_sample(limit: int = 500) -> None:
    """Sample real CVEs to surface distribution and obvious gaps."""
    async with SessionLocal() as session:
        # Random sample so we don't keep hitting the same recent CVEs
        result = await session.execute(
            select(Vulnerability)
            .options(selectinload(Vulnerability.affected_products))
            .order_by(text("random()"))
            .limit(limit)
        )
        rows = result.scalars().all()

    counts: Counter[str] = Counter()
    multi = 0
    none = 0
    examples: dict[str, tuple[str, list[str]]] = {}
    for v in rows:
        products = [(p.vendor, p.product) for p in v.affected_products]
        domains = infer_domains_from_row(v.title or "", v.description or "", products)
        if not domains:
            none += 1
            continue
        if len(domains) >= 2:
            multi += 1
        for d in domains:
            counts[d] += 1
            if d not in examples:
                examples[d] = (v.cve_id, domains)

    print(f"\nSampled {len(rows)} rows. uncategorized={none} ({100*none//max(len(rows),1)}%) multi-domain={multi}")
    print("Domain distribution:")
    for domain in DOMAINS:
        c = counts.get(domain, 0)
        ex = examples.get(domain)
        ex_str = f"  e.g. {ex[0]} → {ex[1]}" if ex else ""
        print(f"  {domain:>16}: {c:>4}{ex_str}")


async def main() -> int:
    print("== Fixture cases ==")
    failures = run_fixtures()
    print(f"\n{'OK' if failures == 0 else 'FAIL'} — {failures} fixture failure(s)")

    print("\n== Real-DB sample (500 random rows) ==")
    await run_db_sample(500)

    return failures


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
