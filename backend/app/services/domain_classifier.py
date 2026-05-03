"""Domain inference for cross-domain vulnerability classification (PR 10-B).

Why a separate axis from ``vulnerability_types`` (RCE/XSS/...): types
describe the *weakness class* (the "how"), domains describe the
*affected technology surface* (the "where"). One CVE can span multiple
domains — e.g. an audio codec parser bug embedded in an SSH client
threatens both ``media`` and ``auth``. The user gave that exact example
when asking for sub-categorization.

Pure function, no DB. The orchestrator computes it once per upsert and
the backfill script reuses the same function across existing rows so
behavior is identical.

Signal layers, in decreasing reliability:
  1. ``affected_products`` vendor/product strings (CPE-derived, strong)
  2. Title + description keyword regex (covers products without CPE
     and the "leaks across domains" cases that vendor alone misses)

CWE is intentionally not used here — CWE describes weakness class, not
technology surface. CWE-787 covers buffer overflows in audio codecs
*and* in kernel drivers; using it for domain inference muddies both.
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.services.parsers.base import ParsedVulnerability


# Controlled vocabulary. Order doesn't matter (we return sorted list)
# but keep semantic groups together for readability.
DOMAINS: tuple[str, ...] = (
    "kernel",
    "os",
    "browser",
    "web-server",
    "web-framework",
    "database",
    "media",
    "network",
    "mail",
    "auth",
    "crypto",
    "runtime",
    "mobile",
    "virtualization",
    "office",
    "enterprise",
    "iot",
    "messaging",
)


def _rx(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


# Vendor/product → domain. Matched against ``"<vendor> <product>"``.
# Use word boundaries to avoid false positives ("opera" must not match
# "operation"). Each entry can contribute one domain; a single CVE can
# match many entries.
_PRODUCT_RULES: list[tuple[str, re.Pattern[str]]] = [
    ("kernel", _rx(r"\blinux_kernel\b|\bwindows.*kernel\b|\bxnu\b|\bfreebsd_kernel\b|\bnetbsd_kernel\b|\bopenbsd_kernel\b")),
    ("os", _rx(r"\b(windows_(xp|vista|7|8|10|11|server))\b|\bmac_os_x\b|\bmacos\b|\biphone_os\b|\bipados\b|\bopensolaris\b|\bsolaris\b|\bubuntu_linux\b|\bdebian_linux\b|\brhel\b|\bfedora\b|\bcentos\b")),
    ("browser", _rx(r"\bfirefox\b|\bchrome\b|\bchromium\b|\bsafari\b|\bopera_browser\b|\binternet_explorer\b|\bedge\b|\bseamonkey\b|\bwebkit\b|\bv8\b|\bgecko\b|\bblink\b")),
    ("web-server", _rx(r"\b(apache(_http_server)?|httpd|tomcat|jetty|nginx|iis|caddy|lighttpd|h2o|envoy|haproxy)\b")),
    ("web-framework", _rx(r"\bwordpress\b|\bdrupal\b|\bjoomla\b|\btypo3\b|\bphpmyadmin\b|\bspring(_framework)?\b|\bnext\.?js\b|\bdjango\b|\brails\b|\blaravel\b|\bexpress\b|\basp\.?net\b|\bsymfony\b|\bcodeigniter\b|\bmoodle\b|\bmagento\b|\bopencart\b|\bprestashop\b")),
    ("database", _rx(r"\bpostgresql\b|\bmysql\b|\bmariadb\b|\bmongodb\b|\bredis\b|\bsqlite\b|\boracle_database\b|\bmssql\b|\belasticsearch\b|\bclickhouse\b|\bcouchdb\b|\bcassandra\b|\binfluxdb\b")),
    ("media", _rx(r"\blibpng\b|\blibjpeg\b|\bquicktime\b|\bflash_player\b|\bpoppler\b|\bffmpeg\b|\bmediaserver\b|\baudio\w*\b|\bcodec\b|\bxine\b|\bvlc\b|\bgstreamer\b|\bimagemagick\b|\bpillow\b|\bgraphicsmagick\b|\blibtiff\b|\blibwebp\b|\blibav\b|\bgimp\b|\bavidemux\b|\bmplayer\b|\bopenh264\b|\bx264\b|\bx265\b|\blibvpx\b|\bopus\b|\bvorbis\b|\blame_mp3\b")),
    ("network", _rx(r"\bcisco\b|\bjuniper\b|\bf5_(networks|big-?ip)?\b|\bbig-?ip\b|\bpaloalto\b|\bfortinet\b|\barista\b|\bextreme_networks\b|\bmikrotik\b|\bunifi\b|\bnetgear\b|\btp-link\b|\bd-link\b|\bbarracuda\b|\bcheckpoint\b|\bsonicwall\b|\bzyxel\b|\bhuawei.*router\b|\bopenwrt\b|\bdd-wrt\b")),
    ("mail", _rx(r"\bpostfix\b|\bexim\b|\bsendmail\b|\bthunderbird\b|\bdovecot\b|\bzimbra\b|\bexchange_server\b|\bmailman\b|\bsquirrelmail\b|\broundcube\b")),
    ("auth", _rx(r"\bopenssh\b|\bssh\w*server\b|\bkerberos\b|\bopenldap\b|\bfreeradius\b|\bshibboleth\b|\bkeycloak\b|\bauth0\b|\bokta\b|\bpam\b|\bsamba\b")),
    ("crypto", _rx(r"\bopenssl\b|\bgnutls\b|\blibgcrypt\b|\bgnupg\b|\bgpg\b|\bbouncycastle\b|\bnss\b|\bmbedtls\b|\bwolfssl\b|\bnetwork_security_services\b")),
    ("runtime", _rx(r"\b(jdk|jre|java_se|openjdk)\b|\bphp\b|\bpython\b|\bnode(\.js)?\b|\bruby\b|\b\.net_framework\b|\bdotnet\b|\bperl\b|\bgolang\b|\brust\b|\bllvm\b")),
    ("mobile", _rx(r"\bandroid\b|\bmediaserver\b|\bwhatsapp\b|\btelegram\b|\bmobile_safari\b|\bsamsung.*mobile\b|\bxiaomi.*mobile\b")),
    ("virtualization", _rx(r"\bvmware\b|\besxi\b|\bvsphere\b|\bxen\b|\bkvm\b|\bqemu\b|\bvirtualbox\b|\bdocker\b|\bkubernetes\b|\bk8s\b|\bopenshift\b|\bproxmox\b|\bhyper-?v\b|\bcontainerd\b|\brunc\b")),
    ("office", _rx(r"\bacrobat\b|\bacrobat_reader\b|\bfoxit\b|\bpoppler\b|\bms_office\b|\boffice_2[0-9]+\b|\bword_processor\b|\bexcel\b|\bpowerpoint\b|\boutlook\b|\blibreoffice\b|\bopenoffice\b")),
    ("enterprise", _rx(r"\bsap\b|\bsalesforce\b|\bibm\b|\bwebsphere\b|\boracle_(business|enterprise|fusion|peoplesoft|siebel|jd_edwards)\b|\bservicenow\b|\bworkday\b|\bsharepoint\b|\bdynamics\b")),
    ("iot", _rx(r"\bqualcomm\b|\bbroadcom\b|\bmediatek\b|\bnordic_semiconductor\b|\besp32\b|\besp8266\b|\barduino\b|\braspberry_pi\b|\bhomekit\b|\bsmartthings\b|\bzigbee\b|\bz-wave\b|\bbaseband\b|\bfirmware\b|\bipcamera\b|\bnvr\b|\bdvr\b")),
    ("messaging", _rx(r"\basterisk\b|\bjabber\b|\bxmpp\b|\bircd?\b|\bsignal_messenger\b|\bsignal_app\b|\brocket\.chat\b|\bmattermost\b|\belement_messenger\b|\bsynapse\b|\bmatrix\b")),
]

# Title / description keyword → domain. Matched against the lowercased
# concatenation of title + description. These pick up the cases that
# vendor/product alone miss — including the "audio bug threatens SSH"
# crossover the user called out.
_TEXT_RULES: list[tuple[str, re.Pattern[str]]] = [
    ("kernel", _rx(r"\bkernel\b|\bring0\b|\bring 0\b|\bsyscall\b|\bkernel-mode\b|\bkmode\b|\bksmbd\b|\bnetfilter\b|\bio_uring\b|\bbpf\b|\bebpf\b|\bcgroup\b")),
    ("browser", _rx(r"\bv8\b|\bspidermonkey\b|\bjavascriptcore\b|\bblink renderer\b|\bweb assembly\b|\bwasm\b|\bbrowser\b|\bmicrosoft edge\b|\bchromium-based\b")),
    ("web-server", _rx(r"\breverse proxy\b|\brequest smuggling\b|\bhttp/2\b|\bhttp/3\b|\bweb server\b|\bvirtual host\b")),
    ("web-framework", _rx(r"\bspel injection\b|\btemplate injection\b|\bssti\b|\borm injection\b|\broute handler\b|\bmiddleware\b|\bdjango\b|\bflask\b|\bnext\.?js\b|\blaravel\b|\bwordpress\b|\bdrupal\b|\bjoomla\b|\bmagento\b|\btypo3\b|\bphpmyadmin\b|\bplugin for wp\b|\bwp[- ]plugin\b|\bwp[- ]admin\b")),
    ("database", _rx(r"\bsql injection\b|\bsqli\b|\bdatabase server\b|\bnosql injection\b|\bquery planner\b|\bstored procedure\b")),
    ("media", _rx(r"\baudio\b|\bvideo\b|\bcodec\b|\bdecoder\b|\bmp3\b|\bmp4\b|\bh\.?26[45]\b|\baac\b|\bopus\b|\bvorbis\b|\bdts\b|\bdolby\b|\balsa\b|\bpulseaudio\b|\bjack(d| audio)\b|\bsoundcard\b|\bfont parser\b|\bjpeg2?\b|\bpng\b|\btiff\b|\bgif\b|\bsvg\b|\bwebp\b|\bheic\b|\bdng\b|\braw image\b|\bicc profile\b")),
    ("network", _rx(r"\bsnmp\b|\bbgp\b|\bospf\b|\bigmp\b|\barp\b|\bdhcp\b|\bdns server\b|\bbind9\b|\bisc dhcp\b|\bipv6\b|\bquic\b|\btls handshake\b|\brouter\b|\bswitch firmware\b|\bnetwork interface\b|\bvpn\b|\bipsec\b|\bopenvpn\b|\bwireguard\b|\bstrongswan\b")),
    ("mail", _rx(r"\bsmtp\b|\bimap\b|\bpop3\b|\bemail client\b|\bmail (transport|delivery|server)\b|\bmime\b|\bspam filter\b|\bspf\b|\bdkim\b|\bdmarc\b")),
    ("auth", _rx(r"\bssh\b|\bopenssh\b|\bsftp\b|\bauthentication bypass\b|\bcredential\b|\bpassword reset\b|\bsession (fixation|hijack)\b|\bsso\b|\bsaml\b|\boauth2?\b|\boidc\b|\bjwt\b|\bldap injection\b|\bkerberos\b|\bpam module\b|\bsudo\b|\bprivilege.*escalation\b")),
    ("crypto", _rx(r"\btls\b|\bssl\b|\bcertificate (parser|validation|chain)\b|\bx\.?509\b|\bcipher\b|\baes\b|\brsa\b|\becdsa\b|\bcurve25519\b|\bdiffie-?hellman\b|\bsignature (verification|forgery)\b|\bhmac\b|\bhash collision\b|\bweak random\b|\brng bias\b|\bside.?channel\b|\bpadding oracle\b|\bbleichenbacher\b")),
    ("runtime", _rx(r"\bjvm\b|\bcpython\b|\bnode runtime\b|\bv8 engine\b|\bphp interpreter\b|\bdotnet runtime\b|\bgo runtime\b|\bjit compiler\b|\bbytecode\b|\bgarbage collector\b")),
    ("mobile", _rx(r"\bandroid\b|\bios\b|\bipad\b|\biphone\b|\bmobile app\b|\bplay store\b|\bapp store\b|\bbinder\b|\bzygote\b|\bart runtime\b|\bxnu\b")),
    ("virtualization", _rx(r"\bhypervisor\b|\bvm escape\b|\bguest-to-host\b|\bcontainer escape\b|\bnamespace\b|\bcontainer runtime\b|\bvirtual machine\b|\bcontainerd\b|\brunc\b|\bdocker engine\b|\bkubelet\b")),
    ("office", _rx(r"\bpdf (parser|reader|renderer)\b|\bdocx\b|\bdoc file\b|\bxlsx\b|\bpptx\b|\boffice document\b|\bmacro execution\b|\bvba\b|\bole2?\b|\bdocument viewer\b")),
    ("enterprise", _rx(r"\berp\b|\bcrm\b|\bbusiness suite\b|\bworkflow engine\b|\bsap netweaver\b|\bservicenow\b|\bsharepoint\b|\boutlook web access\b|\bowa\b")),
    ("iot", _rx(r"\bfirmware\b|\bsmart (home|device|tv|camera)\b|\bcamera firmware\b|\bsoho router\b|\bbaseband\b|\biot device\b|\bembedded device\b|\bnvr\b|\bdvr\b|\bset-top box\b")),
    ("messaging", _rx(r"\bvoip\b|\bsip\b|\bsdp\b|\brtp\b|\brtcp\b|\bwebrtc\b|\bxmpp\b|\bmatrix protocol\b|\birc\b|\bchat server\b|\bmessaging server\b")),
]


def infer_domains(parsed: "ParsedVulnerability") -> list[str]:
    """Return a sorted, deduped list of domain strings.

    Empty list means "no signal at all". Callers should treat that as
    "uncategorized" rather than "everything" — domain filters use
    overlap (``&&``) semantics so an empty array matches no chip.
    """
    found: set[str] = set()

    # 1. Vendor/product — concatenate vendor and product so a single regex
    #    can match either side ("openssh" might appear in product, but
    #    "ssh" might appear only in description).
    for prod in parsed.affected_products:
        haystack = f"{prod.vendor or ''} {prod.product or ''}"
        for domain, rx in _PRODUCT_RULES:
            if rx.search(haystack):
                found.add(domain)

    # 2. Title + description keyword regex.
    text = f"{parsed.title or ''}\n{parsed.description or ''}"
    for domain, rx in _TEXT_RULES:
        if rx.search(text):
            found.add(domain)

    return sorted(found)


def infer_domains_from_row(
    title: str,
    description: str | None,
    products: list[tuple[str | None, str | None]],
) -> list[str]:
    """Backfill helper — same logic as ``infer_domains`` but takes raw
    fields instead of a ``ParsedVulnerability`` so it can be used over
    DB rows without reconstructing the parser dataclass."""
    found: set[str] = set()
    for vendor, product in products:
        haystack = f"{vendor or ''} {product or ''}"
        for domain, rx in _PRODUCT_RULES:
            if rx.search(haystack):
                found.add(domain)
    text = f"{title or ''}\n{description or ''}"
    for domain, rx in _TEXT_RULES:
        if rx.search(text):
            found.add(domain)
    return sorted(found)
