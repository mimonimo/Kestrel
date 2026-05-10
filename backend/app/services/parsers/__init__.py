from app.services.parsers.base import (
    BaseParser,
    ParsedProduct,
    ParsedReference,
    ParsedVulnerability,
)
from app.services.parsers.exploit_db import ExploitDbParser
from app.services.parsers.github_advisory import GithubAdvisoryParser
from app.services.parsers.mitre import MitreParser
from app.services.parsers.nvd import NvdParser

ALL_PARSERS: list[type[BaseParser]] = [
    NvdParser,
    ExploitDbParser,
    GithubAdvisoryParser,
    MitreParser,
]

__all__ = [
    "ALL_PARSERS",
    "BaseParser",
    "ExploitDbParser",
    "GithubAdvisoryParser",
    "MitreParser",
    "NvdParser",
    "ParsedProduct",
    "ParsedReference",
    "ParsedVulnerability",
]
