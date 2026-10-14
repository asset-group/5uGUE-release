"""Version configuration for RQ1 experiment versions (V1-V3, V3F) and full mode."""

from dataclasses import dataclass
from enum import Enum


class FuzzerVersion(str, Enum):
    V1 = "v1"  # Research tools (papers + web, no GitHub fetch, no batch)
    V2 = "v2"  # Research tools (papers + web + GitHub, no batch testing)
    V3 = "v3"  # No knowledge, full research tools + batch
    V3F = "v3f"  # No knowledge, filtered research tools (no papers, domain-restricted web) + batch
    FULL = "full"  # Current behavior (all knowledge + tools)


@dataclass(frozen=True)
class VersionConfig:
    version: FuzzerVersion
    include_crash_patterns: bool
    include_strategy_hints: bool
    load_known_crashes: bool
    load_global_kb: bool
    load_session_history: bool
    enable_local_papers: bool
    enable_web_tools: bool
    enable_github_fetch: (
        bool  # True = fetch_url has GitHub intelligence (blob→raw, tree→API)
    )
    enable_batch_testing: bool  # True = execute_test_batch is registered
    restrict_exploits_to_session: bool  # True = only see agent-created exploits
    # Tuple of domain strings to block in web search/fetch
    blocked_domains: tuple[str, ...] = ()


def get_version_config(version_str: str) -> VersionConfig:
    """Factory to create VersionConfig from a version string."""
    try:
        version = FuzzerVersion(version_str)
    except ValueError:
        valid = [v.value for v in FuzzerVersion]
        raise ValueError(f"Invalid version '{version_str}'. Must be one of: {valid}")

    if version == FuzzerVersion.V1:
        return VersionConfig(
            version=FuzzerVersion.V1,
            include_crash_patterns=False,
            include_strategy_hints=False,
            load_known_crashes=False,
            load_global_kb=False,
            load_session_history=False,
            enable_local_papers=True,
            enable_web_tools=True,
            enable_github_fetch=False,
            enable_batch_testing=False,
            restrict_exploits_to_session=True,
        )
    elif version == FuzzerVersion.V2:
        return VersionConfig(
            version=FuzzerVersion.V2,
            include_crash_patterns=False,
            include_strategy_hints=False,
            load_known_crashes=False,
            load_global_kb=False,
            load_session_history=False,
            enable_local_papers=True,
            enable_web_tools=True,
            enable_github_fetch=True,
            enable_batch_testing=False,
            restrict_exploits_to_session=True,
        )
    elif version == FuzzerVersion.V3:
        return VersionConfig(
            version=FuzzerVersion.V3,
            include_crash_patterns=False,
            include_strategy_hints=False,
            load_known_crashes=False,
            load_global_kb=False,
            load_session_history=False,
            enable_local_papers=True,
            enable_web_tools=True,
            enable_github_fetch=True,
            enable_batch_testing=True,
            restrict_exploits_to_session=True,
        )
    elif version == FuzzerVersion.V3F:
        return VersionConfig(
            version=FuzzerVersion.V3F,
            include_crash_patterns=False,
            include_strategy_hints=False,
            load_known_crashes=False,
            load_global_kb=False,
            load_session_history=False,
            enable_local_papers=False,
            enable_web_tools=True,
            enable_github_fetch=False,
            enable_batch_testing=True,
            restrict_exploits_to_session=True,
            blocked_domains=(
                "github.com",
                "githubusercontent.com",
                "gitlab.com",
                "gitlab.org",
                "asset-group.github.io",
            ),
        )
    else:  # FULL
        return VersionConfig(
            version=FuzzerVersion.FULL,
            include_crash_patterns=True,
            include_strategy_hints=True,
            load_known_crashes=True,
            load_global_kb=True,
            load_session_history=True,
            enable_local_papers=True,
            enable_web_tools=True,
            enable_github_fetch=True,
            enable_batch_testing=True,
            restrict_exploits_to_session=False,
        )
