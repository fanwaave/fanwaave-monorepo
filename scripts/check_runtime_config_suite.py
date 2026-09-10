#!/usr/bin/env python3
"""Fail-closed semantic checks for the repository-root runtime TOML suite."""
from __future__ import annotations

import hashlib
import json
import re
import tomllib
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
FILES = (
    ".ores-mw.toml",
    ".ores-rl.toml",
    ".ores-lru.toml",
    ".auth-shared.toml",
    ".fanwaave-cfg.toml",
    ".cli-flags.toml",
)
ENV_KEY = re.compile(r"^[A-Z][A-Z0-9_]{1,127}$")
SHARED_AUTH_REVISION = "52b7ac7fbf0c7c169684f613eda923f3aa6c82e9"
SHARED_AUTH_REPOSITORY = "https://github.com/shared-auth/shared-auth-interfaces"


def need(ok: bool, code: str) -> None:
    if not ok:
        raise ValueError(code)


def load(name: str) -> dict[str, Any]:
    path = ROOT / name
    need(path.is_file() and not path.is_symlink(), f"{name}:regular-file-required")
    data = path.read_bytes()
    need(len(data) <= 256 * 1024, f"{name}:file-too-large")
    value = tomllib.loads(data.decode("utf-8"))
    need(isinstance(value, dict), f"{name}:object-required")
    return value


def check_middleware(value: dict[str, Any]) -> None:
    need(value.get("schema_version") == 1, "mw:schema-version")
    need(value.get("repository_mode") == "hybrid", "mw:hybrid-required")
    need(value.get("allow_overlapping_roots") is True, "mw:same-root-overlap-must-be-explicit")
    targets = value.get("targets")
    need(isinstance(targets, list) and len(targets) == 2, "mw:two-explicit-targets-required")
    by_role = {target.get("role"): target for target in targets if isinstance(target, dict)}
    need(set(by_role) == {"client", "server"}, "mw:client-server-roles-required")
    need(by_role["client"].get("roots") == ["."], "mw:client-root")
    need(by_role["server"].get("roots") == ["."], "mw:server-root")
    need(by_role["client"].get("middleware") == "propagation-only", "mw:client-propagation-only")
    need(by_role["server"].get("middleware") == "disabled", "mw:server-must-not-invent-stack")
    headers = by_role["client"].get("propagate_headers")
    need(isinstance(headers, list) and "traceparent" in headers, "mw:traceparent-required")
    need("stack_config" not in by_role["client"], "mw:client-stack-forbidden")


def check_rate_limit(value: dict[str, Any]) -> None:
    need(value.get("schemaVersion") == "ores.rate-limit.config.v1", "rl:schema-version")
    need(value.get("layout") == "combined", "rl:combined-required")
    client = value.get("client")
    server = value.get("server")
    need(isinstance(client, dict) and client.get("root") == ".", "rl:client-same-root")
    need(isinstance(server, dict) and server.get("root") == ".", "rl:server-same-root")
    need("redisUrlEnv" not in client and "keyHmacEnv" not in client, "rl:client-secret-projection-forbidden")
    hmac_env = server.get("keyHmacEnv")
    need(isinstance(hmac_env, str) and ENV_KEY.fullmatch(hmac_env) is not None, "rl:hmac-env-name-required")
    policies = value.get("policies")
    need(isinstance(policies, list) and policies, "rl:policy-required")
    for policy in policies:
        need(isinstance(policy, dict), "rl:policy-object-required")
        need(policy.get("enforcementMode") == "observe-only", "rl:rollout-must-be-observe-only")
        need(policy.get("consistencyMode") == "advisory", "rl:rollout-must-be-advisory")


def check_lru(value: dict[str, Any]) -> None:
    need(value.get("protocol") == "ores.lru-config.v1", "lru:protocol")
    need(value.get("roles") == ["client", "server"], "lru:roles")
    redis = value.get("redis")
    need(isinstance(redis, dict), "lru:redis-config-required")
    redis_env = redis.get("urlEnv")
    need(isinstance(redis_env, str) and ENV_KEY.fullmatch(redis_env) is not None, "lru:redis-env-name-required")
    need(redis.get("reconcileIntervalMs") == 180000, "lru:repair-interval")
    caches = value.get("caches")
    need(isinstance(caches, list) and caches, "lru:cache-required")
    identities: set[tuple[str, str]] = set()
    roles: set[str] = set()
    for cache in caches:
        need(isinstance(cache, dict), "lru:cache-object-required")
        role, name = cache.get("role"), cache.get("name")
        need(role in {"client", "server"} and isinstance(name, str) and name, "lru:cache-identity")
        identity = (role, name)
        need(identity not in identities, "lru:duplicate-role-cache")
        identities.add(identity)
        roles.add(role)
        if role == "client":
            need(cache.get("syncMode") == "local_only", "lru:client-local-only")
    need(roles == {"client", "server"}, "lru:client-server-cache-required")


def check_shared_auth(value: dict[str, Any]) -> None:
    need(not (ROOT / ".shared-auth.toml").exists(), "auth:dual-alias-presence-forbidden")
    need(value.get("schema_version") == 1, "auth:schema-version")
    compatibility = value.get("compatibility")
    need(isinstance(compatibility, dict), "auth:compatibility-required")
    need(compatibility.get("repository") == SHARED_AUTH_REPOSITORY, "auth:repository-provenance")
    need(compatibility.get("commit") == SHARED_AUTH_REVISION, "auth:exact-reviewed-revision")
    serialized = json.dumps(value, sort_keys=True).lower()
    for forbidden in ("password", "private_key", "client_secret", "service_role_key", "database_url", "dsn"):
        need(forbidden not in serialized, f"auth:secret-field-forbidden:{forbidden}")


def check_fanwaave(value: dict[str, Any], cli: dict[str, Any]) -> None:
    need(value.get("version") == 1 and value.get("mode") == "hybrid", "fanwaave:hybrid-v1")
    need(value.get("strict") is True, "fanwaave:strict-required")
    flags2env = value.get("flags2env")
    need(isinstance(flags2env, dict), "fanwaave:flags2env-required")
    need(flags2env.get("contract") == ".cli-flags.toml", "fanwaave:cli-contract")
    need(flags2env.get("require_audit") is True, "fanwaave:flags2env-audit-required")
    need(flags2env.get("precedence") == "argv-over-env", "fanwaave:precedence")
    need(value.get("client", {}).get("enabled") is True, "fanwaave:client-enabled")
    need(value.get("server", {}).get("enabled") is True, "fanwaave:server-enabled")

    env_entries = value.get("env")
    need(isinstance(env_entries, list) and env_entries, "fanwaave:env-bindings-required")
    env_names: set[str] = set()
    secret_envs: set[str] = set()
    for entry in env_entries:
        need(isinstance(entry, dict), "fanwaave:env-object-required")
        key = entry.get("key")
        need(isinstance(key, str) and ENV_KEY.fullmatch(key) is not None, "fanwaave:env-key-name-required")
        need(key not in env_names, "fanwaave:duplicate-env-key")
        env_names.add(key)
        if entry.get("secret") is True:
            need("default" not in entry, "fanwaave:secret-default-forbidden")
            secret_envs.add(key)

    need(cli.get("env", {}).get("load") is False, "flags2env:dotenv-load-forbidden")
    need(cli.get("parse", {}).get("allow_unknown") is False, "flags2env:unknown-flags-must-fail")
    flags = cli.get("flags")
    need(isinstance(flags, dict), "flags2env:flags-required")
    flag_envs = {definition.get("env") for definition in flags.values() if isinstance(definition, dict)}
    need(not (secret_envs & flag_envs), "flags2env:secret-env-must-not-be-cli-flag")


def main() -> int:
    values = {name: load(name) for name in FILES}
    check_middleware(values[".ores-mw.toml"])
    check_rate_limit(values[".ores-rl.toml"])
    check_lru(values[".ores-lru.toml"])
    check_shared_auth(values[".auth-shared.toml"])
    check_fanwaave(values[".fanwaave-cfg.toml"], values[".cli-flags.toml"])
    receipt = {
        "schema": "fanwaave.runtime-config-suite-admission/v1",
        "status": "passed",
        "files": {
            name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
            for name in FILES
        },
        "sameRootRoles": ["client", "server"],
        "sharedAuthCompatibilityRevision": SHARED_AUTH_REVISION,
    }
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
