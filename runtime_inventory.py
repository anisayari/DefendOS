from __future__ import annotations

import ipaddress
import os
import re
import shlex
import subprocess
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


_CACHE: dict[str, Any] = {"timestamp": 0.0, "payload": None}

USER_PROCESS_RE = re.compile(r'"([^"]+)",pid=(\d+),fd=(\d+)')
SYSTEMD_UNIT_RE = re.compile(r"/([^/]+\.service)(?:/|$)")

PROCESS_TYPE_HINTS: list[tuple[tuple[str, ...], str, str]] = [
    (("sshd", "sshd:"), "openssh", "OpenSSH server handling remote shell access."),
    (("nginx",), "nginx", "Nginx reverse proxy or web server."),
    (("apache2", "httpd"), "apache", "Apache HTTP server."),
    (("caddy",), "caddy", "Caddy web server or reverse proxy."),
    (("traefik",), "traefik", "Traefik edge proxy or ingress router."),
    (("haproxy",), "haproxy", "HAProxy load balancer or TCP/HTTP proxy."),
    (("docker", "dockerd"), "docker", "Docker daemon managing containers and images."),
    (("containerd",), "containerd", "Container runtime used by Docker or Kubernetes."),
    (("kubelet",), "kubernetes", "Kubernetes node agent."),
    (("redis-server", "redis"), "redis", "Redis in-memory data store."),
    (("postgres", "postmaster"), "postgresql", "PostgreSQL database server."),
    (("mysqld", "mariadbd", "mariadb"), "mysql", "MySQL or MariaDB database server."),
    (("mongod",), "mongodb", "MongoDB database server."),
    (("fail2ban-server",), "fail2ban", "Fail2ban intrusion prevention daemon."),
    (("cron", "crond"), "cron", "Cron scheduler executing recurring jobs."),
    (("rsyslogd", "syslog-ng"), "logging", "System logging daemon."),
    (("systemd", "init"), "systemd", "System and service manager."),
    (("node", "npm", "pnpm", "yarn", "next-server"), "node", "Node.js application runtime."),
    (("python", "python3", "gunicorn", "uvicorn", "celery", "flask", "django-admin"), "python", "Python application runtime."),
    (("php-fpm", "php-fpm8", "php-fpm7", "php"), "php", "PHP runtime or PHP-FPM worker."),
    (("java",), "java", "Java application runtime."),
    (("ruby", "puma", "sidekiq"), "ruby", "Ruby application runtime."),
    (("go",), "go", "Go application runtime."),
    (("dotnet",), "dotnet", ".NET application runtime."),
    (("deno",), "deno", "Deno JavaScript runtime."),
]

CONFIG_PATH_PATTERNS = {
    "node": ["package.json", ".env", "ecosystem.config.js", "ecosystem.config.cjs", "next.config.js", "next.config.mjs", "vite.config.ts", "vite.config.js"],
    "python": ["pyproject.toml", "requirements.txt", ".env", "gunicorn.conf.py", "manage.py", "uwsgi.ini"],
    "php": [".env", "composer.json"],
    "ruby": ["Gemfile", "config.ru", ".env"],
    "java": ["application.yml", "application.yaml", "application.properties"],
    "nginx": ["/etc/nginx/nginx.conf"],
    "caddy": ["/etc/caddy/Caddyfile"],
    "redis": ["/etc/redis/redis.conf"],
    "postgresql": ["/etc/postgresql", "/var/lib/postgresql"],
    "mysql": ["/etc/mysql/my.cnf", "/etc/mysql/mysql.conf.d"],
    "docker": ["/etc/docker/daemon.json"],
}


def collect_runtime_inventory(cache_ttl_seconds: int = 5) -> dict[str, Any]:
    now = time.time()
    cached_payload = _CACHE.get("payload")
    cached_timestamp = float(_CACHE.get("timestamp") or 0.0)
    if cached_payload and now - cached_timestamp < cache_ttl_seconds:
        return cached_payload

    sockets = collect_listening_sockets()
    pid_to_sockets: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for socket_info in sockets:
        for process_ref in socket_info["process_refs"]:
            pid_to_sockets[process_ref["pid"]].append(
                {
                    "protocol": socket_info["protocol"],
                    "state": socket_info["state"],
                    "bind_host": socket_info["bind_host"],
                    "port": socket_info["port"],
                    "exposure": socket_info["exposure"],
                    "label": f'{socket_info["port"]}/{socket_info["protocol"]}',
                }
            )

    processes = collect_processes(pid_to_sockets)
    summary = summarize_inventory(processes, sockets)
    runtime_families = build_runtime_families(processes)

    payload = {
        "generated_at": utc_now_text(),
        "summary": summary,
        "runtime_families": runtime_families,
        "ports": sockets,
        "processes": processes,
    }
    _CACHE["timestamp"] = now
    _CACHE["payload"] = payload
    return payload


def utc_now_text() -> str:
    return datetime.now(timezone.utc).isoformat()


def run_text(command: list[str], *, timeout: int = 5) -> str:
    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )
    return completed.stdout or ""


def collect_listening_sockets() -> list[dict[str, Any]]:
    lines = run_text(["ss", "-lntupH"]).splitlines()
    ports: list[dict[str, Any]] = []
    for line in lines:
        parts = line.split(None, 6)
        if len(parts) < 6:
            continue
        proto, state = parts[0], parts[1]
        local_address = parts[4]
        process_blob = parts[6] if len(parts) >= 7 else ""
        bind_host, port = split_host_port(local_address)
        if port is None:
            continue
        process_refs = parse_process_refs(process_blob)
        ports.append(
            {
                "protocol": proto,
                "state": state,
                "bind_host": bind_host,
                "port": port,
                "port_text": str(port),
                "exposure": classify_bind_exposure(bind_host),
                "process_refs": process_refs,
                "process_names": [ref["name"] for ref in process_refs],
            }
        )

    ports.sort(key=lambda item: (exposure_rank(item["exposure"]), item["port"], item["protocol"]))
    return ports


def split_host_port(local_address: str) -> tuple[str, int | None]:
    text = local_address.strip()
    if not text:
        return "", None

    if text.startswith("[") and "]:" in text:
        host, port_text = text.rsplit("]:", 1)
        host = host[1:]
    elif ":" in text:
        host, port_text = text.rsplit(":", 1)
    else:
        return text, None

    port_text = port_text.strip()
    if not port_text.isdigit():
        return host or "*", None
    return host or "*", int(port_text)


def parse_process_refs(process_blob: str) -> list[dict[str, Any]]:
    refs: list[dict[str, Any]] = []
    for name, pid_text, fd_text in USER_PROCESS_RE.findall(process_blob):
        try:
            pid = int(pid_text)
            fd = int(fd_text)
        except ValueError:
            continue
        refs.append({"name": name, "pid": pid, "fd": fd})
    return refs


def classify_bind_exposure(bind_host: str) -> str:
    host = bind_host.strip("[]")
    if host in {"*", "0.0.0.0", "::"}:
        return "public"
    if host in {"127.0.0.1", "::1", "localhost"}:
        return "local"

    try:
        ip_value = ipaddress.ip_address(host)
    except ValueError:
        return "unknown"

    if ip_value.is_loopback:
        return "local"
    if ip_value.is_private or ip_value.is_link_local:
        return "private"
    return "public"


def exposure_rank(value: str) -> int:
    order = {"public": 0, "private": 1, "local": 2, "unknown": 3}
    return order.get(value, 9)


def collect_processes(pid_to_sockets: dict[int, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    output = run_text(
        [
            "ps",
            "-ww",
            "-eo",
            "pid=",
            "-o",
            "ppid=",
            "-o",
            "user=",
            "-o",
            "pcpu=",
            "-o",
            "pmem=",
            "-o",
            "etime=",
            "-o",
            "comm=",
            "-o",
            "args=",
            "--sort=-pcpu",
        ],
        timeout=8,
    )
    processes: list[dict[str, Any]] = []
    for line in output.splitlines():
        parts = line.strip().split(None, 7)
        if len(parts) < 7:
            continue

        pid_text, ppid_text, user, cpu_text, mem_text, elapsed, comm = parts[:7]
        args = parts[7] if len(parts) == 8 else comm

        try:
            pid = int(pid_text)
            ppid = int(ppid_text)
            cpu_percent = float(cpu_text)
            memory_percent = float(mem_text)
        except ValueError:
            continue

        cmdline_parts = safe_shlex_split(args)
        cwd = read_proc_link(pid, "cwd")
        exe = read_proc_link(pid, "exe")
        systemd_unit = read_systemd_unit(pid)
        runtime, runtime_description = infer_runtime(comm, exe, cmdline_parts)
        entrypoint = infer_entrypoint(runtime, cmdline_parts)
        app_name = infer_application_name(comm, cwd, systemd_unit, entrypoint)
        sockets = sorted(pid_to_sockets.get(pid, []), key=lambda item: (exposure_rank(item["exposure"]), item["port"], item["protocol"]))
        config_candidates = infer_config_candidates(runtime, systemd_unit, cwd, cmdline_parts)

        process_info = {
            "pid": pid,
            "ppid": ppid,
            "user": user,
            "cpu_percent": round(cpu_percent, 1),
            "memory_percent": round(memory_percent, 1),
            "elapsed": elapsed,
            "command": comm,
            "args": args,
            "runtime": runtime,
            "runtime_description": runtime_description,
            "application_name": app_name,
            "entrypoint": entrypoint,
            "cwd": cwd,
            "exe": exe,
            "systemd_unit": systemd_unit,
            "ports": sockets,
            "port_count": len(sockets),
            "public_port_count": sum(1 for item in sockets if item["exposure"] == "public"),
            "config_candidates": config_candidates,
            "primary_config": config_candidates[0] if config_candidates else None,
        }
        process_info["description"] = describe_process(process_info)
        processes.append(process_info)

    processes.sort(
        key=lambda item: (
            -item["public_port_count"],
            -item["port_count"],
            -item["cpu_percent"],
            item["application_name"].lower(),
            item["pid"],
        )
    )
    return processes


def safe_shlex_split(value: str) -> list[str]:
    try:
        return shlex.split(value)
    except ValueError:
        return value.split()


def read_proc_link(pid: int, name: str) -> str | None:
    path = Path("/proc") / str(pid) / name
    try:
        return os.readlink(path)
    except OSError:
        return None


def read_systemd_unit(pid: int) -> str | None:
    path = Path("/proc") / str(pid) / "cgroup"
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

    for line in content.splitlines():
        match = SYSTEMD_UNIT_RE.search(line)
        if match:
            return match.group(1)
    return None


def infer_runtime(comm: str, exe: str | None, cmdline_parts: list[str]) -> tuple[str, str]:
    primary_tokens = [
        comm.lower(),
        Path(exe).name.lower() if exe else "",
        Path(cmdline_parts[0]).name.lower() if cmdline_parts else "",
    ]
    secondary_tokens = [Path(part).name.lower() for part in cmdline_parts[1:6]]
    for patterns, runtime, description in PROCESS_TYPE_HINTS:
        if any(match_runtime_pattern(pattern, primary_tokens, secondary_tokens) for pattern in patterns):
            return runtime, description

    if comm.startswith("[") and comm.endswith("]"):
        return "kernel", "Kernel worker or thread."
    return "native", "Linux process with no specific runtime fingerprint yet."


def match_runtime_pattern(pattern: str, primary_tokens: list[str], secondary_tokens: list[str]) -> bool:
    if not pattern:
        return False
    if pattern.endswith(":"):
        prefix = pattern[:-1]
        return any(token.startswith(prefix) for token in primary_tokens if token)
    return pattern in [token for token in primary_tokens + secondary_tokens if token]


def infer_entrypoint(runtime: str, cmdline_parts: list[str]) -> str | None:
    if not cmdline_parts:
        return None

    args = cmdline_parts[1:]
    if runtime == "python":
        if "-m" in args:
            index = args.index("-m")
            if index + 1 < len(args):
                return args[index + 1]
        for token in args:
            if not token or token == "-" or token.startswith("-"):
                continue
            return token
    elif runtime == "node":
        for token in args:
            if not token or token == "-" or token.startswith("-"):
                continue
            return token
    elif runtime == "java" and "-jar" in args:
        index = args.index("-jar")
        if index + 1 < len(args):
            return args[index + 1]
    elif runtime in {"ruby", "php", "go", "dotnet", "deno"}:
        for token in args:
            if not token or token == "-" or token.startswith("-"):
                continue
            return token
    for token in args:
        if not token or token == "-" or token.startswith("-"):
            continue
        if "/" in token or token.endswith((".py", ".js", ".mjs", ".cjs", ".jar", ".rb", ".php", ".html", ".ts")):
            return token
    return None


def infer_application_name(comm: str, cwd: str | None, systemd_unit: str | None, entrypoint: str | None) -> str:
    if systemd_unit and not systemd_unit.startswith("user@"):
        return systemd_unit.removesuffix(".service")

    if entrypoint and not entrypoint.startswith(("-", ":")):
        entry_path = Path(entrypoint)
        if entry_path.name:
            if entry_path.suffix and entry_path.stem not in {"index", "main", "server", "app"}:
                return entry_path.stem
            if entry_path.parent.name not in {"", "/", ".", "bin", "sbin", "usr", "lib", "libexec"}:
                return entry_path.parent.name
            return entry_path.name

    if cwd:
        cwd_name = Path(cwd).name
        if cwd_name and cwd_name not in {"root", "home"}:
            return cwd_name

    return comm


def infer_config_candidates(runtime: str, systemd_unit: str | None, cwd: str | None, cmdline_parts: list[str]) -> list[str]:
    candidates: list[str] = []

    for index, token in enumerate(cmdline_parts):
        lowered = token.lower()
        if lowered in {"-c", "--config", "--config-file", "--config-path"} and index + 1 < len(cmdline_parts):
            candidates.append(cmdline_parts[index + 1])
            continue
        if "=" in token:
            key, value = token.split("=", 1)
            if "config" in key.lower() or value.endswith((".conf", ".json", ".yaml", ".yml", ".toml", ".ini")):
                candidates.append(value)
                continue
        if token.endswith((".conf", ".json", ".yaml", ".yml", ".toml", ".ini", ".env")):
            candidates.append(token)

    if systemd_unit:
        for systemd_path in (
            Path("/etc/systemd/system") / systemd_unit,
            Path("/lib/systemd/system") / systemd_unit,
            Path("/usr/lib/systemd/system") / systemd_unit,
        ):
            if systemd_path.exists():
                candidates.append(str(systemd_path))

    if cwd:
        cwd_path = Path(cwd)
        for relative in CONFIG_PATH_PATTERNS.get(runtime, []):
            path = cwd_path / relative
            if path.exists():
                candidates.append(str(path))

    for absolute_path in CONFIG_PATH_PATTERNS.get(runtime, []):
        if absolute_path.startswith("/"):
            path = Path(absolute_path)
            if path.exists():
                candidates.append(str(path))

    if runtime == "node" and cwd:
        cwd_path = Path(cwd)
        for pattern in ("*config*.js", "*config*.cjs", "*config*.mjs", "*config*.ts", "*config*.json"):
            for filename in cwd_path.glob(pattern):
                candidates.append(str(filename))
    if runtime == "python" and cwd:
        cwd_path = Path(cwd)
        for filename in cwd_path.glob("*.ini"):
            candidates.append(str(filename))
        for filename in cwd_path.glob("*.conf"):
            candidates.append(str(filename))

    return unique_preserve_order(candidates)


def unique_preserve_order(paths: list[str]) -> list[str]:
    seen: set[str] = set()
    unique: list[str] = []
    for raw_path in paths:
        path = raw_path.strip()
        if not path:
            continue
        if path in seen:
            continue
        seen.add(path)
        unique.append(path)
    return unique


def describe_process(process_info: dict[str, Any]) -> str:
    runtime_description = process_info["runtime_description"]
    app_name = process_info["application_name"]
    entrypoint = process_info.get("entrypoint")
    ports = process_info.get("ports") or []
    systemd_unit = process_info.get("systemd_unit")

    sentences = [f"{app_name}: {runtime_description}"]
    if entrypoint:
        sentences.append(f"Entrypoint guess: {entrypoint}.")
    if ports:
        public_ports = [socket["label"] for socket in ports if socket["exposure"] == "public"][:4]
        local_ports = [socket["label"] for socket in ports if socket["exposure"] != "public"][:4]
        if public_ports:
            sentences.append(f"Public listeners: {', '.join(public_ports)}.")
        elif local_ports:
            sentences.append(f"Local listeners: {', '.join(local_ports)}.")
    if systemd_unit:
        sentences.append(f"Managed by {systemd_unit}.")
    return " ".join(sentences)


def summarize_inventory(processes: list[dict[str, Any]], sockets: list[dict[str, Any]]) -> dict[str, Any]:
    public_ports = [socket for socket in sockets if socket["exposure"] == "public"]
    private_ports = [socket for socket in sockets if socket["exposure"] == "private"]
    local_ports = [socket for socket in sockets if socket["exposure"] == "local"]
    runtime_counter = Counter(process["runtime"] for process in processes)
    busy_processes = processes[:8]

    return {
        "process_count": len(processes),
        "listening_port_count": len(sockets),
        "public_port_count": len(public_ports),
        "private_port_count": len(private_ports),
        "local_port_count": len(local_ports),
        "runtime_count": len(runtime_counter),
        "top_runtimes": [
            {"runtime": runtime, "count": count}
            for runtime, count in runtime_counter.most_common(8)
        ],
        "hot_processes": [
            {
                "pid": process["pid"],
                "application_name": process["application_name"],
                "runtime": process["runtime"],
                "cpu_percent": process["cpu_percent"],
                "memory_percent": process["memory_percent"],
                "port_count": process["port_count"],
            }
            for process in busy_processes
        ],
    }


def build_runtime_families(processes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for process in processes:
        runtime = process["runtime"]
        family = grouped.setdefault(
            runtime,
            {
                "runtime": runtime,
                "count": 0,
                "public_port_count": 0,
                "process_names": [],
            },
        )
        family["count"] += 1
        family["public_port_count"] += process["public_port_count"]
        family["process_names"].append(process["application_name"])

    families = list(grouped.values())
    for family in families:
        unique_names: list[str] = []
        seen: set[str] = set()
        for name in family["process_names"]:
            if name in seen:
                continue
            seen.add(name)
            unique_names.append(name)
        family["sample_processes"] = unique_names[:5]
        del family["process_names"]

    families.sort(key=lambda item: (-item["public_port_count"], -item["count"], item["runtime"]))
    return families
