import bz2
import glob
import gzip
import lzma
import os
import re
from datetime import datetime, timedelta
from typing import Dict, Iterable, List, Optional, Tuple

SSH_LOG_GLOBS = [
    "/var/log/auth.log*",
    "/var/log/secure*",
    "/var/log/messages*",
]

UNSUPPORTED_ARCHIVE_SUFFIXES = (".zst",)

BRUTEFORCE_THRESHOLD = 8
BRUTEFORCE_WINDOW_SECONDS = 300

SPRAY_USER_THRESHOLD = 5
SPRAY_WINDOW_SECONDS = 600

INVALID_USER_THRESHOLD = 6
INVALID_USER_WINDOW_SECONDS = 600

SUCCESS_AFTER_FAIL_THRESHOLD = 5
SUCCESS_AFTER_FAIL_WINDOW_SECONDS = 900

PRIVILEGED_USERS = {
    "root",
    "admin",
    "administrator",
}

SERVICE_USERS = {
    "www-data",
    "apache",
    "nginx",
    "httpd",
    "www",
    "_www",
    "nobody",
    "daemon",
}

ANOMALY_PATTERNS: List[Tuple[str, str, str]] = [
    (r"POSSIBLE BREAK-IN ATTEMPT", "high", "аномалия SSH (possible break-in attempt)"),
    (r"Bad protocol version identification", "medium", "аномалия SSH-протокола"),
    (r"Did not receive identification string", "low", "сканирование порта SSH"),
    (r"Unable to negotiate", "medium", "ошибка согласования SSH"),
    (r"Connection closed by invalid user", "low", "закрытие соединения для invalid user"),
]

SEVERITY_LABELS = {
    "high": "ВЫСОКИЙ",
    "medium": "СРЕДНИЙ",
    "low": "НИЗКИЙ",
    "info": "ИНФО",
}

SYSLOG_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<proc>[^:]+):\s+(?P<msg>.*)$"
)

FAILED_RE = re.compile(
    r"Failed password for(?: invalid user)? (?P<user>[A-Za-z0-9_.-]+) from (?P<ip>[0-9A-Fa-f:.]+) port (?P<port>\d+)",
    re.IGNORECASE,
)
INVALID_USER_RE = re.compile(
    r"Invalid user (?P<user>[A-Za-z0-9_.-]+) from (?P<ip>[0-9A-Fa-f:.]+)",
    re.IGNORECASE,
)
NOT_ALLOWED_RE = re.compile(
    r"User (?P<user>[A-Za-z0-9_.-]+) from (?P<ip>[0-9A-Fa-f:.]+) not allowed",
    re.IGNORECASE,
)
ACCEPTED_RE = re.compile(
    r"Accepted (?P<method>\S+) for (?P<user>[A-Za-z0-9_.-]+) from (?P<ip>[0-9A-Fa-f:.]+) port (?P<port>\d+)",
    re.IGNORECASE,
)
FROM_IP_RE = re.compile(r"\bfrom\s+(?P<ip>[0-9A-Fa-f:.]+)", re.IGNORECASE)


def iter_files_in_dir(directory: str) -> Iterable[str]:
    try:
        for name in os.listdir(directory):
            path = os.path.join(directory, name)
            if os.path.isfile(path):
                yield path
    except OSError:
        return


def is_unsupported_archive(path: str) -> bool:
    return path.endswith(UNSUPPORTED_ARCHIVE_SUFFIXES)


def read_text_file(path: str) -> Optional[List[str]]:
    if is_unsupported_archive(path):
        return None

    try:
        if path.endswith(".gz"):
            opener = gzip.open
        elif path.endswith(".xz"):
            opener = lzma.open
        elif path.endswith(".bz2"):
            opener = bz2.open
        else:
            opener = open

        with opener(path, "rt", encoding="utf-8", errors="replace") as f:
            return f.read().splitlines()
    except (OSError, EOFError, gzip.BadGzipFile, lzma.LZMAError):
        return None


def parse_syslog_line(line: str) -> Tuple[Optional[str], str]:
    match = SYSLOG_RE.match(line)
    if not match:
        return None, line.strip()
    return match.group("ts"), match.group("msg")


def parse_timestamp(ts_str: Optional[str]) -> Optional[datetime]:
    if not ts_str:
        return None
    try:
        year = datetime.now().year
        return datetime.strptime(f"{year} {ts_str}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None


def dedupe_paths(paths: List[str]) -> List[str]:
    deduped: List[str] = []
    seen = set()
    for path in paths:
        if path not in seen:
            deduped.append(path)
            seen.add(path)
    return deduped


def discover_ssh_log_paths() -> List[str]:
    paths: List[str] = []
    for pattern in SSH_LOG_GLOBS:
        for path in sorted(glob.glob(pattern)):
            if os.path.isfile(path) and not is_unsupported_archive(path):
                paths.append(path)
    return dedupe_paths(paths)


def extract_ip(msg: str) -> str:
    match = FROM_IP_RE.search(msg)
    if match:
        return match.group("ip")
    return ""


def scan_ssh_file(path: str) -> Tuple[List[Dict[str, str]], List[Dict[str, object]], List[Dict[str, object]]]:
    lines = read_text_file(path)
    if lines is None:
        return ([{
            "source": path,
            "line": "0",
            "issue": "недоступен",
            "severity": "info",
            "detail": "нет доступа или файл отсутствует",
        }], [], [])

    findings: List[Dict[str, str]] = []
    failed_events: List[Dict[str, object]] = []
    success_events: List[Dict[str, object]] = []

    for idx, line in enumerate(lines, start=1):
        if "sshd" not in line.lower():
            continue

        ts_str, msg = parse_syslog_line(line)
        ts = parse_timestamp(ts_str)
        lower_msg = msg.lower()

        failed_match = FAILED_RE.search(msg)
        if failed_match:
            user = failed_match.group("user")
            ip = failed_match.group("ip")
            failed_events.append({
                "ts": ts,
                "source": path,
                "line": str(idx),
                "user": user,
                "ip": ip,
                "invalid_user": "invalid user" in lower_msg,
            })
            if user.lower() == "root":
                findings.append({
                    "source": path,
                    "line": str(idx),
                    "severity": "medium",
                    "issue": "попытка SSH-входа в root",
                    "detail": msg[:200],
                    "user": user,
                    "ip": ip,
                })
            continue

        invalid_user_match = INVALID_USER_RE.search(msg)
        if invalid_user_match:
            user = invalid_user_match.group("user")
            ip = invalid_user_match.group("ip")
            failed_events.append({
                "ts": ts,
                "source": path,
                "line": str(idx),
                "user": user,
                "ip": ip,
                "invalid_user": True,
            })
            findings.append({
                "source": path,
                "line": str(idx),
                "severity": "low",
                "issue": "нетипичный пользователь SSH",
                "detail": f"попытка входа несуществующим пользователем {user}",
                "user": user,
                "ip": ip,
            })
            continue

        not_allowed_match = NOT_ALLOWED_RE.search(msg)
        if not_allowed_match:
            user = not_allowed_match.group("user")
            ip = not_allowed_match.group("ip")
            failed_events.append({
                "ts": ts,
                "source": path,
                "line": str(idx),
                "user": user,
                "ip": ip,
                "invalid_user": True,
            })
            findings.append({
                "source": path,
                "line": str(idx),
                "severity": "medium",
                "issue": "запрещенный пользователь SSH",
                "detail": msg[:200],
                "user": user,
                "ip": ip,
            })
            continue

        accepted_match = ACCEPTED_RE.search(msg)
        if accepted_match:
            success_events.append({
                "ts": ts,
                "source": path,
                "line": str(idx),
                "user": accepted_match.group("user"),
                "ip": accepted_match.group("ip"),
                "method": accepted_match.group("method"),
            })
            continue

        for pattern, severity, issue in ANOMALY_PATTERNS:
            if re.search(pattern, msg, flags=re.IGNORECASE):
                findings.append({
                    "source": path,
                    "line": str(idx),
                    "severity": severity,
                    "issue": issue,
                    "detail": msg[:200],
                    "ip": extract_ip(msg),
                })
                break

    return findings, failed_events, success_events


def detect_bruteforce(failed_events: List[Dict[str, object]]) -> List[Dict[str, str]]:
    findings: List[Dict[str, str]] = []
    events_by_ip: Dict[str, List[Dict[str, object]]] = {}

    for event in failed_events:
        ts = event.get("ts")
        ip = event.get("ip")
        if not ts or not ip:
            continue
        events_by_ip.setdefault(str(ip), []).append(event)

    for ip, items in events_by_ip.items():
        items.sort(key=lambda x: x["ts"])
        i = 0
        for j in range(len(items)):
            while items[j]["ts"] - items[i]["ts"] > timedelta(seconds=BRUTEFORCE_WINDOW_SECONDS):
                i += 1
            count = j - i + 1
            if count >= BRUTEFORCE_THRESHOLD:
                users = sorted({
                    str(ev.get("user", ""))
                    for ev in items[i:j + 1]
                    if ev.get("user")
                })
                start = items[i]["ts"].strftime("%Y-%m-%d %H:%M:%S")
                end = items[j]["ts"].strftime("%Y-%m-%d %H:%M:%S")
                findings.append({
                    "source": str(items[j].get("source", "multiple")),
                    "line": str(items[j].get("line", "0")),
                    "severity": "high",
                    "issue": "брутфорс SSH",
                    "detail": (
                        f"{count} неудачных попыток за {BRUTEFORCE_WINDOW_SECONDS} сек "
                        f"({start} - {end}), users={','.join(users[:5])}"
                    ),
                    "ip": ip,
                })
                break

    return findings


def detect_password_spray(failed_events: List[Dict[str, object]]) -> List[Dict[str, str]]:
    findings: List[Dict[str, str]] = []
    events_by_ip: Dict[str, List[Dict[str, object]]] = {}

    for event in failed_events:
        ts = event.get("ts")
        ip = event.get("ip")
        if not ts or not ip:
            continue
        events_by_ip.setdefault(str(ip), []).append(event)

    for ip, items in events_by_ip.items():
        items.sort(key=lambda x: x["ts"])
        i = 0
        for j in range(len(items)):
            while items[j]["ts"] - items[i]["ts"] > timedelta(seconds=SPRAY_WINDOW_SECONDS):
                i += 1
            window_users = {
                str(ev.get("user", ""))
                for ev in items[i:j + 1]
                if ev.get("user")
            }
            if len(window_users) >= SPRAY_USER_THRESHOLD:
                start = items[i]["ts"].strftime("%Y-%m-%d %H:%M:%S")
                end = items[j]["ts"].strftime("%Y-%m-%d %H:%M:%S")
                findings.append({
                    "source": str(items[j].get("source", "multiple")),
                    "line": str(items[j].get("line", "0")),
                    "severity": "medium",
                    "issue": "подозрительный IP (перебор пользователей)",
                    "detail": (
                        f"{len(window_users)} пользователей за {SPRAY_WINDOW_SECONDS} сек "
                        f"({start} - {end})"
                    ),
                    "ip": ip,
                })
                break

    return findings


def detect_invalid_user_burst(failed_events: List[Dict[str, object]]) -> List[Dict[str, str]]:
    findings: List[Dict[str, str]] = []
    events_by_ip: Dict[str, List[Dict[str, object]]] = {}

    for event in failed_events:
        ts = event.get("ts")
        ip = event.get("ip")
        invalid_user = event.get("invalid_user")
        if not ts or not ip or not invalid_user:
            continue
        events_by_ip.setdefault(str(ip), []).append(event)

    for ip, items in events_by_ip.items():
        items.sort(key=lambda x: x["ts"])
        i = 0
        for j in range(len(items)):
            while items[j]["ts"] - items[i]["ts"] > timedelta(seconds=INVALID_USER_WINDOW_SECONDS):
                i += 1
            count = j - i + 1
            if count >= INVALID_USER_THRESHOLD:
                findings.append({
                    "source": str(items[j].get("source", "multiple")),
                    "line": str(items[j].get("line", "0")),
                    "severity": "medium",
                    "issue": "подозрительный IP (invalid user)",
                    "detail": f"{count} попыток invalid user за {INVALID_USER_WINDOW_SECONDS} сек",
                    "ip": ip,
                })
                break

    return findings


def detect_suspicious_success(
    success_events: List[Dict[str, object]],
    failed_events: List[Dict[str, object]],
) -> List[Dict[str, str]]:
    findings: List[Dict[str, str]] = []
    failed_by_ip: Dict[str, List[Dict[str, object]]] = {}

    for event in failed_events:
        ts = event.get("ts")
        ip = event.get("ip")
        if not ts or not ip:
            continue
        failed_by_ip.setdefault(str(ip), []).append(event)

    for ip_events in failed_by_ip.values():
        ip_events.sort(key=lambda x: x["ts"])

    for event in success_events:
        ts = event.get("ts")
        ip = str(event.get("ip", ""))
        user = str(event.get("user", ""))
        method = str(event.get("method", ""))
        if not ts:
            continue

        user_l = user.lower()
        method_l = method.lower()

        if user_l in PRIVILEGED_USERS:
            findings.append({
                "source": str(event.get("source", "multiple")),
                "line": str(event.get("line", "0")),
                "severity": "high",
                "issue": "успешный вход привилегированного пользователя SSH",
                "detail": f"user={user}, method={method}",
                "user": user,
                "ip": ip,
            })
        elif user_l in SERVICE_USERS:
            findings.append({
                "source": str(event.get("source", "multiple")),
                "line": str(event.get("line", "0")),
                "severity": "medium",
                "issue": "нетипичный пользователь SSH",
                "detail": f"успешный вход сервисного аккаунта ({user})",
                "user": user,
                "ip": ip,
            })

        if method_l == "password" and (user_l in PRIVILEGED_USERS or user_l in SERVICE_USERS):
            findings.append({
                "source": str(event.get("source", "multiple")),
                "line": str(event.get("line", "0")),
                "severity": "medium",
                "issue": "подозрительное подключение по паролю",
                "detail": f"user={user}, method=password",
                "user": user,
                "ip": ip,
            })

        recent_failed = 0
        for fail_event in reversed(failed_by_ip.get(ip, [])):
            fail_ts = fail_event.get("ts")
            if not fail_ts or fail_ts > ts:
                continue
            if ts - fail_ts > timedelta(seconds=SUCCESS_AFTER_FAIL_WINDOW_SECONDS):
                break
            recent_failed += 1

        if recent_failed >= SUCCESS_AFTER_FAIL_THRESHOLD:
            findings.append({
                "source": str(event.get("source", "multiple")),
                "line": str(event.get("line", "0")),
                "severity": "high",
                "issue": "успешный вход после серии неудачных попыток",
                "detail": (
                    f"{recent_failed} неудачных попыток за "
                    f"{SUCCESS_AFTER_FAIL_WINDOW_SECONDS} сек перед успехом"
                ),
                "user": user,
                "ip": ip,
            })

    return findings


def collect_log_sources(extra_paths: Optional[List[str]] = None) -> Tuple[List[str], List[Dict[str, str]]]:
    sources: List[str] = []
    info_findings: List[Dict[str, str]] = []

    auto_sources = discover_ssh_log_paths()
    if auto_sources:
        sources.extend(auto_sources)
    elif not extra_paths:
        info_findings.append({
            "source": "ssh logs",
            "line": "0",
            "severity": "info",
            "issue": "SSH-логи не найдены",
            "detail": "проверьте наличие /var/log/auth.log, /var/log/secure или /var/log/messages",
        })

    if extra_paths:
        for path in extra_paths:
            if os.path.isdir(path):
                for file_path in iter_files_in_dir(path):
                    if is_unsupported_archive(file_path):
                        info_findings.append({
                            "source": file_path,
                            "line": "0",
                            "severity": "info",
                            "issue": "неподдерживаемый архив SSH-логов",
                            "detail": "формат .zst пока не поддерживается",
                        })
                        continue
                    sources.append(file_path)
            else:
                if is_unsupported_archive(path):
                    info_findings.append({
                        "source": path,
                        "line": "0",
                        "severity": "info",
                        "issue": "неподдерживаемый архив SSH-логов",
                        "detail": "формат .zst пока не поддерживается",
                    })
                    continue
                sources.append(path)

    return dedupe_paths(sources), info_findings


def run_ssh_scan(extra_paths: Optional[List[str]] = None) -> List[Dict[str, str]]:
    sources, info_findings = collect_log_sources(extra_paths=extra_paths)
    findings: List[Dict[str, str]] = list(info_findings)
    failed_events: List[Dict[str, object]] = []
    success_events: List[Dict[str, object]] = []

    for path in sources:
        file_findings, file_failed, file_success = scan_ssh_file(path)
        findings.extend(file_findings)
        failed_events.extend(file_failed)
        success_events.extend(file_success)

    findings.extend(detect_bruteforce(failed_events))
    findings.extend(detect_password_spray(failed_events))
    findings.extend(detect_invalid_user_burst(failed_events))
    findings.extend(detect_suspicious_success(success_events, failed_events))

    return findings


def format_ssh_findings(findings: List[Dict[str, str]]) -> str:
    if not findings:
        return "Подозрительных SSH-событий не найдено."

    severity_order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    findings_sorted = sorted(
        findings,
        key=lambda x: (severity_order.get(x.get("severity", "info"), 9), x.get("source", ""), x.get("line", "")),
    )

    lines: List[str] = []
    for item in findings_sorted:
        source = item.get("source", "unknown")
        line = item.get("line", "0")
        severity_key = item.get("severity", "info")
        severity = SEVERITY_LABELS.get(severity_key, "ИНФО")
        issue = item.get("issue", "неизвестно")
        detail = item.get("detail", "")
        user = item.get("user", "")
        ip = item.get("ip", "")

        suffix_parts = []
        if user:
            suffix_parts.append(f"user={user}")
        if ip:
            suffix_parts.append(f"ip={ip}")
        suffix = f" ({', '.join(suffix_parts)})" if suffix_parts else ""

        lines.append(f"[{severity}] {source}:{line} {issue}{suffix}")
        if detail:
            lines.append(f"  деталь: {detail}")

    return "\n".join(lines)
