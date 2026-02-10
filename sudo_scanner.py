import os
import re
from datetime import datetime, timedelta
from typing import Dict, Iterable, List, Optional, Tuple

AUTH_LOG_FILES = [
    "/var/log/auth.log",
    "/var/log/secure",
]
DEFAULT_SUDO_LOG = "/var/log/sudo.log"
SUDOERS_FILES = [
    "/etc/sudoers",
]
SUDOERS_DIRS = [
    "/etc/sudoers.d",
]

FREQUENT_THRESHOLD = 5
FREQUENT_WINDOW_SECONDS = 60

SUSPICIOUS_COMMAND_PATTERNS: List[Tuple[str, str, str]] = [
    (r"\b(curl|wget)\b", "medium", "загрузка из сети"),
    (r"\b(/bin/)?bash\b|\b(/bin/)?sh\b", "low", "вызов shell"),
    (r"\bchmod\b\s+\+s\b", "high", "установка SUID"),
    (r"\buseradd\b|\badduser\b", "medium", "создание пользователя"),
    (r"\bvisudo\b", "medium", "редактирование sudoers"),
    (r"\bchown\b.*\broot\b", "medium", "смена владельца на root"),
]

SERVICE_USERS = {
    "www-data",
    "apache",
    "nginx",
    "httpd",
    "www",
    "_www",
    "nobody",
}

SUSPICIOUS_PWD_PREFIXES = [
    "/tmp",
    "/var/tmp",
    "/dev/shm",
    "/run",
    "/var/run",
]

NO_TTY_PATTERNS = [
    r"no tty present",
    r"tty=unknown",
    r"tty=\?",
    r"tty=notty",
]

NOT_IN_SUDOERS_PATTERNS = [
    r"not in the sudoers file",
    r"not in sudoers",
    r"not allowed to run sudo",
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


def iter_files_in_dir(directory: str) -> Iterable[str]:
    try:
        for name in os.listdir(directory):
            path = os.path.join(directory, name)
            if os.path.isfile(path):
                yield path
    except OSError:
        return


def read_text_file(path: str) -> Optional[List[str]]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read().splitlines()
    except OSError:
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


def parse_sudo_fields(msg: str) -> Dict[str, str]:
    fields: Dict[str, str] = {}
    user_match = re.match(r"^([A-Za-z0-9_.-]+)\s*:", msg)
    if user_match:
        fields["user"] = user_match.group(1)

    command_match = re.search(r"\bCOMMAND(?:=|:)\s*(.+)$", msg)
    if command_match:
        fields["command"] = command_match.group(1).strip()

    tty_match = re.search(r"\bTTY=([^; ]+)", msg)
    if tty_match:
        fields["tty"] = tty_match.group(1).strip()

    pwd_match = re.search(r"\bPWD=([^; ]+)", msg)
    if pwd_match:
        fields["pwd"] = pwd_match.group(1).strip()

    return fields


def extract_logfile_paths(lines: List[str]) -> List[str]:
    paths: List[str] = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "logfile" not in stripped:
            continue
        match = re.search(r'logfile\s*=\s*"?([^"\s]+)"?', stripped)
        if match:
            paths.append(match.group(1))
    return paths


def discover_sudo_log_paths() -> List[str]:
    paths: List[str] = []
    for sudoers in SUDOERS_FILES:
        lines = read_text_file(sudoers)
        if lines:
            paths.extend(extract_logfile_paths(lines))

    for directory in SUDOERS_DIRS:
        for path in iter_files_in_dir(directory):
            lines = read_text_file(path)
            if lines:
                paths.extend(extract_logfile_paths(lines))

    if os.path.exists(DEFAULT_SUDO_LOG):
        paths.append(DEFAULT_SUDO_LOG)

    deduped: List[str] = []
    seen = set()
    for path in paths:
        if path not in seen:
            deduped.append(path)
            seen.add(path)
    return deduped


def is_no_tty(msg: str, tty_value: Optional[str]) -> bool:
    if tty_value and tty_value.lower() in {"unknown", "?", "notty"}:
        return True
    for pattern in NO_TTY_PATTERNS:
        if re.search(pattern, msg, flags=re.IGNORECASE):
            return True
    return False


def is_not_in_sudoers(msg: str) -> bool:
    for pattern in NOT_IN_SUDOERS_PATTERNS:
        if re.search(pattern, msg, flags=re.IGNORECASE):
            return True
    return False


def is_suspicious_pwd(pwd: Optional[str]) -> bool:
    if not pwd:
        return False
    return any(pwd.startswith(prefix) for prefix in SUSPICIOUS_PWD_PREFIXES)


def scan_sudo_file(path: str) -> Tuple[List[Dict[str, str]], List[Dict[str, object]]]:
    lines = read_text_file(path)
    if lines is None:
        return ([{
            "source": path,
            "line": "0",
            "issue": "недоступен",
            "severity": "info",
            "detail": "нет доступа или файл отсутствует",
        }], [])

    findings: List[Dict[str, str]] = []
    events: List[Dict[str, object]] = []

    for idx, line in enumerate(lines, start=1):
        if "sudo" not in line.lower():
            continue
        ts_str, msg = parse_syslog_line(line)
        ts = parse_timestamp(ts_str)
        fields = parse_sudo_fields(msg)
        user = fields.get("user")
        command = fields.get("command")
        tty = fields.get("tty")
        pwd = fields.get("pwd")

        if is_not_in_sudoers(msg):
            findings.append({
                "source": path,
                "line": str(idx),
                "severity": "high",
                "issue": "пользователь не в sudoers",
                "detail": msg[:200],
                "user": user or "",
                "command": command or "",
            })

        if is_no_tty(msg, tty):
            findings.append({
                "source": path,
                "line": str(idx),
                "severity": "medium",
                "issue": "sudo без TTY",
                "detail": "TTY отсутствует или неизвестен",
                "user": user or "",
                "command": command or "",
            })

        if user and user in SERVICE_USERS:
            findings.append({
                "source": path,
                "line": str(idx),
                "severity": "medium",
                "issue": "нетипичный пользователь",
                "detail": f"сервисный аккаунт: {user}",
                "user": user,
                "command": command or "",
            })

        if is_suspicious_pwd(pwd):
            findings.append({
                "source": path,
                "line": str(idx),
                "severity": "low",
                "issue": "нетипичное место запуска",
                "detail": pwd or "",
                "user": user or "",
                "command": command or "",
            })

        target_text = command or msg
        for pattern, severity, reason in SUSPICIOUS_COMMAND_PATTERNS:
            if re.search(pattern, target_text, flags=re.IGNORECASE):
                findings.append({
                    "source": path,
                    "line": str(idx),
                    "severity": severity,
                    "issue": reason,
                    "detail": pattern,
                    "user": user or "",
                    "command": command or "",
                })

        if command:
            events.append({
                "ts": ts,
                "user": user,
                "source": path,
                "line": str(idx),
                "command": command,
            })

    return findings, events


def detect_frequent(events: List[Dict[str, object]]) -> List[Dict[str, str]]:
    findings: List[Dict[str, str]] = []
    events_by_user: Dict[str, List[Dict[str, object]]] = {}
    for event in events:
        ts = event.get("ts")
        user = event.get("user")
        if not ts or not user:
            continue
        events_by_user.setdefault(str(user), []).append(event)

    for user, items in events_by_user.items():
        items.sort(key=lambda x: x["ts"])
        i = 0
        for j in range(len(items)):
            while items[j]["ts"] - items[i]["ts"] > timedelta(seconds=FREQUENT_WINDOW_SECONDS):
                i += 1
            count = j - i + 1
            if count >= FREQUENT_THRESHOLD:
                start = items[i]["ts"].strftime("%Y-%m-%d %H:%M:%S")
                end = items[j]["ts"].strftime("%Y-%m-%d %H:%M:%S")
                findings.append({
                    "source": str(items[j].get("source", "multiple")),
                    "line": str(items[j].get("line", "0")),
                    "severity": "medium",
                    "issue": "частые sudo-вызовы",
                    "detail": f"{count} за {FREQUENT_WINDOW_SECONDS} сек ({start} - {end})",
                    "user": user,
                    "command": str(items[j].get("command", "")),
                })
                break

    return findings


def collect_log_sources(extra_paths: Optional[List[str]] = None) -> Tuple[List[str], List[Dict[str, str]]]:
    sources: List[str] = []
    info_findings: List[Dict[str, str]] = []

    auth_existing = [path for path in AUTH_LOG_FILES if os.path.exists(path)]
    if not auth_existing:
        info_findings.append({
            "source": "auth.log/secure",
            "line": "0",
            "severity": "info",
            "issue": "логи auth/secure не найдены",
            "detail": "нет доступных файлов /var/log/auth.log или /var/log/secure",
        })
    else:
        sources.extend(auth_existing)

    sudo_log_paths = discover_sudo_log_paths()
    for path in sudo_log_paths:
        if os.path.exists(path):
            sources.append(path)
        else:
            info_findings.append({
                "source": path,
                "line": "0",
                "severity": "info",
                "issue": "sudo.log настроен, но файл не найден",
                "detail": "проверьте Defaults logfile=...",
            })

    if extra_paths:
        sources.extend(extra_paths)

    deduped: List[str] = []
    seen = set()
    for path in sources:
        if path not in seen:
            deduped.append(path)
            seen.add(path)
    return deduped, info_findings


def run_sudo_scan(extra_paths: Optional[List[str]] = None) -> List[Dict[str, str]]:
    sources, info_findings = collect_log_sources(extra_paths=extra_paths)
    findings: List[Dict[str, str]] = list(info_findings)
    events: List[Dict[str, object]] = []

    for path in sources:
        file_findings, file_events = scan_sudo_file(path)
        findings.extend(file_findings)
        events.extend(file_events)

    findings.extend(detect_frequent(events))
    return findings


def format_sudo_findings(findings: List[Dict[str, str]]) -> str:
    if not findings:
        return "Подозрительных запусков sudo не найдено."

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
        command = item.get("command", "")
        user = item.get("user", "")
        suffix = f" (user={user})" if user else ""
        lines.append(f"[{severity}] {source}:{line} {issue}{suffix}")
        if detail:
            lines.append(f"  деталь: {detail}")
        if command:
            lines.append(f"  команда: {command}")
    return "\n".join(lines)