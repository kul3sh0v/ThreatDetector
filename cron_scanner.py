import os
import re
from typing import Dict, Iterable, List, Optional, Tuple

# Базовые пути cron для Linux
CRON_FILES = [
    "/etc/crontab",
]
CRON_DIRS = [
    "/etc/cron.d",
]
CRON_SPOOL_DIRS = [
    "/var/spool/cron",
    "/var/spool/cron/crontabs",
]
CRON_SCRIPT_DIRS = [
    "/etc/cron.hourly",
    "/etc/cron.daily",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
]

# Признаки, которые часто встречаются в инъекциях/вредоносных cron-заданиях
SUSPICIOUS_PATTERNS: List[Tuple[str, str, str]] = [
    (r"\b(curl|wget)\b.*\|\s*(bash|sh|zsh|ksh)", "high", "скачивание и запуск (shell)"),
    (r"\b(curl|wget)\b.*\|\s*(python|perl|ruby|php)", "high", "скачивание и запуск (интерпретатор)"),
    (r"\bbase64\s+(-d|--decode)\b", "high", "декодирование base64"),
    (r"\bpython\s+-c\b|\bperl\s+-e\b|\bphp\s+-r\b|\bruby\s+-e\b", "medium", "исполнение кода в командной строке"),
    (r"\b(nc|netcat)\b.*\s-?e\b", "high", "netcat с флагом exec"),
    (r"\b(bash|sh)\s+-i\b", "high", "интерактивная оболочка"),
    (r"\bmkfifo\b", "medium", "использование именованного канала"),
    (r"\b(/tmp|/var/tmp|/dev/shm)\b", "medium", "использование временных путей"),
    (r"\bchmod\b.*\+x\b", "medium", "изменение прав на исполняемые"),
    (r"\b/s?bin/(bash|sh)\s+-c\b", "medium", "shell с флагом -c"),
    (r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "low", "сырой IP-адрес"),
    (r"/\.[A-Za-z0-9_.-]+", "low", "использование скрытого пути"),
]

SEVERITY_LABELS = {
    "high": "ВЫСОКИЙ",
    "medium": "СРЕДНИЙ",
    "low": "НИЗКИЙ",
    "info": "ИНФО",
}


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


def parse_cron_line(
    line: str,
    is_system_cron: bool,
) -> Optional[Dict[str, str]]:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None

    parts = stripped.split()
    if not parts:
        return None

    if parts[0].startswith("@"):
        if is_system_cron:
            if len(parts) < 3:
                return None
            return {
                "schedule": parts[0],
                "user": parts[1],
                "command": " ".join(parts[2:]),
            }
        if len(parts) < 2:
            return None
        return {
            "schedule": parts[0],
            "command": " ".join(parts[1:]),
        }

    # Обычный формат: 5 полей расписания (+ user в системном cron)
    if is_system_cron:
        if len(parts) < 7:
            return None
        return {
            "schedule": " ".join(parts[0:5]),
            "user": parts[5],
            "command": " ".join(parts[6:]),
        }

    if len(parts) < 6:
        return None
    return {
        "schedule": " ".join(parts[0:5]),
        "command": " ".join(parts[5:]),
    }


def scan_text_for_suspicion(text: str) -> List[Tuple[str, str, str]]:
    hits: List[Tuple[str, str, str]] = []
    for pattern, severity, reason in SUSPICIOUS_PATTERNS:
        if re.search(pattern, text, flags=re.IGNORECASE):
            hits.append((severity, reason, pattern))
    return hits


def scan_cron_file(path: str, is_system_cron: bool) -> List[Dict[str, str]]:
    lines = read_text_file(path)
    if lines is None:
        return [{
            "source": path,
            "line": "0",
            "issue": "недоступен",
            "severity": "info",
            "detail": "нет доступа или файл отсутствует",
        }]

    findings: List[Dict[str, str]] = []
    for idx, line in enumerate(lines, start=1):
        parsed = parse_cron_line(line, is_system_cron=is_system_cron)
        if not parsed:
            continue
        command = parsed.get("command", "")
        hits = scan_text_for_suspicion(command)
        for severity, reason, pattern in hits:
            findings.append({
                "source": path,
                "line": str(idx),
                "severity": severity,
                "issue": reason,
                "detail": pattern,
                "command": command,
            })
    return findings


def scan_cron_script(path: str) -> List[Dict[str, str]]:
    lines = read_text_file(path)
    if lines is None:
        return [{
            "source": path,
            "line": "0",
            "issue": "недоступен",
            "severity": "info",
            "detail": "нет доступа или файл отсутствует",
        }]

    findings: List[Dict[str, str]] = []
    for idx, line in enumerate(lines, start=1):
        hits = scan_text_for_suspicion(line)
        for severity, reason, pattern in hits:
            findings.append({
                "source": path,
                "line": str(idx),
                "severity": severity,
                "issue": reason,
                "detail": pattern,
                "command": line.strip(),
            })
    return findings


def gather_cron_sources(extra_paths: Optional[List[str]] = None) -> List[Tuple[str, str]]:
    sources: List[Tuple[str, str]] = []

    for path in CRON_FILES:
        sources.append((path, "system"))

    for directory in CRON_DIRS:
        for path in iter_files_in_dir(directory):
            sources.append((path, "system"))

    for directory in CRON_SPOOL_DIRS:
        for path in iter_files_in_dir(directory):
            sources.append((path, "user"))

    for directory in CRON_SCRIPT_DIRS:
        for path in iter_files_in_dir(directory):
            sources.append((path, "script"))

    if extra_paths:
        for path in extra_paths:
            if os.path.isdir(path):
                for file_path in iter_files_in_dir(path):
                    sources.append((file_path, "system"))
            else:
                sources.append((path, "system"))

    return sources


def run_cron_scan(extra_paths: Optional[List[str]] = None) -> List[Dict[str, str]]:
    findings: List[Dict[str, str]] = []
    sources = gather_cron_sources(extra_paths=extra_paths)
    for path, kind in sources:
        if kind == "script":
            findings.extend(scan_cron_script(path))
        else:
            is_system = kind == "system"
            findings.extend(scan_cron_file(path, is_system_cron=is_system))
    return findings


def format_cron_findings(findings: List[Dict[str, str]]) -> str:
    if not findings:
        return "Подозрительных записей cron не найдено."

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
        lines.append(f"[{severity}] {source}:{line} {issue}")
        if detail:
            lines.append(f"  паттерн: {detail}")
        if command:
            lines.append(f"  команда: {command}")
    return "\n".join(lines)