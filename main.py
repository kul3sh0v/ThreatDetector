import argparse
import os
import sys

from cron_scanner import format_cron_findings, run_cron_scan
from sudo_scanner import format_sudo_findings, run_sudo_scan


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Запуск сканеров cron и sudo (по ключам или оба по умолчанию).",
    )
    parser.add_argument(
        "-c",
        "--cron-scan",
        action="store_true",
        help="Включить сканирование cron.",
    )
    parser.add_argument(
        "-s",
        "--sudo-scan",
        action="store_true",
        help="Включить сканирование sudo.",
    )
    parser.add_argument(
        "--cron-paths",
        "--paths",
        nargs="*",
        default=None,
        help="Дополнительные файлы или каталоги с cron-записями для проверки.",
    )
    parser.add_argument(
        "--sudo-logs",
        nargs="*",
        default=None,
        help="Дополнительные файлы логов sudo для проверки.",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Необязательный файл для сохранения отчёта.",
    )
    args = parser.parse_args()

    if os.name == "nt":
        print("Сканеры предназначены для Linux. Windows Task Scheduler не поддерживается.", file=sys.stderr)
        return 2

    run_cron = args.cron_scan
    run_sudo = args.sudo_scan
    if not (run_cron or run_sudo):
        run_cron = True
        run_sudo = True

    sections = []
    if run_cron:
        cron_findings = run_cron_scan(extra_paths=args.cron_paths)
        sections.append(("CRON", format_cron_findings(cron_findings)))

    if run_sudo:
        sudo_findings = run_sudo_scan(extra_paths=args.sudo_logs)
        sections.append(("SUDO", format_sudo_findings(sudo_findings)))

    report = "\n\n".join(
        f"=== {title} ===\n{content}" for title, content in sections
    )

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(report + "\n")
        except OSError as exc:
            print(f"Не удалось записать отчёт в файл: {exc}", file=sys.stderr)
            print(report)
            return 1
    else:
        print(report)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
