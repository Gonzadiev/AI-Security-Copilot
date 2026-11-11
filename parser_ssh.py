"""Convert classic Linux OpenSSH authentication logs to AI Security Copilot CSV.

Supports traditional syslog lines starting with an English month abbreviation,
not arbitrary journald JSON, ISO timestamps or other authentication services.
"""

import argparse
import csv
import re
from datetime import datetime
from ipaddress import ip_address
from pathlib import Path

MONTHS = {
    name: index
    for index, name in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"),
        start=1,
    )
}

SYSLOG = re.compile(
    r"^(?P<month>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+"
    r"(?P<clock>\d{2}:\d{2}:\d{2})\s+\S+\s+"
    r"sshd(?:-session)?(?:\[\d+\])?:\s+(?P<message>.+)$"
)

AUTHENTICATION = re.compile(
    r"^(?P<action>Failed|Accepted)\s+"
    r"(?:password|publickey|keyboard-interactive(?:/pam)?)\s+"
    r"for\s+(?:invalid user\s+)?(?P<username>.+?)\s+"
    r"from\s+(?P<ip>\S+)\s+port\s+\d+\s+ssh2(?:\b|:|$)",
    re.IGNORECASE,
)


def parse_line(line: str, year: int) -> dict[str, str] | None:
    """Return timestamp/ip/status or None if the line is not a supported SSH event."""
    match = SYSLOG.match(line.strip())
    if not match:
        return None

    auth = AUTHENTICATION.match(match.group("message"))
    if not auth:
        return None

    try:
        ip = str(ip_address(auth.group("ip")))
        month = MONTHS[match.group("month").title()]
        hours, minutes, seconds = map(int, match.group("clock").split(":"))
        timestamp = datetime(year, month, int(match.group("day")), hours, minutes, seconds)
    except (ValueError, KeyError):
        return None

    
    return {
        "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "ip": ip,
        "status": (
            "FAIL"
            if auth.group("action").lower() == "failed"
            else "SUCCESS"
        ),
        "username": auth.group("username")
    }



def convert(input_file: Path, output_file: Path, year: int) -> dict[str, int]:
    """Convert a log file and report records converted and skipped."""
    input_file = input_file.resolve()
    output_file = output_file.resolve()
    if input_file == output_file:
        raise ValueError("El archivo de salida no puede ser el mismo que el de entrada")

    lines = input_file.read_text(encoding="utf-8", errors="replace").splitlines()
    records = [record for line in lines if (record := parse_line(line, year)) is not None]
    if not records:
        raise ValueError("No se han encontrado eventos SSH compatibles. Revisa el formato y el año")

    records.sort(key=lambda record: record["timestamp"])
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with output_file.open("w", encoding="utf-8", newline="") as output:
        writer = csv.DictWriter(
            output,
            fieldnames=["timestamp", "ip", "status", "username"]
        )
        writer.writeheader()
        writer.writerows(records)

    return {"convertidos": len(records), "ignorados": len(lines) - len(records)}


def main() -> None:
    cli = argparse.ArgumentParser(description="Convertir logs SSH estilo syslog a CSV para AI Security Copilot")
    cli.add_argument("--input", type=Path, required=True, help="Ruta de auth.log / secure")
    cli.add_argument("--output", type=Path, default=Path("data/ssh_auth_normalized.csv"))
    cli.add_argument("--year", type=int, required=True, help="Año de los registros (syslog no lo incluye)")
    args = cli.parse_args()
    try:
        summary = convert(args.input, args.output, args.year)
    except (OSError, ValueError) as error:
        cli.exit(1, f"Error: {error}\n")
    print(f"CSV creado: {args.output}")
    print(f"Registros convertidos: {summary['convertidos']}")
    print(f"Líneas ignoradas: {summary['ignorados']}")


if __name__ == "__main__":
    main()
