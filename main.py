#!/usr/bin/env python3
import argparse
import collections
import csv
import dataclasses
import datetime
import fnmatch
import gzip
import hashlib
import io
import json
import math
import os
import pathlib
import platform
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
import typing
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed

UTC = datetime.timezone.utc

@dataclasses.dataclass
class Finding:
    code: str
    severity: str
    title: str
    description: str
    source: str = ""
    boot: str = ""
    evidence: list = dataclasses.field(default_factory=list)
    recommendation: str = ""
    confidence: str = "medium"

@dataclasses.dataclass
class CommandResult:
    command: list
    returncode: int
    stdout: str
    stderr: str
    duration: float
    error: str = ""

@dataclasses.dataclass
class Context:
    args: object
    results: dict = dataclasses.field(default_factory=dict)
    findings: list = dataclasses.field(default_factory=list)
    errors: list = dataclasses.field(default_factory=list)
    metadata: dict = dataclasses.field(default_factory=dict)
    command_log: list = dataclasses.field(default_factory=list)

    def finding(self, code, severity, title, description, source="", boot="", evidence=None, recommendation="", confidence="medium"):
        self.findings.append(Finding(code, severity, title, description, source, boot, list(evidence or []), recommendation, confidence))

    def error(self, scope, message):
        self.errors.append({"scope": scope, "message": str(message)})

class Runner:
    def __init__(self, timeout=12, max_output=2000000, fixture=None):
        self.timeout = timeout
        self.max_output = max_output
        self.fixture = pathlib.Path(fixture) if fixture else None
        self.history = []

    def run(self, command, timeout=None):
        started = time.monotonic()
        key = "__".join(re.sub(r"[^a-zA-Z0-9_.-]", "_", str(x)) for x in command)
        if self.fixture:
            path = self.fixture / (key + ".txt")
            if path.is_file():
                result = CommandResult(list(command), 0, path.read_text(errors="replace")[:self.max_output], "", time.monotonic() - started)
            else:
                result = CommandResult(list(command), 127, "", "", time.monotonic() - started, "fixture missing: " + path.name)
        else:
            try:
                process = subprocess.run(command, text=True, capture_output=True, timeout=timeout or self.timeout, check=False, errors="replace")
                result = CommandResult(list(command), process.returncode, process.stdout[:self.max_output], process.stderr[:8192], time.monotonic() - started)
            except (OSError, subprocess.TimeoutExpired) as exc:
                result = CommandResult(list(command), 127, "", "", time.monotonic() - started, str(exc))
        self.history.append(dataclasses.asdict(result))
        return result

    def text(self, command, timeout=None):
        result = self.run(command, timeout)
        return result.stdout if result.returncode == 0 else ""

    def json(self, command, default=None):
        raw = self.text(command)
        try:
            return json.loads(raw)
        except (ValueError, TypeError):
            return default

def safe_read(path, limit=2000000):
    try:
        with open(path, "rb") as stream:
            return stream.read(limit).decode("utf-8", "replace")
    except (OSError, ValueError):
        return ""

def read_lines(path, limit=2000000):
    return safe_read(path, limit).splitlines()

def parse_timestamp(value):
    if isinstance(value, (int, float)):
        try:
            return datetime.datetime.fromtimestamp(value, UTC)
        except (OverflowError, OSError, ValueError):
            return None
    if not value:
        return None
    text = str(value).strip()
    for candidate in (text, text.replace("Z", "+00:00")):
        try:
            result = datetime.datetime.fromisoformat(candidate)
            return result if result.tzinfo else result.replace(tzinfo=UTC)
        except ValueError:
            pass
    return None

def iso(value):
    if value is None:
        return None
    return value.astimezone(UTC).isoformat()

def number(value, default=None):
    try:
        return float(value)
    except (TypeError, ValueError, OverflowError):
        return default

def integer(value, default=None):
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return default

def human_duration(seconds):
    value = number(seconds)
    if value is None:
        return "unknown"
    sign = "-" if value < 0 else ""
    value = abs(value)
    if value < 1:
        return f"{sign}{value * 1000:.1f}ms"
    if value < 60:
        return f"{sign}{value:.2f}s"
    if value < 3600:
        return f"{sign}{value / 60:.2f}m"
    return f"{sign}{value / 3600:.2f}h"

def percentile(values, fraction):
    values = sorted(v for v in values if isinstance(v, (int, float)) and math.isfinite(v))
    if not values:
        return None
    index = (len(values) - 1) * fraction
    low, high = math.floor(index), math.ceil(index)
    return values[low] + (values[high] - values[low]) * (index - low)

def describe(values):
    values = [v for v in values if isinstance(v, (int, float)) and math.isfinite(v)]
    if not values:
        return {"count": 0}
    return {"count": len(values), "min": min(values), "max": max(values), "mean": statistics.mean(values), "median": statistics.median(values), "p90": percentile(values, .9), "p95": percentile(values, .95), "standard_deviation": statistics.pstdev(values)}

def extract_pairs(text, separator="="):
    result = {}
    for line in text.splitlines():
        if separator not in line:
            continue
        key, value = line.split(separator, 1)
        key = key.strip()
        if key:
            result[key] = value.strip().strip('"')
    return result

def normalize_unit(unit):
    return unit.strip().removesuffix(".service").replace("\\x2d", "-")

def stable_hash(data):
    return hashlib.sha256(json.dumps(data, sort_keys=True, default=str, ensure_ascii=False).encode()).hexdigest()

def load_json(path):
    try:
        with open(path, encoding="utf-8") as stream:
            return json.load(stream)
    except (OSError, ValueError) as exc:
        raise ValueError(f"Cannot read JSON {path}: {exc}") from exc

def atomic_json(path, value):
    target = pathlib.Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".boot-forensics-", dir=str(target.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, ensure_ascii=False, sort_keys=True, default=str)
            stream.write("\n")
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)

def parse_boot_list(text):
    boots = []
    for line in text.splitlines():
        match = re.match(r"^\s*(-?\d+)\s+([0-9a-fA-F-]{32,36})\s+(.*)$", line)
        if match:
            boots.append({"index": int(match.group(1)), "id": match.group(2), "range": match.group(3).strip()})
    return boots

def parse_blame(text):
    entries = []
    for line in text.splitlines():
        match = re.match(r"^\s*(\d+(?:\.\d+)?)(ms|s|min|h)\s+(.+?)\s*$", line)
        if match:
            multipliers = {"ms": .001, "s": 1, "min": 60, "h": 3600}
            entries.append({"unit": match.group(3), "seconds": float(match.group(1)) * multipliers[match.group(2)]})
    return sorted(entries, key=lambda x: x["seconds"], reverse=True)

def parse_systemd_time(text):
    values = {}
    for duration, unit, stage in re.findall(r"(\d+(?:\.\d+)?)\s*(ms|s|min|h)\s*\(([^)]+)\)", text):
        values[stage] = float(duration) * {"ms": .001, "s": 1, "min": 60, "h": 3600}[unit]
    total = re.search(r"=\s*([\d.]+)\s*(ms|s|min|h)", text)
    if total:
        values["total"] = float(total.group(1)) * {"ms": .001, "s": 1, "min": 60, "h": 3600}[total.group(2)]
    return values

def parse_critical_chain(text):
    result = []
    for line in text.splitlines():
        match = re.search(r"([\w@.\\:-]+\.(?:service|target|mount|socket|device|timer|path|slice|swap))\s+@([\d.]+)(ms|s)(?:\s+\+([\d.]+)(ms|s))?", line)
        if match:
            scale = lambda val, unit: float(val) * (.001 if unit == "ms" else 1)
            result.append({"unit": match.group(1), "at_seconds": scale(match.group(2), match.group(3)), "duration_seconds": scale(match.group(4), match.group(5)) if match.group(4) else None})
    return result

def parse_unit_records(text):
    records = []
    for line in text.splitlines():
        columns = line.strip().split(None, 4)
        if len(columns) >= 4 and re.search(r"\.(service|mount|socket|target|timer|path|slice|swap|device)$", columns[0]):
            records.append({"unit": columns[0], "load": columns[1], "active": columns[2], "sub": columns[3], "description": columns[4] if len(columns) > 4 else ""})
    return records

def parse_journal_json(text, limit=10000):
    records = []
    for line in text.splitlines():
        if len(records) >= limit:
            break
        try:
            record = json.loads(line)
            if isinstance(record, dict):
                records.append(record)
        except ValueError:
            continue
    return records

def journal_message(record):
    message = record.get("MESSAGE", "")
    return message if isinstance(message, str) else str(message)

def journal_time(record):
    raw = record.get("__REALTIME_TIMESTAMP") or record.get("_SOURCE_REALTIME_TIMESTAMP")
    microseconds = integer(raw)
    return iso(parse_timestamp(microseconds / 1000000)) if microseconds is not None else None

def severity_name(priority):
    levels = {0: "emergency", 1: "alert", 2: "critical", 3: "error", 4: "warning", 5: "notice", 6: "info", 7: "debug"}
    return levels.get(integer(priority), "unknown")

def summarize_journal(records):
    priority = collections.Counter()
    units = collections.Counter()
    identifiers = collections.Counter()
    boots = collections.Counter()
    for record in records:
        priority[severity_name(record.get("PRIORITY"))] += 1
        units[record.get("_SYSTEMD_UNIT", "unknown")] += 1
        identifiers[record.get("SYSLOG_IDENTIFIER", "unknown")] += 1
        boots[record.get("_BOOT_ID", "unknown")] += 1
    return {"entries": len(records), "priorities": dict(priority), "units": units.most_common(30), "identifiers": identifiers.most_common(30), "boot_ids": dict(boots)}

def kernel_release():
    return platform.release()

def collect_identity(ctx, runner):
    release = extract_pairs(safe_read("/etc/os-release"))
    uname = platform.uname()
    cmdline = safe_read("/proc/cmdline").strip()
    uptime = safe_read("/proc/uptime").split()
    boot_id = safe_read("/proc/sys/kernel/random/boot_id").strip()
    ctx.results["identity"] = {"hostname": uname.node, "system": uname.system, "kernel": uname.release, "machine": uname.machine, "distribution": release, "cmdline": cmdline, "uptime_seconds": number(uptime[0]) if uptime else None, "boot_id": boot_id, "timestamp": iso(datetime.datetime.now(UTC)), "euid": os.geteuid() if hasattr(os, "geteuid") else None}
    if "quiet" in cmdline.split():
        ctx.metadata["quiet_boot"] = True
    if not boot_id:
        ctx.error("identity", "Kernel boot ID unavailable")

def collect_boots(ctx, runner):
    output = runner.run(["journalctl", "--list-boots", "--no-pager", "--no-legend"])
    ctx.results["boots"] = parse_boot_list(output.stdout)
    if output.returncode != 0:
        ctx.error("boots", output.error or output.stderr.strip() or "journalctl unavailable")
    if not ctx.results["boots"]:
        ctx.finding("JOURNAL_NO_BOOTS", "warning", "No journal boot history", "No boot records could be enumerated", "journalctl", recommendation="Inspect journal persistence and permissions")

def collect_boot_timing(ctx, runner):
    time_result = runner.run(["systemd-analyze", "time"])
    blame_result = runner.run(["systemd-analyze", "blame", "--no-pager"])
    chain_result = runner.run(["systemd-analyze", "critical-chain", "--no-pager"])
    ctx.results["timing"] = {"stages": parse_systemd_time(time_result.stdout), "blame": parse_blame(blame_result.stdout), "critical_chain": parse_critical_chain(chain_result.stdout), "raw_time": time_result.stdout.strip()}
    if time_result.returncode != 0:
        ctx.error("timing", time_result.error or time_result.stderr.strip())
    for item in ctx.results["timing"]["blame"]:
        if item["seconds"] >= ctx.args.slow_unit:
            ctx.finding("SLOW_UNIT", "warning", "Slow systemd unit", f"{item['unit']} took {human_duration(item['seconds'])}", "systemd-analyze", evidence=[item], recommendation="Inspect the unit and its dependencies")
    total = ctx.results["timing"]["stages"].get("total")
    if total is not None and total >= ctx.args.slow_boot:
        ctx.finding("SLOW_BOOT", "warning", "Long boot duration", f"Reported boot time is {human_duration(total)}", "systemd-analyze", evidence=[{"total_seconds": total}], recommendation="Review critical-chain and blame reports")

def collect_units(ctx, runner):
    failed = runner.run(["systemctl", "list-units", "--state=failed", "--all", "--no-pager", "--no-legend", "--plain"])
    all_units = runner.run(["systemctl", "list-units", "--all", "--no-pager", "--no-legend", "--plain"])
    failed_records = parse_unit_records(failed.stdout)
    ctx.results["units"] = {"failed": failed_records, "all": parse_unit_records(all_units.stdout)}
    for item in failed_records:
        ctx.finding("FAILED_UNIT", "error", "Failed systemd unit", f"{item['unit']} is in a failed state", "systemctl", evidence=[item], recommendation=f"Run systemctl status {item['unit']} and journalctl -u {item['unit']}")
    if failed.returncode != 0:
        ctx.error("units", failed.error or failed.stderr.strip())

def collect_journal(ctx, runner):
    boot = str(ctx.args.boot)
    command = ["journalctl", "-b", boot, "--no-pager", "--output=json", "-n", str(ctx.args.journal_limit)]
    if ctx.args.journal_priority is not None:
        command.extend(["-p", str(ctx.args.journal_priority)])
    output = runner.run(command, timeout=ctx.args.timeout * 2)
    records = parse_journal_json(output.stdout, ctx.args.journal_limit)
    ctx.results["journal"] = {"summary": summarize_journal(records), "events": []}
    if output.returncode != 0:
        ctx.error("journal", output.error or output.stderr.strip())
    for record in records:
        priority = integer(record.get("PRIORITY"), 6)
        if priority <= 4:
            ctx.results["journal"]["events"].append({"time": journal_time(record), "priority": severity_name(priority), "unit": record.get("_SYSTEMD_UNIT", ""), "message": journal_message(record)[:1200]})
    ctx.metadata["journal_records"] = records

def collect_kernel(ctx, runner):
    output = runner.run(["journalctl", "-k", "-b", str(ctx.args.boot), "--no-pager", "--output=short-monotonic", "-n", str(ctx.args.kernel_limit)])
    lines = output.stdout.splitlines()
    ctx.results["kernel"] = {"entries": len(lines), "sample": lines[-min(len(lines), 100):]}
    ctx.metadata["kernel_lines"] = lines
    if output.returncode != 0:
        ctx.error("kernel", output.error or output.stderr.strip())

def collect_bootloader(ctx, runner):
    cmdline = safe_read("/proc/cmdline").strip()
    efivars = pathlib.Path("/sys/firmware/efi/efivars")
    loader = pathlib.Path("/boot/loader/entries")
    entries = []
    if loader.is_dir():
        for path in sorted(loader.glob("*.conf"))[:100]:
            values = {}
            for line in read_lines(path, 32768):
                fields = line.split(None, 1)
                if len(fields) == 2:
                    values[fields[0]] = fields[1]
            entries.append({"name": path.name, "title": values.get("title"), "version": values.get("version"), "linux": values.get("linux"), "options": values.get("options")})
    ctx.results["bootloader"] = {"efi": efivars.exists(), "loader_entries": entries, "cmdline": cmdline, "boot_mount": pathlib.Path("/boot").is_mount()}
    if not pathlib.Path("/boot").exists():
        ctx.finding("BOOT_PATH_MISSING", "warning", "Boot directory missing", "/boot was not found", "filesystem")

def collect_mounts(ctx, runner):
    mounts = []
    for line in read_lines("/proc/self/mountinfo"):
        parts = line.split(" - ", 1)
        if len(parts) != 2:
            continue
        left = parts[0].split()
        right = parts[1].split()
        if len(left) >= 6 and len(right) >= 3:
            mounts.append({"mount": left[4].replace("\\040", " "), "options": left[5], "fstype": right[0], "source": right[1]})
    ctx.results["mounts"] = mounts
    targets = {item["mount"] for item in mounts}
    if "/" not in targets:
        ctx.finding("ROOT_MOUNT_UNKNOWN", "warning", "Root mount not discovered", "Could not find root mount in mountinfo", "mountinfo")

def collect_storage(ctx, runner):
    result = []
    for mount in ("/", "/boot", "/boot/efi", "/var", "/var/log", "/var/log/journal"):
        if not os.path.exists(mount):
            continue
        try:
            stats = os.statvfs(mount)
            total = stats.f_blocks * stats.f_frsize
            available = stats.f_bavail * stats.f_frsize
            used = 100 * (1 - available / total) if total else None
            entry = {"path": mount, "bytes_total": total, "bytes_available": available, "used_percent": used, "inodes_free": stats.f_favail, "inodes_total": stats.f_files}
            result.append(entry)
            if used is not None and used >= ctx.args.disk_warning:
                ctx.finding("DISK_PRESSURE", "warning", "Low filesystem space", f"{mount} is {used:.1f}% used", "statvfs", evidence=[entry], recommendation="Inspect filesystem usage before future upgrades")
            if stats.f_files and stats.f_favail / stats.f_files < .05:
                ctx.finding("INODE_PRESSURE", "warning", "Low free inodes", f"{mount} has less than 5% free inodes", "statvfs", evidence=[entry])
        except OSError as exc:
            ctx.error("storage", f"{mount}: {exc}")
    ctx.results["storage"] = result

def collect_security(ctx, runner):
    enforce = safe_read("/sys/fs/selinux/enforce").strip()
    lockdown = safe_read("/sys/kernel/security/lockdown").strip()
    secureboot = None
    efivars = pathlib.Path("/sys/firmware/efi/efivars")
    try:
        for entry in efivars.glob("SecureBoot-*"):
            secureboot = bool(entry.read_bytes()[4])
            break
    except (OSError, IndexError):
        pass
    ctx.results["security"] = {"selinux_enforcing": True if enforce == "1" else False if enforce == "0" else None, "lockdown": lockdown, "secure_boot": secureboot, "lsm": safe_read("/sys/kernel/security/lsm").strip()}
    if enforce == "0":
        ctx.finding("SELINUX_PERMISSIVE", "notice", "SELinux is permissive", "SELinux enforcement is disabled", "selinux", recommendation="Verify whether permissive mode is intentional")

def collect_network(ctx, runner):
    hostname = platform.node()
    output = runner.run(["systemctl", "is-active", "NetworkManager.service"])
    ctx.results["network"] = {"hostname": hostname, "networkmanager_active": output.stdout.strip() == "active", "resolv_conf": safe_read("/etc/resolv.conf", 8192)}

def collect_system(ctx, runner):
    memory = extract_pairs(safe_read("/proc/meminfo"), ":")
    load = safe_read("/proc/loadavg").split()
    pressure = {}
    for resource in ("cpu", "io", "memory"):
        pressure[resource] = safe_read("/proc/pressure/" + resource).strip()
    ctx.results["system"] = {"memory": memory, "loadavg": load, "pressure": pressure, "cpu_count": os.cpu_count(), "uptime": safe_read("/proc/uptime").strip()}

def collect_journal_storage(ctx, runner):
    disk = runner.run(["journalctl", "--disk-usage"])
    config = {}
    for path in ("/etc/systemd/journald.conf", "/etc/systemd/journald.conf.d"):
        p = pathlib.Path(path)
        if p.is_file():
            config[str(p)] = safe_read(p, 20000)
        elif p.is_dir():
            for item in sorted(p.glob("*.conf"))[:50]:
                config[str(item)] = safe_read(item, 20000)
    ctx.results["journal_storage"] = {"usage": disk.stdout.strip(), "persistent_directory": pathlib.Path("/var/log/journal").is_dir(), "config": config}
    if not pathlib.Path("/var/log/journal").is_dir():
        ctx.finding("JOURNAL_VOLATILE", "notice", "Persistent journal directory absent", "Boot history may not survive reboot depending on journald configuration", "journald", recommendation="Consider persistent journal storage if historical boot diagnostics are required")

def collect_services(ctx, runner):
    names = ["systemd-journald.service", "systemd-udevd.service", "systemd-logind.service", "dbus-broker.service", "NetworkManager.service", "firewalld.service", "chronyd.service", "sshd.service", "podman.service", "crond.service", "systemd-resolved.service"]
    output = runner.run(["systemctl", "show", *names, "--property=Id,ActiveState,SubState,ExecMainStatus,Result,NRestarts,ActiveEnterTimestampMonotonic", "--no-pager"])
    records = []
    for section in re.split(r"\n\s*\n", output.stdout):
        values = extract_pairs(section)
        if values.get("Id"):
            records.append(values)
    ctx.results["services"] = records
    for record in records:
        if record.get("Result") in ("exit-code", "signal", "timeout", "core-dump"):
            ctx.finding("SERVICE_RESULT", "error", "Service failure result", f"{record['Id']}: {record['Result']}", "systemctl", evidence=[record])
        restarts = integer(record.get("NRestarts"), 0)
        if restarts >= ctx.args.restart_warning:
            ctx.finding("SERVICE_RESTARTS", "warning", "Repeated service restarts", f"{record['Id']} restarted {restarts} times", "systemctl", evidence=[record])

def collect_firmware(ctx, runner):
    dmi = {}
    root = pathlib.Path("/sys/class/dmi/id")
    for name in ("bios_vendor", "bios_version", "bios_date", "board_name", "board_vendor", "product_name", "product_version", "sys_vendor"):
        value = safe_read(root / name, 4096).strip()
        if value:
            dmi[name] = value
    ctx.results["firmware"] = {"dmi": dmi, "efi": pathlib.Path("/sys/firmware/efi").exists()}

def collect_modules(ctx, runner):
    modules = []
    for line in read_lines("/proc/modules"):
        parts = line.split()
        if len(parts) >= 3:
            modules.append({"name": parts[0], "size": integer(parts[1]), "references": integer(parts[2]), "dependencies": parts[3] if len(parts) > 3 else ""})
    ctx.results["modules"] = {"count": len(modules), "modules": modules[:ctx.args.max_items]}

def collect_crypt(ctx, runner):
    crypttab = []
    for line in read_lines("/etc/crypttab"):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        fields = stripped.split()
        if len(fields) >= 2:
            crypttab.append({"name": fields[0], "device": fields[1], "options": fields[3] if len(fields) > 3 else ""})
    ctx.results["crypt"] = crypttab

def collect_fstab(ctx, runner):
    records = []
    for line in read_lines("/etc/fstab"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) >= 4:
            records.append({"device": fields[0], "mount": fields[1], "type": fields[2], "options": fields[3], "dump": fields[4] if len(fields) > 4 else "", "pass": fields[5] if len(fields) > 5 else ""})
    ctx.results["fstab"] = records
    for record in records:
        if record["device"].startswith("/dev/") and not os.path.exists(record["device"]):
            ctx.finding("FSTAB_DEVICE_MISSING", "warning", "fstab device unavailable", f"{record['device']} for {record['mount']} was not found", "fstab", evidence=[record])

def collect_timers(ctx, runner):
    output = runner.run(["systemctl", "list-timers", "--all", "--no-pager", "--no-legend", "--plain"])
    ctx.results["timers"] = {"raw": output.stdout[:50000], "lines": len(output.stdout.splitlines())}

def collect_targets(ctx, runner):
    default = runner.run(["systemctl", "get-default"])
    state = runner.run(["systemctl", "is-system-running"])
    ctx.results["targets"] = {"default": default.stdout.strip(), "state": state.stdout.strip(), "state_exit": state.returncode}
    if state.stdout.strip() in ("degraded", "maintenance"):
        ctx.finding("SYSTEM_DEGRADED", "warning", "Systemd reports degraded state", f"System state is {state.stdout.strip()}", "systemctl", recommendation="Inspect failed units")

def collect_dnf(ctx, runner):
    paths = ["/var/log/dnf.log", "/var/log/dnf5.log", "/var/log/hawkey.log", "/var/log/dnf.rpm.log"]
    matches = []
    for path in paths:
        p = pathlib.Path(path)
        if p.exists():
            lines = read_lines(path, 500000)
            matches.append({"path": path, "lines": len(lines), "recent": lines[-30:]})
    ctx.results["dnf"] = matches

def collect_crash(ctx, runner):
    directories = ["/var/crash", "/var/lib/systemd/coredump", "/sys/fs/pstore"]
    result = []
    for directory in directories:
        path = pathlib.Path(directory)
        if not path.is_dir():
            continue
        try:
            entries = [{"name": item.name, "directory": item.is_dir()} for item in sorted(path.iterdir())[:ctx.args.max_items]]
        except OSError as exc:
            ctx.error("crash", str(exc))
            continue
        result.append({"path": directory, "entries": entries})
        if entries and directory == "/sys/fs/pstore":
            ctx.finding("PSTORE_RECORDS", "warning", "Persistent crash records present", f"Found {len(entries)} pstore records", "pstore", recommendation="Inspect persistent kernel crash records")
    ctx.results["crash"] = result

def collect_boot_files(ctx, runner):
    paths = ["/boot/vmlinuz-" + platform.release(), "/boot/initramfs-" + platform.release() + ".img", "/boot/grub2/grub.cfg", "/boot/efi/EFI"]
    result = []
    for path in paths:
        try:
            stat = os.stat(path)
            result.append({"path": path, "exists": True, "size": stat.st_size, "modified": iso(datetime.datetime.fromtimestamp(stat.st_mtime, UTC))})
        except OSError:
            result.append({"path": path, "exists": False})
    ctx.results["boot_files"] = result
    for item in result[:2]:
        if not item["exists"]:
            ctx.finding("BOOT_ARTIFACT_MISSING", "notice", "Current kernel boot artifact not found", f"{item['path']} is absent", "boot", recommendation="Confirm whether the distribution stores boot artifacts at another location")

def collect_initramfs(ctx, runner):
    path = "/boot/initramfs-" + platform.release() + ".img"
    if os.path.isfile(path):
        output = runner.run(["lsinitrd", path], timeout=ctx.args.timeout * 2)
        lines = output.stdout.splitlines()
        ctx.results["initramfs"] = {"path": path, "entries": len(lines), "sample": lines[:min(100, len(lines))]}
        if output.returncode != 0:
            ctx.error("initramfs", output.error or output.stderr.strip())
    else:
        ctx.results["initramfs"] = {"path": path, "entries": None}

def collect_boot_history(ctx, runner):
    result = runner.run(["last", "-x", "-n", str(ctx.args.max_items), "--time-format", "iso"])
    ctx.results["boot_history"] = {"raw": result.stdout[:50000]}
    if result.returncode != 0:
        ctx.error("boot_history", result.error or result.stderr.strip())

def collect_virtualization(ctx, runner):
    output = runner.run(["systemd-detect-virt"])
    ctx.results["virtualization"] = {"type": output.stdout.strip() if output.returncode == 0 else "none", "container": pathlib.Path("/.dockerenv").exists()}

def collect_time_sync(ctx, runner):
    output = runner.run(["timedatectl", "show", "--property=NTPSynchronized,Timezone,LocalRTC,TimeUSec", "--no-pager"])
    ctx.results["time_sync"] = extract_pairs(output.stdout)
    if ctx.results["time_sync"].get("NTPSynchronized") == "no":
        ctx.finding("NTP_UNSYNCED", "notice", "Clock not synchronized", "timedatectl reports NTP synchronization is unavailable", "timedatectl")

def collect_udev(ctx, runner):
    output = runner.run(["udevadm", "control", "--ping"])
    ctx.results["udev"] = {"responsive": output.returncode == 0, "error": output.error or output.stderr.strip()}
    if output.returncode != 0:
        ctx.finding("UDEV_UNRESPONSIVE", "warning", "Udev control unavailable", "udevadm control --ping did not succeed", "udevadm")

def collect_entropy(ctx, runner):
    value = integer(safe_read("/proc/sys/kernel/random/entropy_avail").strip())
    ctx.results["entropy"] = {"available": value}

def collect_swap(ctx, runner):
    rows = []
    for line in read_lines("/proc/swaps")[1:]:
        parts = line.split()
        if len(parts) >= 5:
            rows.append({"path": parts[0], "type": parts[1], "size_kib": integer(parts[2]), "used_kib": integer(parts[3]), "priority": integer(parts[4])})
    ctx.results["swap"] = rows

def collect_interrupts(ctx, runner):
    lines = read_lines("/proc/interrupts", 500000)
    ctx.results["interrupts"] = {"lines": len(lines), "sample": lines[:30]}

def collect_kernel_config(ctx, runner):
    paths = ["/boot/config-" + platform.release(), "/proc/config.gz"]
    result = {"source": None, "options": {}}
    for path in paths:
        try:
            if path.endswith(".gz"):
                with gzip.open(path, "rt", errors="replace") as stream:
                    raw = stream.read(2000000)
            else:
                raw = safe_read(path)
            if raw:
                result = {"source": path, "options": extract_pairs(raw)}
                break
        except OSError:
            continue
    ctx.results["kernel_config"] = {"source": result["source"], "count": len(result["options"]), "selected": {key: value for key, value in result["options"].items() if key in ("CONFIG_PREEMPT", "CONFIG_PREEMPT_DYNAMIC", "CONFIG_SECURITY_SELINUX", "CONFIG_BPF", "CONFIG_CGROUPS", "CONFIG_KEXEC", "CONFIG_PSTORE", "CONFIG_EFI")}}

def collect_rpm_kernels(ctx, runner):
    output = runner.run(["rpm", "-q", "--qf", "%{NAME}|%{VERSION}|%{RELEASE}|%{ARCH}|%{INSTALLTIME}\n", "kernel-core"])
    entries = []
    for line in output.stdout.splitlines():
        parts = line.split("|")
        if len(parts) == 5:
            entries.append({"name": parts[0], "version": parts[1], "release": parts[2], "arch": parts[3], "installed": iso(parse_timestamp(integer(parts[4])))})
    ctx.results["rpm_kernels"] = entries

def collect_sysctl(ctx, runner):
    keys = ["kernel.panic", "kernel.panic_on_oops", "kernel.hung_task_timeout_secs", "kernel.watchdog", "kernel.softlockup_panic", "kernel.hardlockup_panic", "vm.panic_on_oom", "vm.swappiness", "fs.file-max", "kernel.randomize_va_space", "kernel.kptr_restrict", "kernel.dmesg_restrict", "kernel.yama.ptrace_scope", "kernel.unprivileged_bpf_disabled"]
    result = {}
    for key in keys:
        result[key] = safe_read("/proc/sys/" + key.replace(".", "/"), 4096).strip() or None
    ctx.results["sysctl"] = result

def collect_environment(ctx, runner):
    ctx.results["environment"] = {"path": os.environ.get("PATH", ""), "locale": os.environ.get("LANG", ""), "python": sys.version.split()[0], "pid": os.getpid(), "cwd": os.getcwd(), "commands": {name: shutil.which(name) for name in ("journalctl", "systemctl", "systemd-analyze", "rpm", "lsinitrd", "last", "timedatectl", "udevadm")}}

def collect_all(ctx, runner):
    collectors = [collect_identity, collect_environment, collect_boots, collect_boot_timing, collect_units, collect_journal, collect_kernel, collect_bootloader, collect_mounts, collect_storage, collect_security, collect_network, collect_system, collect_journal_storage, collect_services, collect_firmware, collect_modules, collect_crypt, collect_fstab, collect_timers, collect_targets, collect_dnf, collect_crash, collect_boot_files, collect_initramfs, collect_boot_history, collect_virtualization, collect_time_sync, collect_udev, collect_entropy, collect_swap, collect_interrupts, collect_kernel_config, collect_rpm_kernels, collect_sysctl]
    for collector in collectors:
        if ctx.args.only and collector.__name__.removeprefix("collect_") not in ctx.args.only:
            continue
        try:
            collector(ctx, runner)
        except (OSError, ValueError, KeyError, TypeError, IndexError, RuntimeError) as exc:
            ctx.error(collector.__name__, f"{type(exc).__name__}: {exc}")

@dataclasses.dataclass(frozen=True)
class Rule:
    code: str
    category: str
    severity: str
    pattern: str
    title: str
    recommendation: str
    source: str = "both"
    flags: int = re.IGNORECASE

    def matches(self, message):
        try:
            return re.search(self.pattern, message, self.flags) is not None
        except re.error:
            return False

RULES = []

def register_rule(code, category, severity, pattern, title, recommendation, source="both"):
    RULES.append(Rule(code, category, severity, pattern, title, recommendation, source))

def evaluate_rules(ctx):
    journal = ctx.metadata.get("journal_records", [])
    kernel = ctx.metadata.get("kernel_lines", [])
    counts = collections.Counter()
    examples = collections.defaultdict(list)
    for record in journal:
        message = journal_message(record)
        for rule in RULES:
            if rule.source not in ("both", "journal"):
                continue
            if rule.matches(message):
                counts[rule.code] += 1
                if len(examples[rule.code]) < ctx.args.rule_examples:
                    examples[rule.code].append({"message": message[:500], "unit": record.get("_SYSTEMD_UNIT", ""), "time": journal_time(record)})
    for line in kernel:
        for rule in RULES:
            if rule.source != "kernel":
                continue
            if rule.matches(line):
                counts[rule.code] += 1
                if len(examples[rule.code]) < ctx.args.rule_examples:
                    examples[rule.code].append({"message": line[:500]})
    for rule in RULES:
        count = counts[rule.code]
        if count:
            ctx.finding(rule.code, rule.severity, rule.title, f"Matched {count} log entr{'y' if count == 1 else 'ies'} in category {rule.category}", rule.source, evidence=examples[rule.code], recommendation=rule.recommendation, confidence="medium")
    ctx.results["rules"] = {"catalog_size": len(RULES), "matched": sum(counts.values()), "counts": dict(counts)}

def apply_baseline(ctx, baseline):
    previous = baseline.get("results", {})
    current = ctx.results
    comparisons = {}
    for path in ("identity.kernel", "identity.cmdline", "targets.default", "security.selinux_enforcing", "security.secure_boot", "virtualization.type", "time_sync.Timezone"):
        section, field = path.split(".", 1)
        before = previous.get(section, {}).get(field)
        after = current.get(section, {}).get(field)
        if before != after:
            comparisons[path] = {"previous": before, "current": after}
    old_units = {entry.get("unit") for entry in previous.get("units", {}).get("failed", [])}
    new_units = {entry.get("unit") for entry in current.get("units", {}).get("failed", [])}
    comparisons["failed_units"] = {"new": sorted(new_units - old_units), "resolved": sorted(old_units - new_units)}
    old_boot = previous.get("timing", {}).get("stages", {}).get("total")
    new_boot = current.get("timing", {}).get("stages", {}).get("total")
    if isinstance(old_boot, (int, float)) and isinstance(new_boot, (int, float)):
        comparisons["boot_time"] = {"previous": old_boot, "current": new_boot, "delta": new_boot - old_boot, "delta_percent": (new_boot - old_boot) / old_boot * 100 if old_boot else None}
        if new_boot - old_boot > ctx.args.regression_seconds:
            ctx.finding("BOOT_REGRESSION", "warning", "Boot time regression", f"Boot time increased by {human_duration(new_boot - old_boot)}", "baseline", evidence=[comparisons["boot_time"]])
    for path, change in comparisons.items():
        if path in ("failed_units", "boot_time"):
            continue
        ctx.finding("BASELINE_CHANGE", "notice", "Boot baseline changed", f"{path} differs from saved baseline", "baseline", evidence=[{"field": path, **change}])
    ctx.results["baseline_comparison"] = comparisons

def serialize(ctx):
    return {"schema": "boot-forensics/1", "generated": iso(datetime.datetime.now(UTC)), "metadata": {k: v for k, v in ctx.metadata.items() if k not in ("journal_records", "kernel_lines")}, "results": ctx.results, "findings": [dataclasses.asdict(item) for item in ctx.findings], "errors": ctx.errors, "commands": ctx.command_log if ctx.args.include_commands else [], "summary": summarize_findings(ctx)}

def summarize_findings(ctx):
    severities = collections.Counter(item.severity for item in ctx.findings)
    return {"findings": len(ctx.findings), "severities": dict(severities), "errors": len(ctx.errors), "sections": len(ctx.results)}

def render_text(report, verbose=False):
    identity = report["results"].get("identity", {})
    lines = ["BOOT FORENSICS", "=" * 76, f"Host: {identity.get('hostname', 'unknown')}", f"Kernel: {identity.get('kernel', 'unknown')}", f"Boot ID: {identity.get('boot_id', 'unknown')}", f"Generated: {report['generated']}", ""]
    summary = report["summary"]
    lines.extend([f"Findings: {summary['findings']}  Errors: {summary['errors']}  Sections: {summary['sections']}", "Severities: " + ", ".join(f"{key}={value}" for key, value in sorted(summary["severities"].items())), ""])
    timing = report["results"].get("timing", {})
    if timing:
        lines.append("BOOT TIMING")
        for key, value in timing.get("stages", {}).items():
            lines.append(f"  {key:24s} {human_duration(value)}")
        lines.append("  Slowest units:")
        for entry in timing.get("blame", [])[:10]:
            lines.append(f"    {human_duration(entry['seconds']):>10}  {entry['unit']}")
        lines.append("")
    failed = report["results"].get("units", {}).get("failed", [])
    if failed:
        lines.append("FAILED UNITS")
        for item in failed[:30]:
            lines.append(f"  {item['unit']}: {item['description']}")
        lines.append("")
    lines.append("FINDINGS")
    for finding in report["findings"]:
        lines.append(f"  [{finding['severity'].upper():8}] {finding['code']}: {finding['title']}")
        lines.append(f"    {finding['description']}")
        if finding.get("recommendation"):
            lines.append(f"    Next: {finding['recommendation']}")
        if verbose:
            for evidence in finding.get("evidence", [])[:3]:
                lines.append("    Evidence: " + json.dumps(evidence, ensure_ascii=False, default=str)[:300])
    if not report["findings"]:
        lines.append("  No findings under the selected checks")
    if report["errors"]:
        lines.extend(["", "COLLECTION ERRORS"])
        for item in report["errors"]:
            lines.append(f"  {item['scope']}: {item['message']}")
    return "\n".join(lines) + "\n"

def render_csv(report):
    stream = io.StringIO()
    writer = csv.writer(stream)
    writer.writerow(["severity", "code", "title", "description", "source", "boot", "confidence", "recommendation"])
    for finding in report["findings"]:
        writer.writerow([finding.get(key, "") for key in ("severity", "code", "title", "description", "source", "boot", "confidence", "recommendation")])
    return stream.getvalue()

def render_ndjson(report):
    entries = [{"type": "metadata", "generated": report["generated"], "summary": report["summary"]}]
    entries.extend({"type": "finding", **finding} for finding in report["findings"])
    entries.extend({"type": "error", **error} for error in report["errors"])
    return "\n".join(json.dumps(item, ensure_ascii=False, default=str) for item in entries) + "\n"

def build_parser():
    parser = argparse.ArgumentParser(prog="boot-forensics", description="Read-only Linux boot, systemd, journal and kernel diagnostics")
    parser.add_argument("--boot", default="0", help="Journal boot index, default current boot")
    parser.add_argument("--format", choices=("text", "json", "csv", "ndjson"), default="text")
    parser.add_argument("--output", help="Write report to file instead of stdout")
    parser.add_argument("--baseline", help="Compare report against previous JSON snapshot")
    parser.add_argument("--save-baseline", help="Save complete report as baseline JSON")
    parser.add_argument("--fixture", help="Read command results from fixture directory")
    parser.add_argument("--only", nargs="*", default=[], help="Restrict collectors by section names")
    parser.add_argument("--timeout", type=float, default=12)
    parser.add_argument("--journal-limit", type=int, default=1500)
    parser.add_argument("--kernel-limit", type=int, default=1500)
    parser.add_argument("--journal-priority", type=int, choices=range(8))
    parser.add_argument("--max-items", type=int, default=200)
    parser.add_argument("--rule-examples", type=int, default=3)
    parser.add_argument("--slow-unit", type=float, default=10)
    parser.add_argument("--slow-boot", type=float, default=90)
    parser.add_argument("--disk-warning", type=float, default=90)
    parser.add_argument("--restart-warning", type=int, default=3)
    parser.add_argument("--regression-seconds", type=float, default=15)
    parser.add_argument("--severity", choices=("all", "notice", "warning", "error", "critical"), default="all")
    parser.add_argument("--include-commands", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--strict", action="store_true", help="Return nonzero if errors or high severity findings occur")
    parser.add_argument("--list-rules", action="store_true")
    parser.add_argument("--version", action="version", version="boot-forensics 1.0.0")
    return parser

def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.list_rules:
        for rule in RULES:
            print(f"{rule.code:40} {rule.severity:9} {rule.category:18} {rule.title}")
        return 0
    if args.timeout <= 0 or args.journal_limit < 0 or args.kernel_limit < 0 or args.max_items < 1 or args.rule_examples < 0:
        parser.error("invalid resource limit")
    runner = Runner(args.timeout, max(2000000, args.journal_limit * 2000), args.fixture)
    ctx = Context(args)
    collect_all(ctx, runner)
    evaluate_rules(ctx)
    if args.baseline:
        try:
            apply_baseline(ctx, load_json(args.baseline))
        except ValueError as exc:
            ctx.error("baseline", str(exc))
    if args.severity != "all":
        ranking = {"notice": 0, "warning": 1, "error": 2, "critical": 3}
        threshold = ranking[args.severity]
        ctx.findings = [finding for finding in ctx.findings if ranking.get(finding.severity, 0) >= threshold]
    ctx.findings.sort(key=lambda finding: ({"critical": 0, "error": 1, "warning": 2, "notice": 3}.get(finding.severity, 4), finding.code))
    ctx.command_log = runner.history
    report = serialize(ctx)
    if args.save_baseline:
        atomic_json(args.save_baseline, report)
    if args.format == "json":
        content = json.dumps(report, indent=2, ensure_ascii=False, default=str) + "\n"
    elif args.format == "csv":
        content = render_csv(report)
    elif args.format == "ndjson":
        content = render_ndjson(report)
    else:
        content = render_text(report, args.verbose)
    if args.output:
        pathlib.Path(args.output).write_text(content, encoding="utf-8")
    else:
        try:
            sys.stdout.write(content)
        except BrokenPipeError:
            return 0
    return 2 if args.strict and (ctx.errors or any(item.severity in ("critical", "error") for item in ctx.findings)) else 0


register_rule(
    'KERNEL_PANIC_01',
    'kernel_panic',
    'critical',
    'Kernel panic',
    'Kernel panic',
    'Inspect kernel stack traces and compare the previous known-good kernel',
    "journal",
)
register_rule(
    'KERNEL_PANIC_02',
    'kernel_panic',
    'critical',
    'not syncing',
    'not syncing',
    'Inspect kernel stack traces and compare the previous known-good kernel',
    "journal",
)
register_rule(
    'KERNEL_PANIC_03',
    'kernel_panic',
    'critical',
    'Oops:',
    'Oops:',
    'Inspect kernel stack traces and compare the previous known-good kernel',
    "journal",
)
register_rule(
    'KERNEL_PANIC_04',
    'kernel_panic',
    'critical',
    'BUG: unable to handle',
    'BUG: unable to handle',
    'Inspect kernel stack traces and compare the previous known-good kernel',
    "journal",
)
register_rule(
    'KERNEL_PANIC_05',
    'kernel_panic',
    'critical',
    'general protection fault',
    'general protection fault',
    'Inspect kernel stack traces and compare the previous known-good kernel',
    "journal",
)
register_rule(
    'KERNEL_PANIC_06',
    'kernel_panic',
    'critical',
    'invalid opcode',
    'invalid opcode',
    'Inspect kernel stack traces and compare the previous known-good kernel',
    "journal",
)
register_rule(
    'KERNEL_PANIC_07',
    'kernel_panic',
    'critical',
    'double fault',
    'double fault',
    'Inspect kernel stack traces and compare the previous known-good kernel',
    "journal",
)
register_rule(
    'KERNEL_PANIC_08',
    'kernel_panic',
    'critical',
    'stack overflow',
    'stack overflow',
    'Inspect kernel stack traces and compare the previous known-good kernel',
    "journal",
)
register_rule(
    'KERNEL_PANIC_09',
    'kernel_panic',
    'critical',
    'kernel BUG at',
    'kernel BUG at',
    'Inspect kernel stack traces and compare the previous known-good kernel',
    "journal",
)
register_rule(
    'KERNEL_PANIC_10',
    'kernel_panic',
    'critical',
    'fatal exception',
    'fatal exception',
    'Inspect kernel stack traces and compare the previous known-good kernel',
    "journal",
)
register_rule(
    'KERNEL_PANIC_11',
    'kernel_panic',
    'critical',
    'panic_on_warn',
    'panic_on_warn',
    'Inspect kernel stack traces and compare the previous known-good kernel',
    "journal",
)
register_rule(
    'KERNEL_PANIC_12',
    'kernel_panic',
    'critical',
    'RCU stall',
    'RCU stall',
    'Inspect kernel stack traces and compare the previous known-good kernel',
    "journal",
)
register_rule(
    'KERNEL_PANIC_13',
    'kernel_panic',
    'critical',
    'soft lockup',
    'soft lockup',
    'Inspect kernel stack traces and compare the previous known-good kernel',
    "journal",
)
register_rule(
    'KERNEL_PANIC_14',
    'kernel_panic',
    'critical',
    'hard LOCKUP',
    'hard LOCKUP',
    'Inspect kernel stack traces and compare the previous known-good kernel',
    "journal",
)
register_rule(
    'KERNEL_PANIC_15',
    'kernel_panic',
    'critical',
    'watchdog: BUG',
    'watchdog: BUG',
    'Inspect kernel stack traces and compare the previous known-good kernel',
    "journal",
)
register_rule(
    'KERNEL_PANIC_16',
    'kernel_panic',
    'critical',
    'hung task',
    'hung task',
    'Inspect kernel stack traces and compare the previous known-good kernel',
    "journal",
)
register_rule(
    'KERNEL_PANIC_17',
    'kernel_panic',
    'critical',
    'blocked for more than',
    'blocked for more than',
    'Inspect kernel stack traces and compare the previous known-good kernel',
    "journal",
)
register_rule(
    'KERNEL_PANIC_18',
    'kernel_panic',
    'critical',
    'scheduling while atomic',
    'scheduling while atomic',
    'Inspect kernel stack traces and compare the previous known-good kernel',
    "journal",
)
register_rule(
    'KERNEL_PANIC_19',
    'kernel_panic',
    'critical',
    'sleeping function called from invalid context',
    'sleeping function called from invalid context',
    'Inspect kernel stack traces and compare the previous known-good kernel',
    "journal",
)
register_rule(
    'KERNEL_PANIC_20',
    'kernel_panic',
    'critical',
    'bad page state',
    'bad page state',
    'Inspect kernel stack traces and compare the previous known-good kernel',
    "journal",
)
register_rule(
    'KERNEL_PANIC_21',
    'kernel_panic',
    'critical',
    'kernel NULL pointer dereference',
    'kernel NULL pointer dereference',
    'Inspect kernel stack traces and compare the previous known-good kernel',
    "journal",
)
register_rule(
    'MEMORY_01',
    'memory',
    'error',
    'Out of memory:',
    'Out of memory:',
    'Inspect memory pressure, process limits and OOM context',
    "journal",
)
register_rule(
    'MEMORY_02',
    'memory',
    'error',
    'oom-killer',
    'oom-killer',
    'Inspect memory pressure, process limits and OOM context',
    "journal",
)
register_rule(
    'MEMORY_03',
    'memory',
    'error',
    'Killed process',
    'Killed process',
    'Inspect memory pressure, process limits and OOM context',
    "journal",
)
register_rule(
    'MEMORY_04',
    'memory',
    'error',
    'Memory cgroup out of memory',
    'Memory cgroup out of memory',
    'Inspect memory pressure, process limits and OOM context',
    "journal",
)
register_rule(
    'MEMORY_05',
    'memory',
    'error',
    'page allocation failure',
    'page allocation failure',
    'Inspect memory pressure, process limits and OOM context',
    "journal",
)
register_rule(
    'MEMORY_06',
    'memory',
    'error',
    'allocation failure',
    'allocation failure',
    'Inspect memory pressure, process limits and OOM context',
    "journal",
)
register_rule(
    'MEMORY_07',
    'memory',
    'error',
    'memory corruption',
    'memory corruption',
    'Inspect memory pressure, process limits and OOM context',
    "journal",
)
register_rule(
    'MEMORY_08',
    'memory',
    'error',
    'bad page map',
    'bad page map',
    'Inspect memory pressure, process limits and OOM context',
    "journal",
)
register_rule(
    'MEMORY_09',
    'memory',
    'error',
    'bad page state',
    'bad page state',
    'Inspect memory pressure, process limits and OOM context',
    "journal",
)
register_rule(
    'MEMORY_10',
    'memory',
    'error',
    'slab corruption',
    'slab corruption',
    'Inspect memory pressure, process limits and OOM context',
    "journal",
)
register_rule(
    'MEMORY_11',
    'memory',
    'error',
    'SLUB: Unable to allocate',
    'SLUB: Unable to allocate',
    'Inspect memory pressure, process limits and OOM context',
    "journal",
)
register_rule(
    'MEMORY_12',
    'memory',
    'error',
    'vmalloc allocation failure',
    'vmalloc allocation failure',
    'Inspect memory pressure, process limits and OOM context',
    "journal",
)
register_rule(
    'MEMORY_13',
    'memory',
    'error',
    'lowmem_reserve',
    'lowmem_reserve',
    'Inspect memory pressure, process limits and OOM context',
    "journal",
)
register_rule(
    'MEMORY_14',
    'memory',
    'error',
    'kswapd.*stalled',
    'kswapd stalled',
    'Inspect memory pressure, process limits and OOM context',
    "journal",
)
register_rule(
    'MEMORY_15',
    'memory',
    'error',
    'compaction.*failed',
    'compaction failed',
    'Inspect memory pressure, process limits and OOM context',
    "journal",
)
register_rule(
    'MEMORY_16',
    'memory',
    'error',
    'memory hotplug.*failed',
    'memory hotplug failed',
    'Inspect memory pressure, process limits and OOM context',
    "journal",
)
register_rule(
    'MEMORY_17',
    'memory',
    'error',
    'hugepage.*allocation failed',
    'hugepage allocation failed',
    'Inspect memory pressure, process limits and OOM context',
    "journal",
)
register_rule(
    'MEMORY_18',
    'memory',
    'error',
    'swap.*I/O error',
    'swap I/O error',
    'Inspect memory pressure, process limits and OOM context',
    "journal",
)
register_rule(
    'MEMORY_19',
    'memory',
    'error',
    'zswap.*error',
    'zswap error',
    'Inspect memory pressure, process limits and OOM context',
    "journal",
)
register_rule(
    'MEMORY_20',
    'memory',
    'error',
    'zram.*failed',
    'zram failed',
    'Inspect memory pressure, process limits and OOM context',
    "journal",
)
register_rule(
    'FILESYSTEM_01',
    'filesystem',
    'error',
    'EXT4-fs error',
    'EXT4-fs error',
    'Check filesystem integrity and underlying storage health',
    "journal",
)
register_rule(
    'FILESYSTEM_02',
    'filesystem',
    'error',
    'EXT4-fs warning',
    'EXT4-fs warning',
    'Check filesystem integrity and underlying storage health',
    "journal",
)
register_rule(
    'FILESYSTEM_03',
    'filesystem',
    'error',
    'XFS.*corruption',
    'XFS corruption',
    'Check filesystem integrity and underlying storage health',
    "journal",
)
register_rule(
    'FILESYSTEM_04',
    'filesystem',
    'error',
    'XFS.*metadata I/O error',
    'XFS metadata I/O error',
    'Check filesystem integrity and underlying storage health',
    "journal",
)
register_rule(
    'FILESYSTEM_05',
    'filesystem',
    'error',
    'BTRFS error',
    'BTRFS error',
    'Check filesystem integrity and underlying storage health',
    "journal",
)
register_rule(
    'FILESYSTEM_06',
    'filesystem',
    'error',
    'BTRFS warning',
    'BTRFS warning',
    'Check filesystem integrity and underlying storage health',
    "journal",
)
register_rule(
    'FILESYSTEM_07',
    'filesystem',
    'error',
    'Buffer I/O error',
    'Buffer I/O error',
    'Check filesystem integrity and underlying storage health',
    "journal",
)
register_rule(
    'FILESYSTEM_08',
    'filesystem',
    'error',
    'I/O error, dev',
    'I/O error, dev',
    'Check filesystem integrity and underlying storage health',
    "journal",
)
register_rule(
    'FILESYSTEM_09',
    'filesystem',
    'error',
    'blk_update_request.*error',
    'blk_update_request error',
    'Check filesystem integrity and underlying storage health',
    "journal",
)
register_rule(
    'FILESYSTEM_10',
    'filesystem',
    'error',
    'journal.*aborted',
    'journal aborted',
    'Check filesystem integrity and underlying storage health',
    "journal",
)
register_rule(
    'FILESYSTEM_11',
    'filesystem',
    'error',
    'Remounting filesystem read-only',
    'Remounting filesystem read-only',
    'Check filesystem integrity and underlying storage health',
    "journal",
)
register_rule(
    'FILESYSTEM_12',
    'filesystem',
    'error',
    'filesystem.*read-only',
    'filesystem read-only',
    'Check filesystem integrity and underlying storage health',
    "journal",
)
register_rule(
    'FILESYSTEM_13',
    'filesystem',
    'error',
    'orphan cleanup.*failed',
    'orphan cleanup failed',
    'Check filesystem integrity and underlying storage health',
    "journal",
)
register_rule(
    'FILESYSTEM_14',
    'filesystem',
    'error',
    'superblock.*corrupt',
    'superblock corrupt',
    'Check filesystem integrity and underlying storage health',
    "journal",
)
register_rule(
    'FILESYSTEM_15',
    'filesystem',
    'error',
    'bad magic number',
    'bad magic number',
    'Check filesystem integrity and underlying storage health',
    "journal",
)
register_rule(
    'FILESYSTEM_16',
    'filesystem',
    'error',
    'inode.*corrupt',
    'inode corrupt',
    'Check filesystem integrity and underlying storage health',
    "journal",
)
register_rule(
    'FILESYSTEM_17',
    'filesystem',
    'error',
    'metadata checksum.*failed',
    'metadata checksum failed',
    'Check filesystem integrity and underlying storage health',
    "journal",
)
register_rule(
    'FILESYSTEM_18',
    'filesystem',
    'error',
    'quota.*failed',
    'quota failed',
    'Check filesystem integrity and underlying storage health',
    "journal",
)
register_rule(
    'FILESYSTEM_19',
    'filesystem',
    'error',
    'fsck.*failed',
    'fsck failed',
    'Check filesystem integrity and underlying storage health',
    "journal",
)
register_rule(
    'FILESYSTEM_20',
    'filesystem',
    'error',
    'mount.*failed',
    'mount failed',
    'Check filesystem integrity and underlying storage health',
    "journal",
)
register_rule(
    'STORAGE_01',
    'storage',
    'error',
    'ata.*failed command',
    'ata failed command',
    'Inspect block-device errors and storage telemetry',
    "journal",
)
register_rule(
    'STORAGE_02',
    'storage',
    'error',
    'ata.*hard resetting link',
    'ata hard resetting link',
    'Inspect block-device errors and storage telemetry',
    "journal",
)
register_rule(
    'STORAGE_03',
    'storage',
    'error',
    'ata.*exception',
    'ata exception',
    'Inspect block-device errors and storage telemetry',
    "journal",
)
register_rule(
    'STORAGE_04',
    'storage',
    'error',
    'nvme.*timeout',
    'nvme timeout',
    'Inspect block-device errors and storage telemetry',
    "journal",
)
register_rule(
    'STORAGE_05',
    'storage',
    'error',
    'nvme.*resetting controller',
    'nvme resetting controller',
    'Inspect block-device errors and storage telemetry',
    "journal",
)
register_rule(
    'STORAGE_06',
    'storage',
    'error',
    'nvme.*I/O.*error',
    'nvme I/O error',
    'Inspect block-device errors and storage telemetry',
    "journal",
)
register_rule(
    'STORAGE_07',
    'storage',
    'error',
    'SCSI.*sense key',
    'SCSI sense key',
    'Inspect block-device errors and storage telemetry',
    "journal",
)
register_rule(
    'STORAGE_08',
    'storage',
    'error',
    'medium error',
    'medium error',
    'Inspect block-device errors and storage telemetry',
    "journal",
)
register_rule(
    'STORAGE_09',
    'storage',
    'error',
    'unrecovered read error',
    'unrecovered read error',
    'Inspect block-device errors and storage telemetry',
    "journal",
)
register_rule(
    'STORAGE_10',
    'storage',
    'error',
    'write protect is on',
    'write protect is on',
    'Inspect block-device errors and storage telemetry',
    "journal",
)
register_rule(
    'STORAGE_11',
    'storage',
    'error',
    'device offline',
    'device offline',
    'Inspect block-device errors and storage telemetry',
    "journal",
)
register_rule(
    'STORAGE_12',
    'storage',
    'error',
    'disk.*failure',
    'disk failure',
    'Inspect block-device errors and storage telemetry',
    "journal",
)
register_rule(
    'STORAGE_13',
    'storage',
    'error',
    'I/O timeout',
    'I/O timeout',
    'Inspect block-device errors and storage telemetry',
    "journal",
)
register_rule(
    'STORAGE_14',
    'storage',
    'error',
    'multipath.*failed',
    'multipath failed',
    'Inspect block-device errors and storage telemetry',
    "journal",
)
register_rule(
    'STORAGE_15',
    'storage',
    'error',
    'dm-.*error',
    'dm- error',
    'Inspect block-device errors and storage telemetry',
    "journal",
)
register_rule(
    'STORAGE_16',
    'storage',
    'error',
    'device-mapper.*error',
    'device-mapper error',
    'Inspect block-device errors and storage telemetry',
    "journal",
)
register_rule(
    'STORAGE_17',
    'storage',
    'error',
    'md.*degraded',
    'md degraded',
    'Inspect block-device errors and storage telemetry',
    "journal",
)
register_rule(
    'STORAGE_18',
    'storage',
    'error',
    'RAID.*degraded',
    'RAID degraded',
    'Inspect block-device errors and storage telemetry',
    "journal",
)
register_rule(
    'STORAGE_19',
    'storage',
    'error',
    'SMART.*FAILED',
    'SMART FAILED',
    'Inspect block-device errors and storage telemetry',
    "journal",
)
register_rule(
    'STORAGE_20',
    'storage',
    'error',
    'thin pool.*out of data space',
    'thin pool out of data space',
    'Inspect block-device errors and storage telemetry',
    "journal",
)
register_rule(
    'NETWORK_01',
    'network',
    'warning',
    'link is down',
    'link is down',
    'Inspect interface state, routes and NetworkManager journal',
    "journal",
)
register_rule(
    'NETWORK_02',
    'network',
    'warning',
    'link down',
    'link down',
    'Inspect interface state, routes and NetworkManager journal',
    "journal",
)
register_rule(
    'NETWORK_03',
    'network',
    'warning',
    'NIC Link is Down',
    'NIC Link is Down',
    'Inspect interface state, routes and NetworkManager journal',
    "journal",
)
register_rule(
    'NETWORK_04',
    'network',
    'warning',
    'carrier lost',
    'carrier lost',
    'Inspect interface state, routes and NetworkManager journal',
    "journal",
)
register_rule(
    'NETWORK_05',
    'network',
    'warning',
    'network unreachable',
    'network unreachable',
    'Inspect interface state, routes and NetworkManager journal',
    "journal",
)
register_rule(
    'NETWORK_06',
    'network',
    'warning',
    'no route to host',
    'no route to host',
    'Inspect interface state, routes and NetworkManager journal',
    "journal",
)
register_rule(
    'NETWORK_07',
    'network',
    'warning',
    'DHCP.*failed',
    'DHCP failed',
    'Inspect interface state, routes and NetworkManager journal',
    "journal",
)
register_rule(
    'NETWORK_08',
    'network',
    'warning',
    'DHCP.*timeout',
    'DHCP timeout',
    'Inspect interface state, routes and NetworkManager journal',
    "journal",
)
register_rule(
    'NETWORK_09',
    'network',
    'warning',
    'DNS.*timeout',
    'DNS timeout',
    'Inspect interface state, routes and NetworkManager journal',
    "journal",
)
register_rule(
    'NETWORK_10',
    'network',
    'warning',
    'DNS.*failed',
    'DNS failed',
    'Inspect interface state, routes and NetworkManager journal',
    "journal",
)
register_rule(
    'NETWORK_11',
    'network',
    'warning',
    'resolver.*failed',
    'resolver failed',
    'Inspect interface state, routes and NetworkManager journal',
    "journal",
)
register_rule(
    'NETWORK_12',
    'network',
    'warning',
    'NetworkManager.*failed',
    'NetworkManager failed',
    'Inspect interface state, routes and NetworkManager journal',
    "journal",
)
register_rule(
    'NETWORK_13',
    'network',
    'warning',
    'network.*disconnected',
    'network disconnected',
    'Inspect interface state, routes and NetworkManager journal',
    "journal",
)
register_rule(
    'NETWORK_14',
    'network',
    'warning',
    'connection.*timed out',
    'connection timed out',
    'Inspect interface state, routes and NetworkManager journal',
    "journal",
)
register_rule(
    'NETWORK_15',
    'network',
    'warning',
    'bond.*link failure',
    'bond link failure',
    'Inspect interface state, routes and NetworkManager journal',
    "journal",
)
register_rule(
    'NETWORK_16',
    'network',
    'warning',
    'bridge.*failed',
    'bridge failed',
    'Inspect interface state, routes and NetworkManager journal',
    "journal",
)
register_rule(
    'NETWORK_17',
    'network',
    'warning',
    'veth.*failed',
    'veth failed',
    'Inspect interface state, routes and NetworkManager journal',
    "journal",
)
register_rule(
    'NETWORK_18',
    'network',
    'warning',
    'IPv6.*duplicate address',
    'IPv6 duplicate address',
    'Inspect interface state, routes and NetworkManager journal',
    "journal",
)
register_rule(
    'NETWORK_19',
    'network',
    'warning',
    'duplicate address detected',
    'duplicate address detected',
    'Inspect interface state, routes and NetworkManager journal',
    "journal",
)
register_rule(
    'NETWORK_20',
    'network',
    'warning',
    'address already in use',
    'address already in use',
    'Inspect interface state, routes and NetworkManager journal',
    "journal",
)
register_rule(
    'FIRMWARE_01',
    'firmware',
    'warning',
    'ACPI Error',
    'ACPI Error',
    'Review firmware compatibility and virtual hardware settings',
    "journal",
)
register_rule(
    'FIRMWARE_02',
    'firmware',
    'warning',
    'ACPI BIOS Error',
    'ACPI BIOS Error',
    'Review firmware compatibility and virtual hardware settings',
    "journal",
)
register_rule(
    'FIRMWARE_03',
    'firmware',
    'warning',
    'ACPI Warning',
    'ACPI Warning',
    'Review firmware compatibility and virtual hardware settings',
    "journal",
)
register_rule(
    'FIRMWARE_04',
    'firmware',
    'warning',
    'firmware.*failed to load',
    'firmware failed to load',
    'Review firmware compatibility and virtual hardware settings',
    "journal",
)
register_rule(
    'FIRMWARE_05',
    'firmware',
    'warning',
    'Direct firmware load.*failed',
    'Direct firmware load failed',
    'Review firmware compatibility and virtual hardware settings',
    "journal",
)
register_rule(
    'FIRMWARE_06',
    'firmware',
    'warning',
    'microcode.*failed',
    'microcode failed',
    'Review firmware compatibility and virtual hardware settings',
    "journal",
)
register_rule(
    'FIRMWARE_07',
    'firmware',
    'warning',
    'BIOS.*bug',
    'BIOS bug',
    'Review firmware compatibility and virtual hardware settings',
    "journal",
)
register_rule(
    'FIRMWARE_08',
    'firmware',
    'warning',
    'EFI.*failed',
    'EFI failed',
    'Review firmware compatibility and virtual hardware settings',
    "journal",
)
register_rule(
    'FIRMWARE_09',
    'firmware',
    'warning',
    'UEFI.*error',
    'UEFI error',
    'Review firmware compatibility and virtual hardware settings',
    "journal",
)
register_rule(
    'FIRMWARE_10',
    'firmware',
    'warning',
    'SMBIOS.*invalid',
    'SMBIOS invalid',
    'Review firmware compatibility and virtual hardware settings',
    "journal",
)
register_rule(
    'FIRMWARE_11',
    'firmware',
    'warning',
    'DMI.*invalid',
    'DMI invalid',
    'Review firmware compatibility and virtual hardware settings',
    "journal",
)
register_rule(
    'FIRMWARE_12',
    'firmware',
    'warning',
    'TPM.*error',
    'TPM error',
    'Review firmware compatibility and virtual hardware settings',
    "journal",
)
register_rule(
    'FIRMWARE_13',
    'firmware',
    'warning',
    'tpm.*failed',
    'tpm failed',
    'Review firmware compatibility and virtual hardware settings',
    "journal",
)
register_rule(
    'FIRMWARE_14',
    'firmware',
    'warning',
    'secure boot.*failed',
    'secure boot failed',
    'Review firmware compatibility and virtual hardware settings',
    "journal",
)
register_rule(
    'FIRMWARE_15',
    'firmware',
    'warning',
    'MCE:',
    'MCE:',
    'Review firmware compatibility and virtual hardware settings',
    "journal",
)
register_rule(
    'FIRMWARE_16',
    'firmware',
    'warning',
    'Machine check events logged',
    'Machine check events logged',
    'Review firmware compatibility and virtual hardware settings',
    "journal",
)
register_rule(
    'FIRMWARE_17',
    'firmware',
    'warning',
    'hardware error',
    'hardware error',
    'Review firmware compatibility and virtual hardware settings',
    "journal",
)
register_rule(
    'FIRMWARE_18',
    'firmware',
    'warning',
    'EDAC.*error',
    'EDAC error',
    'Review firmware compatibility and virtual hardware settings',
    "journal",
)
register_rule(
    'FIRMWARE_19',
    'firmware',
    'warning',
    'APEI.*error',
    'APEI error',
    'Review firmware compatibility and virtual hardware settings',
    "journal",
)
register_rule(
    'FIRMWARE_20',
    'firmware',
    'warning',
    'HEST.*error',
    'HEST error',
    'Review firmware compatibility and virtual hardware settings',
    "journal",
)
register_rule(
    'BOOT_01',
    'boot',
    'error',
    'Failed to start',
    'Failed to start',
    'Inspect the failing unit with systemctl status and journalctl -u',
    "journal",
)
register_rule(
    'BOOT_02',
    'boot',
    'error',
    'Dependency failed',
    'Dependency failed',
    'Inspect the failing unit with systemctl status and journalctl -u',
    "journal",
)
register_rule(
    'BOOT_03',
    'boot',
    'error',
    'Timed out waiting for device',
    'Timed out waiting for device',
    'Inspect the failing unit with systemctl status and journalctl -u',
    "journal",
)
register_rule(
    'BOOT_04',
    'boot',
    'error',
    'A start job is running',
    'A start job is running',
    'Inspect the failing unit with systemctl status and journalctl -u',
    "journal",
)
register_rule(
    'BOOT_05',
    'boot',
    'error',
    'Failed to mount',
    'Failed to mount',
    'Inspect the failing unit with systemctl status and journalctl -u',
    "journal",
)
register_rule(
    'BOOT_06',
    'boot',
    'error',
    'Failed to activate swap',
    'Failed to activate swap',
    'Inspect the failing unit with systemctl status and journalctl -u',
    "journal",
)
register_rule(
    'BOOT_07',
    'boot',
    'error',
    'Failed to load kernel modules',
    'Failed to load kernel modules',
    'Inspect the failing unit with systemctl status and journalctl -u',
    "journal",
)
register_rule(
    'BOOT_08',
    'boot',
    'error',
    'Failed to start Load Kernel Modules',
    'Failed to start Load Kernel Modules',
    'Inspect the failing unit with systemctl status and journalctl -u',
    "journal",
)
register_rule(
    'BOOT_09',
    'boot',
    'error',
    'Failed to start Remount Root',
    'Failed to start Remount Root',
    'Inspect the failing unit with systemctl status and journalctl -u',
    "journal",
)
register_rule(
    'BOOT_10',
    'boot',
    'error',
    'Failed to start Network Manager',
    'Failed to start Network Manager',
    'Inspect the failing unit with systemctl status and journalctl -u',
    "journal",
)
register_rule(
    'BOOT_11',
    'boot',
    'error',
    'Failed to start Journal Service',
    'Failed to start Journal Service',
    'Inspect the failing unit with systemctl status and journalctl -u',
    "journal",
)
register_rule(
    'BOOT_12',
    'boot',
    'error',
    'Failed to start User Manager',
    'Failed to start User Manager',
    'Inspect the failing unit with systemctl status and journalctl -u',
    "journal",
)
register_rule(
    'BOOT_13',
    'boot',
    'error',
    'Failed to reach target',
    'Failed to reach target',
    'Inspect the failing unit with systemctl status and journalctl -u',
    "journal",
)
register_rule(
    'BOOT_14',
    'boot',
    'error',
    'Job.*failed',
    'Job failed',
    'Inspect the failing unit with systemctl status and journalctl -u',
    "journal",
)
register_rule(
    'BOOT_15',
    'boot',
    'error',
    'start operation timed out',
    'start operation timed out',
    'Inspect the failing unit with systemctl status and journalctl -u',
    "journal",
)
register_rule(
    'BOOT_16',
    'boot',
    'error',
    'start request repeated too quickly',
    'start request repeated too quickly',
    'Inspect the failing unit with systemctl status and journalctl -u',
    "journal",
)
register_rule(
    'BOOT_17',
    'boot',
    'error',
    'Failed with result',
    'Failed with result',
    'Inspect the failing unit with systemctl status and journalctl -u',
    "journal",
)
register_rule(
    'BOOT_18',
    'boot',
    'error',
    'Main process exited',
    'Main process exited',
    'Inspect the failing unit with systemctl status and journalctl -u',
    "journal",
)
register_rule(
    'BOOT_19',
    'boot',
    'error',
    'Control process exited',
    'Control process exited',
    'Inspect the failing unit with systemctl status and journalctl -u',
    "journal",
)
register_rule(
    'BOOT_20',
    'boot',
    'error',
    'Failed to execute',
    'Failed to execute',
    'Inspect the failing unit with systemctl status and journalctl -u',
    "journal",
)
register_rule(
    'SECURITY_01',
    'security',
    'warning',
    'avc:  denied',
    'avc:  denied',
    'Review security audit records and policy before changing enforcement',
    "journal",
)
register_rule(
    'SECURITY_02',
    'security',
    'warning',
    'SELinux.*denied',
    'SELinux denied',
    'Review security audit records and policy before changing enforcement',
    "journal",
)
register_rule(
    'SECURITY_03',
    'security',
    'warning',
    'SELinux.*failed',
    'SELinux failed',
    'Review security audit records and policy before changing enforcement',
    "journal",
)
register_rule(
    'SECURITY_04',
    'security',
    'warning',
    'audit.*backlog limit exceeded',
    'audit backlog limit exceeded',
    'Review security audit records and policy before changing enforcement',
    "journal",
)
register_rule(
    'SECURITY_05',
    'security',
    'warning',
    'audit.*lost',
    'audit lost',
    'Review security audit records and policy before changing enforcement',
    "journal",
)
register_rule(
    'SECURITY_06',
    'security',
    'warning',
    'audit.*failure',
    'audit failure',
    'Review security audit records and policy before changing enforcement',
    "journal",
)
register_rule(
    'SECURITY_07',
    'security',
    'warning',
    'IMA.*appraisal failed',
    'IMA appraisal failed',
    'Review security audit records and policy before changing enforcement',
    "journal",
)
register_rule(
    'SECURITY_08',
    'security',
    'warning',
    'integrity.*violation',
    'integrity violation',
    'Review security audit records and policy before changing enforcement',
    "journal",
)
register_rule(
    'SECURITY_09',
    'security',
    'warning',
    'Lockdown:.*restricted',
    'Lockdown: restricted',
    'Review security audit records and policy before changing enforcement',
    "journal",
)
register_rule(
    'SECURITY_10',
    'security',
    'warning',
    'apparmor="DENIED"',
    'apparmor="DENIED"',
    'Review security audit records and policy before changing enforcement',
    "journal",
)
register_rule(
    'SECURITY_11',
    'security',
    'warning',
    'seccomp.*violation',
    'seccomp violation',
    'Review security audit records and policy before changing enforcement',
    "journal",
)
register_rule(
    'SECURITY_12',
    'security',
    'warning',
    'polkit.*denied',
    'polkit denied',
    'Review security audit records and policy before changing enforcement',
    "journal",
)
register_rule(
    'SECURITY_13',
    'security',
    'warning',
    'authentication failure',
    'authentication failure',
    'Review security audit records and policy before changing enforcement',
    "journal",
)
register_rule(
    'SECURITY_14',
    'security',
    'warning',
    'pam_unix.*failure',
    'pam_unix failure',
    'Review security audit records and policy before changing enforcement',
    "journal",
)
register_rule(
    'SECURITY_15',
    'security',
    'warning',
    'Failed password',
    'Failed password',
    'Review security audit records and policy before changing enforcement',
    "journal",
)
register_rule(
    'SECURITY_16',
    'security',
    'warning',
    'invalid user',
    'invalid user',
    'Review security audit records and policy before changing enforcement',
    "journal",
)
register_rule(
    'SECURITY_17',
    'security',
    'warning',
    'sudo:.*incorrect password',
    'sudo: incorrect password',
    'Review security audit records and policy before changing enforcement',
    "journal",
)
register_rule(
    'SECURITY_18',
    'security',
    'warning',
    'sshd.*fatal',
    'sshd fatal',
    'Review security audit records and policy before changing enforcement',
    "journal",
)
register_rule(
    'SECURITY_19',
    'security',
    'warning',
    'permission denied',
    'permission denied',
    'Review security audit records and policy before changing enforcement',
    "journal",
)
register_rule(
    'SECURITY_20',
    'security',
    'warning',
    'certificate.*expired',
    'certificate expired',
    'Review security audit records and policy before changing enforcement',
    "journal",
)
register_rule(
    'CONTAINERS_01',
    'containers',
    'warning',
    'podman.*failed',
    'podman failed',
    'Inspect Podman logs, OCI runtime and container cgroups',
    "journal",
)
register_rule(
    'CONTAINERS_02',
    'containers',
    'warning',
    'conmon.*failed',
    'conmon failed',
    'Inspect Podman logs, OCI runtime and container cgroups',
    "journal",
)
register_rule(
    'CONTAINERS_03',
    'containers',
    'warning',
    'crun.*failed',
    'crun failed',
    'Inspect Podman logs, OCI runtime and container cgroups',
    "journal",
)
register_rule(
    'CONTAINERS_04',
    'containers',
    'warning',
    'runc.*failed',
    'runc failed',
    'Inspect Podman logs, OCI runtime and container cgroups',
    "journal",
)
register_rule(
    'CONTAINERS_05',
    'containers',
    'warning',
    'containerd.*failed',
    'containerd failed',
    'Inspect Podman logs, OCI runtime and container cgroups',
    "journal",
)
register_rule(
    'CONTAINERS_06',
    'containers',
    'warning',
    'overlayfs.*error',
    'overlayfs error',
    'Inspect Podman logs, OCI runtime and container cgroups',
    "journal",
)
register_rule(
    'CONTAINERS_07',
    'containers',
    'warning',
    'overlay.*failed',
    'overlay failed',
    'Inspect Podman logs, OCI runtime and container cgroups',
    "journal",
)
register_rule(
    'CONTAINERS_08',
    'containers',
    'warning',
    'cgroup.*failed',
    'cgroup failed',
    'Inspect Podman logs, OCI runtime and container cgroups',
    "journal",
)
register_rule(
    'CONTAINERS_09',
    'containers',
    'warning',
    'cgroup.*out of memory',
    'cgroup out of memory',
    'Inspect Podman logs, OCI runtime and container cgroups',
    "journal",
)
register_rule(
    'CONTAINERS_10',
    'containers',
    'warning',
    'failed to create container',
    'failed to create container',
    'Inspect Podman logs, OCI runtime and container cgroups',
    "journal",
)
register_rule(
    'CONTAINERS_11',
    'containers',
    'warning',
    'failed to start container',
    'failed to start container',
    'Inspect Podman logs, OCI runtime and container cgroups',
    "journal",
)
register_rule(
    'CONTAINERS_12',
    'containers',
    'warning',
    'container.*exited unexpectedly',
    'container exited unexpectedly',
    'Inspect Podman logs, OCI runtime and container cgroups',
    "journal",
)
register_rule(
    'CONTAINERS_13',
    'containers',
    'warning',
    'container.*OOM',
    'container OOM',
    'Inspect Podman logs, OCI runtime and container cgroups',
    "journal",
)
register_rule(
    'CONTAINERS_14',
    'containers',
    'warning',
    'OCI runtime.*error',
    'OCI runtime error',
    'Inspect Podman logs, OCI runtime and container cgroups',
    "journal",
)
register_rule(
    'CONTAINERS_15',
    'containers',
    'warning',
    'namespace.*operation not permitted',
    'namespace operation not permitted',
    'Inspect Podman logs, OCI runtime and container cgroups',
    "journal",
)
register_rule(
    'CONTAINERS_16',
    'containers',
    'warning',
    'netavark.*failed',
    'netavark failed',
    'Inspect Podman logs, OCI runtime and container cgroups',
    "journal",
)
register_rule(
    'CONTAINERS_17',
    'containers',
    'warning',
    'aardvark-dns.*failed',
    'aardvark-dns failed',
    'Inspect Podman logs, OCI runtime and container cgroups',
    "journal",
)
register_rule(
    'CONTAINERS_18',
    'containers',
    'warning',
    'slirp4netns.*failed',
    'slirp4netns failed',
    'Inspect Podman logs, OCI runtime and container cgroups',
    "journal",
)
register_rule(
    'CONTAINERS_19',
    'containers',
    'warning',
    'pasta.*failed',
    'pasta failed',
    'Inspect Podman logs, OCI runtime and container cgroups',
    "journal",
)
register_rule(
    'CONTAINERS_20',
    'containers',
    'warning',
    'rootless.*failed',
    'rootless failed',
    'Inspect Podman logs, OCI runtime and container cgroups',
    "journal",
)
register_rule(
    'SYSTEMD_01',
    'systemd',
    'error',
    'systemd.*Failed',
    'systemd Failed',
    'Review unit configuration and dependency ordering',
    "journal",
)
register_rule(
    'SYSTEMD_02',
    'systemd',
    'error',
    'systemd.*timeout',
    'systemd timeout',
    'Review unit configuration and dependency ordering',
    "journal",
)
register_rule(
    'SYSTEMD_03',
    'systemd',
    'error',
    'systemd.*dependency failed',
    'systemd dependency failed',
    'Review unit configuration and dependency ordering',
    "journal",
)
register_rule(
    'SYSTEMD_04',
    'systemd',
    'error',
    'systemd.*Failed to fork',
    'systemd Failed to fork',
    'Review unit configuration and dependency ordering',
    "journal",
)
register_rule(
    'SYSTEMD_05',
    'systemd',
    'error',
    'systemd.*Failed to allocate',
    'systemd Failed to allocate',
    'Review unit configuration and dependency ordering',
    "journal",
)
register_rule(
    'SYSTEMD_06',
    'systemd',
    'error',
    'systemd.*Failed to create',
    'systemd Failed to create',
    'Review unit configuration and dependency ordering',
    "journal",
)
register_rule(
    'SYSTEMD_07',
    'systemd',
    'error',
    'systemd.*Failed to set',
    'systemd Failed to set',
    'Review unit configuration and dependency ordering',
    "journal",
)
register_rule(
    'SYSTEMD_08',
    'systemd',
    'error',
    'systemd.*Failed to attach',
    'systemd Failed to attach',
    'Review unit configuration and dependency ordering',
    "journal",
)
register_rule(
    'SYSTEMD_09',
    'systemd',
    'error',
    'systemd.*Failed to open',
    'systemd Failed to open',
    'Review unit configuration and dependency ordering',
    "journal",
)
register_rule(
    'SYSTEMD_10',
    'systemd',
    'error',
    'systemd.*Failed to execute',
    'systemd Failed to execute',
    'Review unit configuration and dependency ordering',
    "journal",
)
register_rule(
    'SYSTEMD_11',
    'systemd',
    'error',
    'systemd.*Failed to parse',
    'systemd Failed to parse',
    'Review unit configuration and dependency ordering',
    "journal",
)
register_rule(
    'SYSTEMD_12',
    'systemd',
    'error',
    'systemd.*Failed to load',
    'systemd Failed to load',
    'Review unit configuration and dependency ordering',
    "journal",
)
register_rule(
    'SYSTEMD_13',
    'systemd',
    'error',
    'systemd.*Failed to mount',
    'systemd Failed to mount',
    'Review unit configuration and dependency ordering',
    "journal",
)
register_rule(
    'SYSTEMD_14',
    'systemd',
    'error',
    'systemd.*Failed to activate',
    'systemd Failed to activate',
    'Review unit configuration and dependency ordering',
    "journal",
)
register_rule(
    'SYSTEMD_15',
    'systemd',
    'error',
    'systemd.*Failed to connect',
    'systemd Failed to connect',
    'Review unit configuration and dependency ordering',
    "journal",
)
register_rule(
    'SYSTEMD_16',
    'systemd',
    'error',
    'systemd.*Failed to resolve',
    'systemd Failed to resolve',
    'Review unit configuration and dependency ordering',
    "journal",
)
register_rule(
    'SYSTEMD_17',
    'systemd',
    'error',
    'systemd.*Failed to enqueue',
    'systemd Failed to enqueue',
    'Review unit configuration and dependency ordering',
    "journal",
)
register_rule(
    'SYSTEMD_18',
    'systemd',
    'error',
    'systemd.*Failed to deserialize',
    'systemd Failed to deserialize',
    'Review unit configuration and dependency ordering',
    "journal",
)
register_rule(
    'SYSTEMD_19',
    'systemd',
    'error',
    'systemd.*Failed to restore',
    'systemd Failed to restore',
    'Review unit configuration and dependency ordering',
    "journal",
)
register_rule(
    'SYSTEMD_20',
    'systemd',
    'error',
    'systemd.*Failed to watch',
    'systemd Failed to watch',
    'Review unit configuration and dependency ordering',
    "journal",
)
register_rule(
    'JOURNAL_01',
    'journal',
    'warning',
    'journal.*corrupted',
    'journal corrupted',
    'Check journald storage, permissions and disk space',
    "journal",
)
register_rule(
    'JOURNAL_02',
    'journal',
    'warning',
    'journal.*truncated',
    'journal truncated',
    'Check journald storage, permissions and disk space',
    "journal",
)
register_rule(
    'JOURNAL_03',
    'journal',
    'warning',
    'journal.*rotat.*failed',
    'journal rotat failed',
    'Check journald storage, permissions and disk space',
    "journal",
)
register_rule(
    'JOURNAL_04',
    'journal',
    'warning',
    'journal.*write.*failed',
    'journal write failed',
    'Check journald storage, permissions and disk space',
    "journal",
)
register_rule(
    'JOURNAL_05',
    'journal',
    'warning',
    'journal.*read.*failed',
    'journal read failed',
    'Check journald storage, permissions and disk space',
    "journal",
)
register_rule(
    'JOURNAL_06',
    'journal',
    'warning',
    'journal.*No space left',
    'journal No space left',
    'Check journald storage, permissions and disk space',
    "journal",
)
register_rule(
    'JOURNAL_07',
    'journal',
    'warning',
    'journal.*I/O error',
    'journal I/O error',
    'Check journald storage, permissions and disk space',
    "journal",
)
register_rule(
    'JOURNAL_08',
    'journal',
    'warning',
    'journal.*Invalid argument',
    'journal Invalid argument',
    'Check journald storage, permissions and disk space',
    "journal",
)
register_rule(
    'JOURNAL_09',
    'journal',
    'warning',
    'journal.*failed to open',
    'journal failed to open',
    'Check journald storage, permissions and disk space',
    "journal",
)
register_rule(
    'JOURNAL_10',
    'journal',
    'warning',
    'journal.*failed to create',
    'journal failed to create',
    'Check journald storage, permissions and disk space',
    "journal",
)
register_rule(
    'JOURNAL_11',
    'journal',
    'warning',
    'journal.*failed to flush',
    'journal failed to flush',
    'Check journald storage, permissions and disk space',
    "journal",
)
register_rule(
    'JOURNAL_12',
    'journal',
    'warning',
    'journal.*failed to sync',
    'journal failed to sync',
    'Check journald storage, permissions and disk space',
    "journal",
)
register_rule(
    'JOURNAL_13',
    'journal',
    'warning',
    'journal.*failed to seal',
    'journal failed to seal',
    'Check journald storage, permissions and disk space',
    "journal",
)
register_rule(
    'JOURNAL_14',
    'journal',
    'warning',
    'journal.*failed to verify',
    'journal failed to verify',
    'Check journald storage, permissions and disk space',
    "journal",
)
register_rule(
    'JOURNAL_15',
    'journal',
    'warning',
    'journal.*file.*unlinked',
    'journal file unlinked',
    'Check journald storage, permissions and disk space',
    "journal",
)
register_rule(
    'JOURNAL_16',
    'journal',
    'warning',
    'journal.*missed',
    'journal missed',
    'Check journald storage, permissions and disk space',
    "journal",
)
register_rule(
    'JOURNAL_17',
    'journal',
    'warning',
    'journal.*dropped',
    'journal dropped',
    'Check journald storage, permissions and disk space',
    "journal",
)
register_rule(
    'JOURNAL_18',
    'journal',
    'warning',
    'journal.*suppressed',
    'journal suppressed',
    'Check journald storage, permissions and disk space',
    "journal",
)
register_rule(
    'JOURNAL_19',
    'journal',
    'warning',
    'journal.*rate limit',
    'journal rate limit',
    'Check journald storage, permissions and disk space',
    "journal",
)
register_rule(
    'JOURNAL_20',
    'journal',
    'warning',
    'journal.*not persistent',
    'journal not persistent',
    'Check journald storage, permissions and disk space',
    "journal",
)
register_rule(
    'CPU_01',
    'cpu',
    'warning',
    'CPU.*thermal throttling',
    'CPU thermal throttling',
    'Inspect CPU thermal, microcode and kernel messages',
    "journal",
)
register_rule(
    'CPU_02',
    'cpu',
    'warning',
    'CPU.*overheating',
    'CPU overheating',
    'Inspect CPU thermal, microcode and kernel messages',
    "journal",
)
register_rule(
    'CPU_03',
    'cpu',
    'warning',
    'CPU.*stuck',
    'CPU stuck',
    'Inspect CPU thermal, microcode and kernel messages',
    "journal",
)
register_rule(
    'CPU_04',
    'cpu',
    'warning',
    'CPU.*offline',
    'CPU offline',
    'Inspect CPU thermal, microcode and kernel messages',
    "journal",
)
register_rule(
    'CPU_05',
    'cpu',
    'warning',
    'CPU.*failed to start',
    'CPU failed to start',
    'Inspect CPU thermal, microcode and kernel messages',
    "journal",
)
register_rule(
    'CPU_06',
    'cpu',
    'warning',
    'CPU.*microcode error',
    'CPU microcode error',
    'Inspect CPU thermal, microcode and kernel messages',
    "journal",
)
register_rule(
    'CPU_07',
    'cpu',
    'warning',
    'CPU.*frequency.*failed',
    'CPU frequency failed',
    'Inspect CPU thermal, microcode and kernel messages',
    "journal",
)
register_rule(
    'CPU_08',
    'cpu',
    'warning',
    'CPU.*clock.*unstable',
    'CPU clock unstable',
    'Inspect CPU thermal, microcode and kernel messages',
    "journal",
)
register_rule(
    'CPU_09',
    'cpu',
    'warning',
    'TSC.*unstable',
    'TSC unstable',
    'Inspect CPU thermal, microcode and kernel messages',
    "journal",
)
register_rule(
    'CPU_10',
    'cpu',
    'warning',
    'clocksource.*unstable',
    'clocksource unstable',
    'Inspect CPU thermal, microcode and kernel messages',
    "journal",
)
register_rule(
    'CPU_11',
    'cpu',
    'warning',
    'NMI watchdog.*lockup',
    'NMI watchdog lockup',
    'Inspect CPU thermal, microcode and kernel messages',
    "journal",
)
register_rule(
    'CPU_12',
    'cpu',
    'warning',
    'RCU.*stall',
    'RCU stall',
    'Inspect CPU thermal, microcode and kernel messages',
    "journal",
)
register_rule(
    'CPU_13',
    'cpu',
    'warning',
    'smpboot.*failed',
    'smpboot failed',
    'Inspect CPU thermal, microcode and kernel messages',
    "journal",
)
register_rule(
    'CPU_14',
    'cpu',
    'warning',
    'CPU.*machine check',
    'CPU machine check',
    'Inspect CPU thermal, microcode and kernel messages',
    "journal",
)
register_rule(
    'CPU_15',
    'cpu',
    'warning',
    'MCE.*CPU',
    'MCE CPU',
    'Inspect CPU thermal, microcode and kernel messages',
    "journal",
)
register_rule(
    'CPU_16',
    'cpu',
    'warning',
    'thermal.*critical',
    'thermal critical',
    'Inspect CPU thermal, microcode and kernel messages',
    "journal",
)
register_rule(
    'CPU_17',
    'cpu',
    'warning',
    'thermal.*shutdown',
    'thermal shutdown',
    'Inspect CPU thermal, microcode and kernel messages',
    "journal",
)
register_rule(
    'CPU_18',
    'cpu',
    'warning',
    'intel_pstate.*failed',
    'intel_pstate failed',
    'Inspect CPU thermal, microcode and kernel messages',
    "journal",
)
register_rule(
    'CPU_19',
    'cpu',
    'warning',
    'amd_pstate.*failed',
    'amd_pstate failed',
    'Inspect CPU thermal, microcode and kernel messages',
    "journal",
)
register_rule(
    'CPU_20',
    'cpu',
    'warning',
    'cpufreq.*failed',
    'cpufreq failed',
    'Inspect CPU thermal, microcode and kernel messages',
    "journal",
)
register_rule(
    'DEVICES_01',
    'devices',
    'warning',
    'USB.*device descriptor read.*error',
    'USB device descriptor read error',
    'Inspect device driver logs and hardware or VM configuration',
    "journal",
)
register_rule(
    'DEVICES_02',
    'devices',
    'warning',
    'USB.*unable to enumerate',
    'USB unable to enumerate',
    'Inspect device driver logs and hardware or VM configuration',
    "journal",
)
register_rule(
    'DEVICES_03',
    'devices',
    'warning',
    'USB.*reset.*failed',
    'USB reset failed',
    'Inspect device driver logs and hardware or VM configuration',
    "journal",
)
register_rule(
    'DEVICES_04',
    'devices',
    'warning',
    'usb.*device not accepting address',
    'usb device not accepting address',
    'Inspect device driver logs and hardware or VM configuration',
    "journal",
)
register_rule(
    'DEVICES_05',
    'devices',
    'warning',
    'PCIe Bus Error',
    'PCIe Bus Error',
    'Inspect device driver logs and hardware or VM configuration',
    "journal",
)
register_rule(
    'DEVICES_06',
    'devices',
    'warning',
    'AER:.*error',
    'AER: error',
    'Inspect device driver logs and hardware or VM configuration',
    "journal",
)
register_rule(
    'DEVICES_07',
    'devices',
    'warning',
    'PCI.*BAR.*failed',
    'PCI BAR failed',
    'Inspect device driver logs and hardware or VM configuration',
    "journal",
)
register_rule(
    'DEVICES_08',
    'devices',
    'warning',
    'PCI.*resource.*failed',
    'PCI resource failed',
    'Inspect device driver logs and hardware or VM configuration',
    "journal",
)
register_rule(
    'DEVICES_09',
    'devices',
    'warning',
    'device.*probe failed',
    'device probe failed',
    'Inspect device driver logs and hardware or VM configuration',
    "journal",
)
register_rule(
    'DEVICES_10',
    'devices',
    'warning',
    'driver.*probe failed',
    'driver probe failed',
    'Inspect device driver logs and hardware or VM configuration',
    "journal",
)
register_rule(
    'DEVICES_11',
    'devices',
    'warning',
    'Bluetooth.*failed',
    'Bluetooth failed',
    'Inspect device driver logs and hardware or VM configuration',
    "journal",
)
register_rule(
    'DEVICES_12',
    'devices',
    'warning',
    'iwlwifi.*failed',
    'iwlwifi failed',
    'Inspect device driver logs and hardware or VM configuration',
    "journal",
)
register_rule(
    'DEVICES_13',
    'devices',
    'warning',
    'amdgpu.*failed',
    'amdgpu failed',
    'Inspect device driver logs and hardware or VM configuration',
    "journal",
)
register_rule(
    'DEVICES_14',
    'devices',
    'warning',
    'nouveau.*failed',
    'nouveau failed',
    'Inspect device driver logs and hardware or VM configuration',
    "journal",
)
register_rule(
    'DEVICES_15',
    'devices',
    'warning',
    'i915.*failed',
    'i915 failed',
    'Inspect device driver logs and hardware or VM configuration',
    "journal",
)
register_rule(
    'DEVICES_16',
    'devices',
    'warning',
    'drm.*error',
    'drm error',
    'Inspect device driver logs and hardware or VM configuration',
    "journal",
)
register_rule(
    'DEVICES_17',
    'devices',
    'warning',
    'input.*failed',
    'input failed',
    'Inspect device driver logs and hardware or VM configuration',
    "journal",
)
register_rule(
    'DEVICES_18',
    'devices',
    'warning',
    'hid.*error',
    'hid error',
    'Inspect device driver logs and hardware or VM configuration',
    "journal",
)
register_rule(
    'DEVICES_19',
    'devices',
    'warning',
    'sound.*failed',
    'sound failed',
    'Inspect device driver logs and hardware or VM configuration',
    "journal",
)
register_rule(
    'DEVICES_20',
    'devices',
    'warning',
    'ALSA.*error',
    'ALSA error',
    'Inspect device driver logs and hardware or VM configuration',
    "journal",
)
register_rule(
    'CLOCK_01',
    'clock',
    'warning',
    'Time has been changed',
    'Time has been changed',
    'Inspect chronyd and timedatectl synchronization status',
    "journal",
)
register_rule(
    'CLOCK_02',
    'clock',
    'warning',
    'System clock.*wrong',
    'System clock wrong',
    'Inspect chronyd and timedatectl synchronization status',
    "journal",
)
register_rule(
    'CLOCK_03',
    'clock',
    'warning',
    'Clock skew detected',
    'Clock skew detected',
    'Inspect chronyd and timedatectl synchronization status',
    "journal",
)
register_rule(
    'CLOCK_04',
    'clock',
    'warning',
    'NTP.*unsynchronized',
    'NTP unsynchronized',
    'Inspect chronyd and timedatectl synchronization status',
    "journal",
)
register_rule(
    'CLOCK_05',
    'clock',
    'warning',
    'NTP.*failed',
    'NTP failed',
    'Inspect chronyd and timedatectl synchronization status',
    "journal",
)
register_rule(
    'CLOCK_06',
    'clock',
    'warning',
    'chronyd.*failed',
    'chronyd failed',
    'Inspect chronyd and timedatectl synchronization status',
    "journal",
)
register_rule(
    'CLOCK_07',
    'clock',
    'warning',
    'timedate.*failed',
    'timedate failed',
    'Inspect chronyd and timedatectl synchronization status',
    "journal",
)
register_rule(
    'CLOCK_08',
    'clock',
    'warning',
    'RTC.*invalid',
    'RTC invalid',
    'Inspect chronyd and timedatectl synchronization status',
    "journal",
)
register_rule(
    'CLOCK_09',
    'clock',
    'warning',
    'RTC.*lost',
    'RTC lost',
    'Inspect chronyd and timedatectl synchronization status',
    "journal",
)
register_rule(
    'CLOCK_10',
    'clock',
    'warning',
    'time jump detected',
    'time jump detected',
    'Inspect chronyd and timedatectl synchronization status',
    "journal",
)
register_rule(
    'CLOCK_11',
    'clock',
    'warning',
    'clock.*stepped',
    'clock stepped',
    'Inspect chronyd and timedatectl synchronization status',
    "journal",
)
register_rule(
    'CLOCK_12',
    'clock',
    'warning',
    'clock.*synchronized.*no',
    'clock synchronized no',
    'Inspect chronyd and timedatectl synchronization status',
    "journal",
)
register_rule(
    'CLOCK_13',
    'clock',
    'warning',
    'clocksource.*unstable',
    'clocksource unstable',
    'Inspect chronyd and timedatectl synchronization status',
    "journal",
)
register_rule(
    'CLOCK_14',
    'clock',
    'warning',
    'TSC.*unstable',
    'TSC unstable',
    'Inspect chronyd and timedatectl synchronization status',
    "journal",
)
register_rule(
    'CLOCK_15',
    'clock',
    'warning',
    'timekeeping.*error',
    'timekeeping error',
    'Inspect chronyd and timedatectl synchronization status',
    "journal",
)
register_rule(
    'CLOCK_16',
    'clock',
    'warning',
    'time.*went backwards',
    'time went backwards',
    'Inspect chronyd and timedatectl synchronization status',
    "journal",
)
register_rule(
    'CLOCK_17',
    'clock',
    'warning',
    'time.*out of sync',
    'time out of sync',
    'Inspect chronyd and timedatectl synchronization status',
    "journal",
)
register_rule(
    'CLOCK_18',
    'clock',
    'warning',
    'adjtime.*failed',
    'adjtime failed',
    'Inspect chronyd and timedatectl synchronization status',
    "journal",
)
register_rule(
    'CLOCK_19',
    'clock',
    'warning',
    'PTP.*failed',
    'PTP failed',
    'Inspect chronyd and timedatectl synchronization status',
    "journal",
)
register_rule(
    'CLOCK_20',
    'clock',
    'warning',
    'phc2sys.*failed',
    'phc2sys failed',
    'Inspect chronyd and timedatectl synchronization status',
    "journal",
)
register_rule(
    'POWER_01',
    'power',
    'warning',
    'power supply.*failed',
    'power supply failed',
    'Inspect power management and thermal sensor reports',
    "journal",
)
register_rule(
    'POWER_02',
    'power',
    'warning',
    'power.*critical',
    'power critical',
    'Inspect power management and thermal sensor reports',
    "journal",
)
register_rule(
    'POWER_03',
    'power',
    'warning',
    'battery.*critical',
    'battery critical',
    'Inspect power management and thermal sensor reports',
    "journal",
)
register_rule(
    'POWER_04',
    'power',
    'warning',
    'battery.*failed',
    'battery failed',
    'Inspect power management and thermal sensor reports',
    "journal",
)
register_rule(
    'POWER_05',
    'power',
    'warning',
    'ACPI.*power.*error',
    'ACPI power error',
    'Inspect power management and thermal sensor reports',
    "journal",
)
register_rule(
    'POWER_06',
    'power',
    'warning',
    'thermal.*shutdown',
    'thermal shutdown',
    'Inspect power management and thermal sensor reports',
    "journal",
)
register_rule(
    'POWER_07',
    'power',
    'warning',
    'over-temperature',
    'over-temperature',
    'Inspect power management and thermal sensor reports',
    "journal",
)
register_rule(
    'POWER_08',
    'power',
    'warning',
    'overcurrent',
    'overcurrent',
    'Inspect power management and thermal sensor reports',
    "journal",
)
register_rule(
    'POWER_09',
    'power',
    'warning',
    'undervoltage',
    'undervoltage',
    'Inspect power management and thermal sensor reports',
    "journal",
)
register_rule(
    'POWER_10',
    'power',
    'warning',
    'voltage.*out of range',
    'voltage out of range',
    'Inspect power management and thermal sensor reports',
    "journal",
)
register_rule(
    'POWER_11',
    'power',
    'warning',
    'fan.*failed',
    'fan failed',
    'Inspect power management and thermal sensor reports',
    "journal",
)
register_rule(
    'POWER_12',
    'power',
    'warning',
    'fan.*stalled',
    'fan stalled',
    'Inspect power management and thermal sensor reports',
    "journal",
)
register_rule(
    'POWER_13',
    'power',
    'warning',
    'hwmon.*error',
    'hwmon error',
    'Inspect power management and thermal sensor reports',
    "journal",
)
register_rule(
    'POWER_14',
    'power',
    'warning',
    'watchdog.*timeout',
    'watchdog timeout',
    'Inspect power management and thermal sensor reports',
    "journal",
)
register_rule(
    'POWER_15',
    'power',
    'warning',
    'watchdog.*did not stop',
    'watchdog did not stop',
    'Inspect power management and thermal sensor reports',
    "journal",
)
register_rule(
    'POWER_16',
    'power',
    'warning',
    'system.*unexpected shutdown',
    'system unexpected shutdown',
    'Inspect power management and thermal sensor reports',
    "journal",
)
register_rule(
    'POWER_17',
    'power',
    'warning',
    'reboot.*unexpected',
    'reboot unexpected',
    'Inspect power management and thermal sensor reports',
    "journal",
)
register_rule(
    'POWER_18',
    'power',
    'warning',
    'shutdown.*failed',
    'shutdown failed',
    'Inspect power management and thermal sensor reports',
    "journal",
)
register_rule(
    'POWER_19',
    'power',
    'warning',
    'suspend.*failed',
    'suspend failed',
    'Inspect power management and thermal sensor reports',
    "journal",
)
register_rule(
    'POWER_20',
    'power',
    'warning',
    'resume.*failed',
    'resume failed',
    'Inspect power management and thermal sensor reports',
    "journal",
)
register_rule(
    'VIRTUALIZATION_01',
    'virtualization',
    'warning',
    'virtio.*failed',
    'virtio failed',
    'Inspect guest drivers and hypervisor configuration',
    "journal",
)
register_rule(
    'VIRTUALIZATION_02',
    'virtualization',
    'warning',
    'virtio.*error',
    'virtio error',
    'Inspect guest drivers and hypervisor configuration',
    "journal",
)
register_rule(
    'VIRTUALIZATION_03',
    'virtualization',
    'warning',
    'virtio_blk.*timeout',
    'virtio_blk timeout',
    'Inspect guest drivers and hypervisor configuration',
    "journal",
)
register_rule(
    'VIRTUALIZATION_04',
    'virtualization',
    'warning',
    'virtio_net.*reset',
    'virtio_net reset',
    'Inspect guest drivers and hypervisor configuration',
    "journal",
)
register_rule(
    'VIRTUALIZATION_05',
    'virtualization',
    'warning',
    'virtio_scsi.*error',
    'virtio_scsi error',
    'Inspect guest drivers and hypervisor configuration',
    "journal",
)
register_rule(
    'VIRTUALIZATION_06',
    'virtualization',
    'warning',
    'qemu.*error',
    'qemu error',
    'Inspect guest drivers and hypervisor configuration',
    "journal",
)
register_rule(
    'VIRTUALIZATION_07',
    'virtualization',
    'warning',
    'kvm.*error',
    'kvm error',
    'Inspect guest drivers and hypervisor configuration',
    "journal",
)
register_rule(
    'VIRTUALIZATION_08',
    'virtualization',
    'warning',
    'hypervisor.*error',
    'hypervisor error',
    'Inspect guest drivers and hypervisor configuration',
    "journal",
)
register_rule(
    'VIRTUALIZATION_09',
    'virtualization',
    'warning',
    'vhost.*failed',
    'vhost failed',
    'Inspect guest drivers and hypervisor configuration',
    "journal",
)
register_rule(
    'VIRTUALIZATION_10',
    'virtualization',
    'warning',
    'vsock.*failed',
    'vsock failed',
    'Inspect guest drivers and hypervisor configuration',
    "journal",
)
register_rule(
    'VIRTUALIZATION_11',
    'virtualization',
    'warning',
    'balloon.*failed',
    'balloon failed',
    'Inspect guest drivers and hypervisor configuration',
    "journal",
)
register_rule(
    'VIRTUALIZATION_12',
    'virtualization',
    'warning',
    'guest agent.*failed',
    'guest agent failed',
    'Inspect guest drivers and hypervisor configuration',
    "journal",
)
register_rule(
    'VIRTUALIZATION_13',
    'virtualization',
    'warning',
    'qemu-ga.*failed',
    'qemu-ga failed',
    'Inspect guest drivers and hypervisor configuration',
    "journal",
)
register_rule(
    'VIRTUALIZATION_14',
    'virtualization',
    'warning',
    'libvirt.*failed',
    'libvirt failed',
    'Inspect guest drivers and hypervisor configuration',
    "journal",
)
register_rule(
    'VIRTUALIZATION_15',
    'virtualization',
    'warning',
    'virtqemud.*failed',
    'virtqemud failed',
    'Inspect guest drivers and hypervisor configuration',
    "journal",
)
register_rule(
    'VIRTUALIZATION_16',
    'virtualization',
    'warning',
    'virtlogd.*failed',
    'virtlogd failed',
    'Inspect guest drivers and hypervisor configuration',
    "journal",
)
register_rule(
    'VIRTUALIZATION_17',
    'virtualization',
    'warning',
    'virtnetworkd.*failed',
    'virtnetworkd failed',
    'Inspect guest drivers and hypervisor configuration',
    "journal",
)
register_rule(
    'VIRTUALIZATION_18',
    'virtualization',
    'warning',
    'virtstoraged.*failed',
    'virtstoraged failed',
    'Inspect guest drivers and hypervisor configuration',
    "journal",
)
register_rule(
    'VIRTUALIZATION_19',
    'virtualization',
    'warning',
    'virtlockd.*failed',
    'virtlockd failed',
    'Inspect guest drivers and hypervisor configuration',
    "journal",
)
register_rule(
    'VIRTUALIZATION_20',
    'virtualization',
    'warning',
    'virtproxyd.*failed',
    'virtproxyd failed',
    'Inspect guest drivers and hypervisor configuration',
    "journal",
)
register_rule(
    'AUTHENTICATION_01',
    'authentication',
    'warning',
    'pam.*authentication failure',
    'pam authentication failure',
    'Review authentication logs and identity service status',
    "journal",
)
register_rule(
    'AUTHENTICATION_02',
    'authentication',
    'warning',
    'pam.*account expired',
    'pam account expired',
    'Review authentication logs and identity service status',
    "journal",
)
register_rule(
    'AUTHENTICATION_03',
    'authentication',
    'warning',
    'pam.*session.*failed',
    'pam session failed',
    'Review authentication logs and identity service status',
    "journal",
)
register_rule(
    'AUTHENTICATION_04',
    'authentication',
    'warning',
    'login.*failed',
    'login failed',
    'Review authentication logs and identity service status',
    "journal",
)
register_rule(
    'AUTHENTICATION_05',
    'authentication',
    'warning',
    'sshd.*Failed password',
    'sshd Failed password',
    'Review authentication logs and identity service status',
    "journal",
)
register_rule(
    'AUTHENTICATION_06',
    'authentication',
    'warning',
    'sshd.*Invalid user',
    'sshd Invalid user',
    'Review authentication logs and identity service status',
    "journal",
)
register_rule(
    'AUTHENTICATION_07',
    'authentication',
    'warning',
    'sshd.*error',
    'sshd error',
    'Review authentication logs and identity service status',
    "journal",
)
register_rule(
    'AUTHENTICATION_08',
    'authentication',
    'warning',
    'sshd.*fatal',
    'sshd fatal',
    'Review authentication logs and identity service status',
    "journal",
)
register_rule(
    'AUTHENTICATION_09',
    'authentication',
    'warning',
    'sudo.*authentication failure',
    'sudo authentication failure',
    'Review authentication logs and identity service status',
    "journal",
)
register_rule(
    'AUTHENTICATION_10',
    'authentication',
    'warning',
    'su.*authentication failure',
    'su authentication failure',
    'Review authentication logs and identity service status',
    "journal",
)
register_rule(
    'AUTHENTICATION_11',
    'authentication',
    'warning',
    'polkit.*not authorized',
    'polkit not authorized',
    'Review authentication logs and identity service status',
    "journal",
)
register_rule(
    'AUTHENTICATION_12',
    'authentication',
    'warning',
    'polkit.*failed',
    'polkit failed',
    'Review authentication logs and identity service status',
    "journal",
)
register_rule(
    'AUTHENTICATION_13',
    'authentication',
    'warning',
    'krb5.*failed',
    'krb5 failed',
    'Review authentication logs and identity service status',
    "journal",
)
register_rule(
    'AUTHENTICATION_14',
    'authentication',
    'warning',
    'kerberos.*failed',
    'kerberos failed',
    'Review authentication logs and identity service status',
    "journal",
)
register_rule(
    'AUTHENTICATION_15',
    'authentication',
    'warning',
    'ldap.*failed',
    'ldap failed',
    'Review authentication logs and identity service status',
    "journal",
)
register_rule(
    'AUTHENTICATION_16',
    'authentication',
    'warning',
    'sssd.*failed',
    'sssd failed',
    'Review authentication logs and identity service status',
    "journal",
)
register_rule(
    'AUTHENTICATION_17',
    'authentication',
    'warning',
    'nss.*failed',
    'nss failed',
    'Review authentication logs and identity service status',
    "journal",
)
register_rule(
    'AUTHENTICATION_18',
    'authentication',
    'warning',
    'userdb.*failed',
    'userdb failed',
    'Review authentication logs and identity service status',
    "journal",
)
register_rule(
    'AUTHENTICATION_19',
    'authentication',
    'warning',
    'systemd-homed.*failed',
    'systemd-homed failed',
    'Review authentication logs and identity service status',
    "journal",
)
register_rule(
    'AUTHENTICATION_20',
    'authentication',
    'warning',
    'keyring.*failed',
    'keyring failed',
    'Review authentication logs and identity service status',
    "journal",
)
register_rule(
    'UPDATES_01',
    'updates',
    'warning',
    'dnf.*failed',
    'dnf failed',
    'Inspect RPM and DNF transaction logs',
    "journal",
)
register_rule(
    'UPDATES_02',
    'updates',
    'warning',
    'dnf5.*failed',
    'dnf5 failed',
    'Inspect RPM and DNF transaction logs',
    "journal",
)
register_rule(
    'UPDATES_03',
    'updates',
    'warning',
    'rpm.*failed',
    'rpm failed',
    'Inspect RPM and DNF transaction logs',
    "journal",
)
register_rule(
    'UPDATES_04',
    'updates',
    'warning',
    'rpmdb.*corrupt',
    'rpmdb corrupt',
    'Inspect RPM and DNF transaction logs',
    "journal",
)
register_rule(
    'UPDATES_05',
    'updates',
    'warning',
    'rpmdb.*error',
    'rpmdb error',
    'Inspect RPM and DNF transaction logs',
    "journal",
)
register_rule(
    'UPDATES_06',
    'updates',
    'warning',
    'package.*scriptlet failed',
    'package scriptlet failed',
    'Inspect RPM and DNF transaction logs',
    "journal",
)
register_rule(
    'UPDATES_07',
    'updates',
    'warning',
    'transaction.*failed',
    'transaction failed',
    'Inspect RPM and DNF transaction logs',
    "journal",
)
register_rule(
    'UPDATES_08',
    'updates',
    'warning',
    'repository.*unavailable',
    'repository unavailable',
    'Inspect RPM and DNF transaction logs',
    "journal",
)
register_rule(
    'UPDATES_09',
    'updates',
    'warning',
    'repomd.*failed',
    'repomd failed',
    'Inspect RPM and DNF transaction logs',
    "journal",
)
register_rule(
    'UPDATES_10',
    'updates',
    'warning',
    'metadata.*failed',
    'metadata failed',
    'Inspect RPM and DNF transaction logs',
    "journal",
)
register_rule(
    'UPDATES_11',
    'updates',
    'warning',
    'GPG check FAILED',
    'GPG check FAILED',
    'Inspect RPM and DNF transaction logs',
    "journal",
)
register_rule(
    'UPDATES_12',
    'updates',
    'warning',
    'signature.*verification failed',
    'signature verification failed',
    'Inspect RPM and DNF transaction logs',
    "journal",
)
register_rule(
    'UPDATES_13',
    'updates',
    'warning',
    'package.*conflict',
    'package conflict',
    'Inspect RPM and DNF transaction logs',
    "journal",
)
register_rule(
    'UPDATES_14',
    'updates',
    'warning',
    'dependency.*problem',
    'dependency problem',
    'Inspect RPM and DNF transaction logs',
    "journal",
)
register_rule(
    'UPDATES_15',
    'updates',
    'warning',
    'modular filtering.*failed',
    'modular filtering failed',
    'Inspect RPM and DNF transaction logs',
    "journal",
)
register_rule(
    'UPDATES_16',
    'updates',
    'warning',
    'subscription.*failed',
    'subscription failed',
    'Inspect RPM and DNF transaction logs',
    "journal",
)
register_rule(
    'UPDATES_17',
    'updates',
    'warning',
    'mirror.*failed',
    'mirror failed',
    'Inspect RPM and DNF transaction logs',
    "journal",
)
register_rule(
    'UPDATES_18',
    'updates',
    'warning',
    'download.*failed',
    'download failed',
    'Inspect RPM and DNF transaction logs',
    "journal",
)
register_rule(
    'UPDATES_19',
    'updates',
    'warning',
    'checksum.*mismatch',
    'checksum mismatch',
    'Inspect RPM and DNF transaction logs',
    "journal",
)
register_rule(
    'UPDATES_20',
    'updates',
    'warning',
    'update.*rollback',
    'update rollback',
    'Inspect RPM and DNF transaction logs',
    "journal",
)
register_rule(
    'PROCESS_01',
    'process',
    'error',
    'segfault at',
    'segfault at',
    'Inspect process core dumps and memory faults',
    "journal",
)
register_rule(
    'PROCESS_02',
    'process',
    'error',
    'segmentation fault',
    'segmentation fault',
    'Inspect process core dumps and memory faults',
    "journal",
)
register_rule(
    'PROCESS_03',
    'process',
    'error',
    'core dumped',
    'core dumped',
    'Inspect process core dumps and memory faults',
    "journal",
)
register_rule(
    'PROCESS_04',
    'process',
    'error',
    'dumped core',
    'dumped core',
    'Inspect process core dumps and memory faults',
    "journal",
)
register_rule(
    'PROCESS_05',
    'process',
    'error',
    'assertion.*failed',
    'assertion failed',
    'Inspect process core dumps and memory faults',
    "journal",
)
register_rule(
    'PROCESS_06',
    'process',
    'error',
    'aborted.*core',
    'aborted core',
    'Inspect process core dumps and memory faults',
    "journal",
)
register_rule(
    'PROCESS_07',
    'process',
    'error',
    'signal 11',
    'signal 11',
    'Inspect process core dumps and memory faults',
    "journal",
)
register_rule(
    'PROCESS_08',
    'process',
    'error',
    'signal 6',
    'signal 6',
    'Inspect process core dumps and memory faults',
    "journal",
)
register_rule(
    'PROCESS_09',
    'process',
    'error',
    'SIGSEGV',
    'SIGSEGV',
    'Inspect process core dumps and memory faults',
    "journal",
)
register_rule(
    'PROCESS_10',
    'process',
    'error',
    'SIGABRT',
    'SIGABRT',
    'Inspect process core dumps and memory faults',
    "journal",
)
register_rule(
    'PROCESS_11',
    'process',
    'error',
    'illegal instruction',
    'illegal instruction',
    'Inspect process core dumps and memory faults',
    "journal",
)
register_rule(
    'PROCESS_12',
    'process',
    'error',
    'bus error',
    'bus error',
    'Inspect process core dumps and memory faults',
    "journal",
)
register_rule(
    'PROCESS_13',
    'process',
    'error',
    'stack smashing detected',
    'stack smashing detected',
    'Inspect process core dumps and memory faults',
    "journal",
)
register_rule(
    'PROCESS_14',
    'process',
    'error',
    'double free',
    'double free',
    'Inspect process core dumps and memory faults',
    "journal",
)
register_rule(
    'PROCESS_15',
    'process',
    'error',
    'malloc.*corruption',
    'malloc corruption',
    'Inspect process core dumps and memory faults',
    "journal",
)
register_rule(
    'PROCESS_16',
    'process',
    'error',
    'glibc.*fatal',
    'glibc fatal',
    'Inspect process core dumps and memory faults',
    "journal",
)
register_rule(
    'PROCESS_17',
    'process',
    'error',
    'resource temporarily unavailable',
    'resource temporarily unavailable',
    'Inspect process core dumps and memory faults',
    "journal",
)
register_rule(
    'PROCESS_18',
    'process',
    'error',
    'too many open files',
    'too many open files',
    'Inspect process core dumps and memory faults',
    "journal",
)
register_rule(
    'PROCESS_19',
    'process',
    'error',
    'fork.*failed',
    'fork failed',
    'Inspect process core dumps and memory faults',
    "journal",
)
register_rule(
    'PROCESS_20',
    'process',
    'error',
    'exec.*failed',
    'exec failed',
    'Inspect process core dumps and memory faults',
    "journal",
)
register_rule(
    'PERMISSIONS_01',
    'permissions',
    'warning',
    'Read-only file system',
    'Read-only file system',
    'Inspect ownership, SELinux labels and effective permissions',
    "journal",
)
register_rule(
    'PERMISSIONS_02',
    'permissions',
    'warning',
    'Permission denied',
    'Permission denied',
    'Inspect ownership, SELinux labels and effective permissions',
    "journal",
)
register_rule(
    'PERMISSIONS_03',
    'permissions',
    'warning',
    'Operation not permitted',
    'Operation not permitted',
    'Inspect ownership, SELinux labels and effective permissions',
    "journal",
)
register_rule(
    'PERMISSIONS_04',
    'permissions',
    'warning',
    'Access denied',
    'Access denied',
    'Inspect ownership, SELinux labels and effective permissions',
    "journal",
)
register_rule(
    'PERMISSIONS_05',
    'permissions',
    'warning',
    'EACCES',
    'EACCES',
    'Inspect ownership, SELinux labels and effective permissions',
    "journal",
)
register_rule(
    'PERMISSIONS_06',
    'permissions',
    'warning',
    'EPERM',
    'EPERM',
    'Inspect ownership, SELinux labels and effective permissions',
    "journal",
)
register_rule(
    'PERMISSIONS_07',
    'permissions',
    'warning',
    'Failed to set permissions',
    'Failed to set permissions',
    'Inspect ownership, SELinux labels and effective permissions',
    "journal",
)
register_rule(
    'PERMISSIONS_08',
    'permissions',
    'warning',
    'Failed to change ownership',
    'Failed to change ownership',
    'Inspect ownership, SELinux labels and effective permissions',
    "journal",
)
register_rule(
    'PERMISSIONS_09',
    'permissions',
    'warning',
    'Failed to create directory',
    'Failed to create directory',
    'Inspect ownership, SELinux labels and effective permissions',
    "journal",
)
register_rule(
    'PERMISSIONS_10',
    'permissions',
    'warning',
    'Failed to open file',
    'Failed to open file',
    'Inspect ownership, SELinux labels and effective permissions',
    "journal",
)
register_rule(
    'PERMISSIONS_11',
    'permissions',
    'warning',
    'Failed to write file',
    'Failed to write file',
    'Inspect ownership, SELinux labels and effective permissions',
    "journal",
)
register_rule(
    'PERMISSIONS_12',
    'permissions',
    'warning',
    'Failed to read file',
    'Failed to read file',
    'Inspect ownership, SELinux labels and effective permissions',
    "journal",
)
register_rule(
    'PERMISSIONS_13',
    'permissions',
    'warning',
    'Failed to access',
    'Failed to access',
    'Inspect ownership, SELinux labels and effective permissions',
    "journal",
)
register_rule(
    'PERMISSIONS_14',
    'permissions',
    'warning',
    'Failed to stat',
    'Failed to stat',
    'Inspect ownership, SELinux labels and effective permissions',
    "journal",
)
register_rule(
    'PERMISSIONS_15',
    'permissions',
    'warning',
    'Failed to chown',
    'Failed to chown',
    'Inspect ownership, SELinux labels and effective permissions',
    "journal",
)
register_rule(
    'PERMISSIONS_16',
    'permissions',
    'warning',
    'Failed to chmod',
    'Failed to chmod',
    'Inspect ownership, SELinux labels and effective permissions',
    "journal",
)
register_rule(
    'PERMISSIONS_17',
    'permissions',
    'warning',
    'Failed to set xattr',
    'Failed to set xattr',
    'Inspect ownership, SELinux labels and effective permissions',
    "journal",
)
register_rule(
    'PERMISSIONS_18',
    'permissions',
    'warning',
    'Failed to set ACL',
    'Failed to set ACL',
    'Inspect ownership, SELinux labels and effective permissions',
    "journal",
)
register_rule(
    'PERMISSIONS_19',
    'permissions',
    'warning',
    'Failed to relabel',
    'Failed to relabel',
    'Inspect ownership, SELinux labels and effective permissions',
    "journal",
)
register_rule(
    'PERMISSIONS_20',
    'permissions',
    'warning',
    'Failed to restore context',
    'Failed to restore context',
    'Inspect ownership, SELinux labels and effective permissions',
    "journal",
)
register_rule(
    'KERNEL_MODULES_01',
    'kernel_modules',
    'warning',
    'module verification failed',
    'module verification failed',
    'Inspect module signatures, dependencies and kernel compatibility',
    "journal",
)
register_rule(
    'KERNEL_MODULES_02',
    'kernel_modules',
    'warning',
    'module.*signature.*failed',
    'module signature failed',
    'Inspect module signatures, dependencies and kernel compatibility',
    "journal",
)
register_rule(
    'KERNEL_MODULES_03',
    'kernel_modules',
    'warning',
    'module.*taint',
    'module taint',
    'Inspect module signatures, dependencies and kernel compatibility',
    "journal",
)
register_rule(
    'KERNEL_MODULES_04',
    'kernel_modules',
    'warning',
    'module.*unknown symbol',
    'module unknown symbol',
    'Inspect module signatures, dependencies and kernel compatibility',
    "journal",
)
register_rule(
    'KERNEL_MODULES_05',
    'kernel_modules',
    'warning',
    'module.*disagrees about version',
    'module disagrees about version',
    'Inspect module signatures, dependencies and kernel compatibility',
    "journal",
)
register_rule(
    'KERNEL_MODULES_06',
    'kernel_modules',
    'warning',
    'module.*invalid format',
    'module invalid format',
    'Inspect module signatures, dependencies and kernel compatibility',
    "journal",
)
register_rule(
    'KERNEL_MODULES_07',
    'kernel_modules',
    'warning',
    'module.*not found',
    'module not found',
    'Inspect module signatures, dependencies and kernel compatibility',
    "journal",
)
register_rule(
    'KERNEL_MODULES_08',
    'kernel_modules',
    'warning',
    'module.*failed to load',
    'module failed to load',
    'Inspect module signatures, dependencies and kernel compatibility',
    "journal",
)
register_rule(
    'KERNEL_MODULES_09',
    'kernel_modules',
    'warning',
    'module.*failed to initialize',
    'module failed to initialize',
    'Inspect module signatures, dependencies and kernel compatibility',
    "journal",
)
register_rule(
    'KERNEL_MODULES_10',
    'kernel_modules',
    'warning',
    'module.*probe failed',
    'module probe failed',
    'Inspect module signatures, dependencies and kernel compatibility',
    "journal",
)
register_rule(
    'KERNEL_MODULES_11',
    'kernel_modules',
    'warning',
    'module.*blacklisted',
    'module blacklisted',
    'Inspect module signatures, dependencies and kernel compatibility',
    "journal",
)
register_rule(
    'KERNEL_MODULES_12',
    'kernel_modules',
    'warning',
    'modprobe.*failed',
    'modprobe failed',
    'Inspect module signatures, dependencies and kernel compatibility',
    "journal",
)
register_rule(
    'KERNEL_MODULES_13',
    'kernel_modules',
    'warning',
    'insmod.*failed',
    'insmod failed',
    'Inspect module signatures, dependencies and kernel compatibility',
    "journal",
)
register_rule(
    'KERNEL_MODULES_14',
    'kernel_modules',
    'warning',
    'rmmod.*failed',
    'rmmod failed',
    'Inspect module signatures, dependencies and kernel compatibility',
    "journal",
)
register_rule(
    'KERNEL_MODULES_15',
    'kernel_modules',
    'warning',
    'depmod.*failed',
    'depmod failed',
    'Inspect module signatures, dependencies and kernel compatibility',
    "journal",
)
register_rule(
    'KERNEL_MODULES_16',
    'kernel_modules',
    'warning',
    'module.*dependency.*failed',
    'module dependency failed',
    'Inspect module signatures, dependencies and kernel compatibility',
    "journal",
)
register_rule(
    'KERNEL_MODULES_17',
    'kernel_modules',
    'warning',
    'module.*unsupported',
    'module unsupported',
    'Inspect module signatures, dependencies and kernel compatibility',
    "journal",
)
register_rule(
    'KERNEL_MODULES_18',
    'kernel_modules',
    'warning',
    'module.*refused',
    'module refused',
    'Inspect module signatures, dependencies and kernel compatibility',
    "journal",
)
register_rule(
    'KERNEL_MODULES_19',
    'kernel_modules',
    'warning',
    'module.*out of memory',
    'module out of memory',
    'Inspect module signatures, dependencies and kernel compatibility',
    "journal",
)
register_rule(
    'KERNEL_MODULES_20',
    'kernel_modules',
    'warning',
    'module.*missing firmware',
    'module missing firmware',
    'Inspect module signatures, dependencies and kernel compatibility',
    "journal",
)
register_rule(
    'DISK_ENCRYPTION_01',
    'disk_encryption',
    'error',
    'cryptsetup.*failed',
    'cryptsetup failed',
    'Inspect encrypted volume mappings and unlock configuration',
    "journal",
)
register_rule(
    'DISK_ENCRYPTION_02',
    'disk_encryption',
    'error',
    'LUKS.*failed',
    'LUKS failed',
    'Inspect encrypted volume mappings and unlock configuration',
    "journal",
)
register_rule(
    'DISK_ENCRYPTION_03',
    'disk_encryption',
    'error',
    'LUKS.*error',
    'LUKS error',
    'Inspect encrypted volume mappings and unlock configuration',
    "journal",
)
register_rule(
    'DISK_ENCRYPTION_04',
    'disk_encryption',
    'error',
    'dm-crypt.*error',
    'dm-crypt error',
    'Inspect encrypted volume mappings and unlock configuration',
    "journal",
)
register_rule(
    'DISK_ENCRYPTION_05',
    'disk_encryption',
    'error',
    'crypt.*key.*failed',
    'crypt key failed',
    'Inspect encrypted volume mappings and unlock configuration',
    "journal",
)
register_rule(
    'DISK_ENCRYPTION_06',
    'disk_encryption',
    'error',
    'unlock.*failed',
    'unlock failed',
    'Inspect encrypted volume mappings and unlock configuration',
    "journal",
)
register_rule(
    'DISK_ENCRYPTION_07',
    'disk_encryption',
    'error',
    'encrypted volume.*failed',
    'encrypted volume failed',
    'Inspect encrypted volume mappings and unlock configuration',
    "journal",
)
register_rule(
    'DISK_ENCRYPTION_08',
    'disk_encryption',
    'error',
    'TPM.*unseal.*failed',
    'TPM unseal failed',
    'Inspect encrypted volume mappings and unlock configuration',
    "journal",
)
register_rule(
    'DISK_ENCRYPTION_09',
    'disk_encryption',
    'error',
    'keyslot.*failed',
    'keyslot failed',
    'Inspect encrypted volume mappings and unlock configuration',
    "journal",
)
register_rule(
    'DISK_ENCRYPTION_10',
    'disk_encryption',
    'error',
    'crypttab.*failed',
    'crypttab failed',
    'Inspect encrypted volume mappings and unlock configuration',
    "journal",
)
register_rule(
    'DISK_ENCRYPTION_11',
    'disk_encryption',
    'error',
    'initramfs.*crypt.*failed',
    'initramfs crypt failed',
    'Inspect encrypted volume mappings and unlock configuration',
    "journal",
)
register_rule(
    'DISK_ENCRYPTION_12',
    'disk_encryption',
    'error',
    'dracut.*crypt.*failed',
    'dracut crypt failed',
    'Inspect encrypted volume mappings and unlock configuration',
    "journal",
)
register_rule(
    'DISK_ENCRYPTION_13',
    'disk_encryption',
    'error',
    'clevis.*failed',
    'clevis failed',
    'Inspect encrypted volume mappings and unlock configuration',
    "journal",
)
register_rule(
    'DISK_ENCRYPTION_14',
    'disk_encryption',
    'error',
    'tang.*failed',
    'tang failed',
    'Inspect encrypted volume mappings and unlock configuration',
    "journal",
)
register_rule(
    'DISK_ENCRYPTION_15',
    'disk_encryption',
    'error',
    'fido2.*failed',
    'fido2 failed',
    'Inspect encrypted volume mappings and unlock configuration',
    "journal",
)
register_rule(
    'DISK_ENCRYPTION_16',
    'disk_encryption',
    'error',
    'systemd-cryptsetup.*failed',
    'systemd-cryptsetup failed',
    'Inspect encrypted volume mappings and unlock configuration',
    "journal",
)
register_rule(
    'DISK_ENCRYPTION_17',
    'disk_encryption',
    'error',
    'crypt.*device.*timeout',
    'crypt device timeout',
    'Inspect encrypted volume mappings and unlock configuration',
    "journal",
)
register_rule(
    'DISK_ENCRYPTION_18',
    'disk_encryption',
    'error',
    'crypt.*header.*corrupt',
    'crypt header corrupt',
    'Inspect encrypted volume mappings and unlock configuration',
    "journal",
)
register_rule(
    'DISK_ENCRYPTION_19',
    'disk_encryption',
    'error',
    'crypt.*authentication.*failed',
    'crypt authentication failed',
    'Inspect encrypted volume mappings and unlock configuration',
    "journal",
)
register_rule(
    'DISK_ENCRYPTION_20',
    'disk_encryption',
    'error',
    'crypt.*integrity.*failed',
    'crypt integrity failed',
    'Inspect encrypted volume mappings and unlock configuration',
    "journal",
)
register_rule(
    'INITRAMFS_01',
    'initramfs',
    'error',
    'dracut.*failed',
    'dracut failed',
    'Inspect initramfs content, dracut configuration and root mapping',
    "journal",
)
register_rule(
    'INITRAMFS_02',
    'initramfs',
    'error',
    'dracut.*error',
    'dracut error',
    'Inspect initramfs content, dracut configuration and root mapping',
    "journal",
)
register_rule(
    'INITRAMFS_03',
    'initramfs',
    'error',
    'initramfs.*failed',
    'initramfs failed',
    'Inspect initramfs content, dracut configuration and root mapping',
    "journal",
)
register_rule(
    'INITRAMFS_04',
    'initramfs',
    'error',
    'initrd.*failed',
    'initrd failed',
    'Inspect initramfs content, dracut configuration and root mapping',
    "journal",
)
register_rule(
    'INITRAMFS_05',
    'initramfs',
    'error',
    'initrd-switch-root.*failed',
    'initrd-switch-root failed',
    'Inspect initramfs content, dracut configuration and root mapping',
    "journal",
)
register_rule(
    'INITRAMFS_06',
    'initramfs',
    'error',
    'switch_root.*failed',
    'switch_root failed',
    'Inspect initramfs content, dracut configuration and root mapping',
    "journal",
)
register_rule(
    'INITRAMFS_07',
    'initramfs',
    'error',
    'Failed to switch root',
    'Failed to switch root',
    'Inspect initramfs content, dracut configuration and root mapping',
    "journal",
)
register_rule(
    'INITRAMFS_08',
    'initramfs',
    'error',
    'root filesystem.*not found',
    'root filesystem not found',
    'Inspect initramfs content, dracut configuration and root mapping',
    "journal",
)
register_rule(
    'INITRAMFS_09',
    'initramfs',
    'error',
    'root device.*not found',
    'root device not found',
    'Inspect initramfs content, dracut configuration and root mapping',
    "journal",
)
register_rule(
    'INITRAMFS_10',
    'initramfs',
    'error',
    'Cannot find root',
    'Cannot find root',
    'Inspect initramfs content, dracut configuration and root mapping',
    "journal",
)
register_rule(
    'INITRAMFS_11',
    'initramfs',
    'error',
    'emergency shell',
    'emergency shell',
    'Inspect initramfs content, dracut configuration and root mapping',
    "journal",
)
register_rule(
    'INITRAMFS_12',
    'initramfs',
    'error',
    'dracut-initqueue timeout',
    'dracut-initqueue timeout',
    'Inspect initramfs content, dracut configuration and root mapping',
    "journal",
)
register_rule(
    'INITRAMFS_13',
    'initramfs',
    'error',
    'initqueue.*timeout',
    'initqueue timeout',
    'Inspect initramfs content, dracut configuration and root mapping',
    "journal",
)
register_rule(
    'INITRAMFS_14',
    'initramfs',
    'error',
    'initrd.*missing module',
    'initrd missing module',
    'Inspect initramfs content, dracut configuration and root mapping',
    "journal",
)
register_rule(
    'INITRAMFS_15',
    'initramfs',
    'error',
    'initramfs.*missing firmware',
    'initramfs missing firmware',
    'Inspect initramfs content, dracut configuration and root mapping',
    "journal",
)
register_rule(
    'INITRAMFS_16',
    'initramfs',
    'error',
    'initrd.*mount.*failed',
    'initrd mount failed',
    'Inspect initramfs content, dracut configuration and root mapping',
    "journal",
)
register_rule(
    'INITRAMFS_17',
    'initramfs',
    'error',
    'dracut.*Warning',
    'dracut Warning',
    'Inspect initramfs content, dracut configuration and root mapping',
    "journal",
)
register_rule(
    'INITRAMFS_18',
    'initramfs',
    'error',
    'dracut.*FATAL',
    'dracut FATAL',
    'Inspect initramfs content, dracut configuration and root mapping',
    "journal",
)
register_rule(
    'INITRAMFS_19',
    'initramfs',
    'error',
    'initrd.*dependency failed',
    'initrd dependency failed',
    'Inspect initramfs content, dracut configuration and root mapping',
    "journal",
)
register_rule(
    'INITRAMFS_20',
    'initramfs',
    'error',
    'initramfs.*corrupt',
    'initramfs corrupt',
    'Inspect initramfs content, dracut configuration and root mapping',
    "journal",
)
register_rule(
    'CGROUPS_01',
    'cgroups',
    'warning',
    'cgroup.*failed to create',
    'cgroup failed to create',
    'Inspect cgroup controller availability and systemd unit limits',
    "journal",
)
register_rule(
    'CGROUPS_02',
    'cgroups',
    'warning',
    'cgroup.*failed to attach',
    'cgroup failed to attach',
    'Inspect cgroup controller availability and systemd unit limits',
    "journal",
)
register_rule(
    'CGROUPS_03',
    'cgroups',
    'warning',
    'cgroup.*failed to migrate',
    'cgroup failed to migrate',
    'Inspect cgroup controller availability and systemd unit limits',
    "journal",
)
register_rule(
    'CGROUPS_04',
    'cgroups',
    'warning',
    'cgroup.*failed to write',
    'cgroup failed to write',
    'Inspect cgroup controller availability and systemd unit limits',
    "journal",
)
register_rule(
    'CGROUPS_05',
    'cgroups',
    'warning',
    'cgroup.*failed to read',
    'cgroup failed to read',
    'Inspect cgroup controller availability and systemd unit limits',
    "journal",
)
register_rule(
    'CGROUPS_06',
    'cgroups',
    'warning',
    'cgroup.*permission denied',
    'cgroup permission denied',
    'Inspect cgroup controller availability and systemd unit limits',
    "journal",
)
register_rule(
    'CGROUPS_07',
    'cgroups',
    'warning',
    'cgroup.*out of memory',
    'cgroup out of memory',
    'Inspect cgroup controller availability and systemd unit limits',
    "journal",
)
register_rule(
    'CGROUPS_08',
    'cgroups',
    'warning',
    'cgroup.*pids.max',
    'cgroup pids.max',
    'Inspect cgroup controller availability and systemd unit limits',
    "journal",
)
register_rule(
    'CGROUPS_09',
    'cgroups',
    'warning',
    'cgroup.*memory.max',
    'cgroup memory.max',
    'Inspect cgroup controller availability and systemd unit limits',
    "journal",
)
register_rule(
    'CGROUPS_10',
    'cgroups',
    'warning',
    'cgroup.*cpu.max',
    'cgroup cpu.max',
    'Inspect cgroup controller availability and systemd unit limits',
    "journal",
)
register_rule(
    'CGROUPS_11',
    'cgroups',
    'warning',
    'cgroup.*io.max',
    'cgroup io.max',
    'Inspect cgroup controller availability and systemd unit limits',
    "journal",
)
register_rule(
    'CGROUPS_12',
    'cgroups',
    'warning',
    'cgroup.*invalid argument',
    'cgroup invalid argument',
    'Inspect cgroup controller availability and systemd unit limits',
    "journal",
)
register_rule(
    'CGROUPS_13',
    'cgroups',
    'warning',
    'cgroup.*controller unavailable',
    'cgroup controller unavailable',
    'Inspect cgroup controller availability and systemd unit limits',
    "journal",
)
register_rule(
    'CGROUPS_14',
    'cgroups',
    'warning',
    'cgroup.*not supported',
    'cgroup not supported',
    'Inspect cgroup controller availability and systemd unit limits',
    "journal",
)
register_rule(
    'CGROUPS_15',
    'cgroups',
    'warning',
    'cgroup.*resource busy',
    'cgroup resource busy',
    'Inspect cgroup controller availability and systemd unit limits',
    "journal",
)
register_rule(
    'CGROUPS_16',
    'cgroups',
    'warning',
    'cgroup.*no space left',
    'cgroup no space left',
    'Inspect cgroup controller availability and systemd unit limits',
    "journal",
)
register_rule(
    'CGROUPS_17',
    'cgroups',
    'warning',
    'cgroup.*delegation failed',
    'cgroup delegation failed',
    'Inspect cgroup controller availability and systemd unit limits',
    "journal",
)
register_rule(
    'CGROUPS_18',
    'cgroups',
    'warning',
    'cgroup.*mount failed',
    'cgroup mount failed',
    'Inspect cgroup controller availability and systemd unit limits',
    "journal",
)
register_rule(
    'CGROUPS_19',
    'cgroups',
    'warning',
    'cgroup.*hierarchy error',
    'cgroup hierarchy error',
    'Inspect cgroup controller availability and systemd unit limits',
    "journal",
)
register_rule(
    'CGROUPS_20',
    'cgroups',
    'warning',
    'cgroup.*kill failed',
    'cgroup kill failed',
    'Inspect cgroup controller availability and systemd unit limits',
    "journal",
)

if __name__ == "__main__":
    raise SystemExit(main())
