"""
IEC 62443-3-3 Compliance Analyzer
Módulo: collector.py
Descripción: Recopila información del sistema operativo para análisis
              de cumplimiento contra los 7 Foundational Requirements (FR).

Sistemas objetivo: Ubuntu 22.04/23.xx/24.xx/25.xx, Kali Linux
Requiere: Python 3.10+, ejecución con sudo para algunos checks
"""

import os
import subprocess
import platform
import json
import pwd
import grp
import stat
import re
from datetime import datetime
from pathlib import Path
from typing import Optional
from datetime import timezone


# ─────────────────────────────────────────────
# Utilidades internas
# ─────────────────────────────────────────────

def _run(cmd: list[str], timeout: int = 10) -> tuple[str, str, int]:
    """Ejecuta un comando y devuelve (stdout, stderr, returncode)."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except subprocess.TimeoutExpired:
        return "", "TIMEOUT", -1
    except FileNotFoundError:
        return "", f"COMMAND_NOT_FOUND: {cmd[0]}", -1
    except PermissionError:
        return "", "PERMISSION_DENIED", -1


def _file_read(path: str) -> Optional[str]:
    """Lee un archivo de texto, devuelve None si no existe o no hay permisos."""
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except (FileNotFoundError, PermissionError):
        return None


def _is_root() -> bool:
    return os.geteuid() == 0


# ─────────────────────────────────────────────
# FR1 — Identificación y autenticación
# ─────────────────────────────────────────────

def collect_fr1_identification() -> dict:
    """
    FR1: Identification and Authentication Control
    SRs cubiertos:
      SR 1.1  Identificación de usuarios humanos
      SR 1.2  Identificación de software y procesos
      SR 1.3  Gestión de cuentas
      SR 1.7  Gestión de contraseñas
      SR 1.8  Autenticación de usuarios vía criptografía
    """
    data = {}

    # SR 1.1 / SR 1.3 — Usuarios del sistema
    users = []
    for pw in pwd.getpwall():
        users.append({
            "username": pw.pw_name,
            "uid": pw.pw_uid,
            "gid": pw.pw_gid,
            "home": pw.pw_dir,
            "shell": pw.pw_shell,
            "has_password": pw.pw_passwd not in ("", "x", "*", "!"),
            "is_system": pw.pw_uid < 1000,
            "login_shell": pw.pw_shell not in ("/usr/sbin/nologin", "/bin/false", "/sbin/nologin"),
        })
    data["users"] = users
    data["users_with_login"] = [u for u in users if u["login_shell"] and not u["is_system"]]

    # SR 1.3 — Grupos y privilegios
    groups = []
    for g in grp.getgrall():
        groups.append({
            "name": g.gr_name,
            "gid": g.gr_gid,
            "members": g.gr_mem,
        })
    data["sudo_group_members"] = next(
        (g["members"] for g in groups if g["name"] in ("sudo", "wheel")), []
    )
    data["groups"] = groups

    # SR 1.7 — Política de contraseñas (PAM / login.defs)
    login_defs = _file_read("/etc/login.defs") or ""
    password_policy = {}
    for key in ["PASS_MAX_DAYS", "PASS_MIN_DAYS", "PASS_MIN_LEN", "PASS_WARN_AGE"]:
        match = re.search(rf"^{key}\s+(\d+)", login_defs, re.MULTILINE)
        password_policy[key] = int(match.group(1)) if match else None
    data["password_policy"] = password_policy

    # PAM pwquality
    pwquality_conf = _file_read("/etc/security/pwquality.conf") or ""
    pam_settings = {}
    for setting in ["minlen", "dcredit", "ucredit", "lcredit", "ocredit", "minclass"]:
        match = re.search(rf"^{setting}\s*=\s*(-?\d+)", pwquality_conf, re.MULTILINE)
        pam_settings[setting] = int(match.group(1)) if match else None
    data["pam_pwquality"] = pam_settings

    # SR 1.8 — SSH: autenticación por clave y configuración
    sshd_config = _file_read("/etc/ssh/sshd_config") or ""
    ssh_settings = {}
    for param in [
        "PasswordAuthentication", "PubkeyAuthentication", "PermitRootLogin",
        "PermitEmptyPasswords", "MaxAuthTries", "Protocol",
        "AuthorizedKeysFile", "UsePAM", "ChallengeResponseAuthentication",
        "KbdInteractiveAuthentication"
    ]:
        match = re.search(rf"^\s*{param}\s+(\S+)", sshd_config, re.IGNORECASE | re.MULTILINE)
        ssh_settings[param] = match.group(1) if match else "not_set"
    data["ssh_config"] = ssh_settings

    # MFA — pam_google_authenticator o similar
    pam_sshd = _file_read("/etc/pam.d/sshd") or ""
    data["mfa_configured"] = "pam_google_authenticator" in pam_sshd or "pam_oath" in pam_sshd

    return data


# ─────────────────────────────────────────────
# FR2 — Control de uso
# ─────────────────────────────────────────────

def collect_fr2_use_control() -> dict:
    """
    FR2: Use Control
    SRs cubiertos:
      SR 2.1  Aplicación de autorización
      SR 2.2  Uso de autenticación inalámbrica
      SR 2.3  Uso de dispositivos portátiles
      SR 2.6  Sesiones remotas
      SR 2.7  Gestión de sesiones simultáneas
    """
    data = {}

    # SR 2.1 — sudo y sudoers
    sudoers_content = _file_read("/etc/sudoers") or ""
    sudoers_d = []
    sudoers_dir = Path("/etc/sudoers.d")
    if sudoers_dir.exists():
        for f in sudoers_dir.iterdir():
            content = _file_read(str(f))
            if content:
                sudoers_d.append({"file": f.name, "content": content})
    data["sudoers_nopasswd_entries"] = bool(re.search(r"NOPASSWD", sudoers_content))
    data["sudoers_d_files"] = len(sudoers_d)

    # AppArmor
    aa_status_out, _, aa_rc = _run(["apparmor_status"])
    if aa_rc != 0:
        aa_status_out, _, aa_rc = _run(["aa-status"])
    data["apparmor"] = {
        "available": aa_rc == 0,
        "profiles_enforce": len(re.findall(r"enforce", aa_status_out)),
        "profiles_complain": len(re.findall(r"complain", aa_status_out)),
        "raw_summary": aa_status_out[:300] if aa_status_out else None,
    }

    # SELinux (menos común en Ubuntu pero verificamos)
    sestatus_out, _, sestatus_rc = _run(["sestatus"])
    data["selinux"] = {
        "available": sestatus_rc == 0,
        "status": sestatus_out[:100] if sestatus_out else "not_installed",
    }

    # SR 2.6 — Sesiones remotas: tmout, HISTSIZE
    bash_profile = _file_read("/etc/profile") or ""
    tmout_match = re.search(r"TMOUT\s*=\s*(\d+)", bash_profile)
    data["session_timeout_seconds"] = int(tmout_match.group(1)) if tmout_match else None

    # Servicios de acceso remoto activos
    services_out, _, _ = _run(["systemctl", "list-units", "--type=service", "--state=running", "--no-pager", "--plain"])
    remote_services = []
    for svc in ["ssh", "sshd", "telnet", "rsh", "rlogin", "vnc", "rdp", "xrdp"]:
        if svc in services_out.lower():
            remote_services.append(svc)
    data["active_remote_services"] = remote_services

    # Puertos en escucha
    ss_out, _, _ = _run(["ss", "-tulnp"])
    listening_ports = []
    for line in ss_out.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 5:
            listening_ports.append({
                "proto": parts[0],
                "local_address": parts[4],
                "process": parts[-1] if len(parts) > 6 else "unknown",
            })
    data["listening_ports"] = listening_ports
    data["listening_ports_count"] = len(listening_ports)

    return data


# ─────────────────────────────────────────────
# FR3 — Integridad del sistema
# ─────────────────────────────────────────────

def collect_fr3_integrity() -> dict:
    """
    FR3: System Integrity
    SRs cubiertos:
      SR 3.1  Integridad de comunicaciones
      SR 3.2  Protección contra código malicioso
      SR 3.3  Checks de seguridad
      SR 3.4  Proceso de verificación del software
    """
    data = {}

    # SR 3.2 — Antivirus/IDS
    security_tools = {}
    for tool in ["clamav", "clamd", "rkhunter", "chkrootkit", "aide", "tripwire", "ossec", "wazuh"]:
        out, _, rc = _run(["which", tool])
        security_tools[tool] = {"installed": rc == 0, "path": out}
    data["security_tools"] = security_tools

    # SR 3.3 — AIDE / integridad de archivos
    aide_conf = _file_read("/etc/aide/aide.conf") or _file_read("/etc/aide.conf")
    data["aide_configured"] = aide_conf is not None

    # SR 3.4 — Secure boot y firma de paquetes
    sb_out, _, sb_rc = _run(["mokutil", "--sb-state"])
    data["secure_boot"] = {
        "available": sb_rc == 0,
        "state": sb_out if sb_rc == 0 else "unknown",
    }

    # Verificar firma GPG de paquetes apt
    apt_conf_d = Path("/etc/apt/apt.conf.d")
    no_verify = False
    if apt_conf_d.exists():
        for f in apt_conf_d.iterdir():
            content = _file_read(str(f)) or ""
            if "AllowUnauthenticated" in content and "true" in content.lower():
                no_verify = True
    data["apt_unauthenticated_allowed"] = no_verify

    # Kernel: ASLR, dmesg restriction
    sysctl_params = {}
    kernel_params = [
        "kernel.randomize_va_space",   # ASLR
        "kernel.dmesg_restrict",
        "kernel.kptr_restrict",
        "kernel.perf_event_paranoid",
        "net.ipv4.conf.all.rp_filter",
        "fs.protected_hardlinks",
        "fs.protected_symlinks",
    ]
    for param in kernel_params:
        out, _, rc = _run(["sysctl", param])
        if rc == 0 and "=" in out:
            sysctl_params[param] = out.split("=")[-1].strip()
        else:
            sysctl_params[param] = None
    data["kernel_hardening"] = sysctl_params

    return data


# ─────────────────────────────────────────────
# FR4 — Confidencialidad de datos
# ─────────────────────────────────────────────

def collect_fr4_confidentiality() -> dict:
    """
    FR4: Data Confidentiality
    SRs cubiertos:
      SR 4.1  Confidencialidad de información en tránsito
      SR 4.2  Protección de información en reposo
    """
    data = {}

    # SR 4.1 — Cifrado en tránsito: versiones TLS disponibles
    openssl_out, _, _ = _run(["openssl", "version"])
    data["openssl_version"] = openssl_out

    # Cipher suites SSH (algoritmos)
    ssh_ciphers = {}
    for field in ["Ciphers", "MACs", "KexAlgorithms", "HostKeyAlgorithms"]:
        out, _, rc = _run(["ssh", "-Q", field.lower().replace("hostkeyalgorithms", "key")])
        if rc != 0:
            out, _, _ = _run(["ssh", "-Q", field.lower()])
        ssh_ciphers[field] = out.splitlines() if rc == 0 else []
    data["ssh_available_ciphers"] = ssh_ciphers

    # SR 4.2 — Cifrado en reposo: LUKS / dm-crypt
    lsblk_out, _, _ = _run(["lsblk", "-o", "NAME,TYPE,FSTYPE,MOUNTPOINT", "--json"])
    crypt_devices = []
    if lsblk_out:
        try:
            lsblk_data = json.loads(lsblk_out)
            for dev in lsblk_data.get("blockdevices", []):
                if dev.get("type") == "crypt":
                    crypt_devices.append(dev.get("name"))
                for child in dev.get("children", []):
                    if child.get("type") == "crypt":
                        crypt_devices.append(child.get("name"))
        except json.JSONDecodeError:
            pass
    data["luks_encrypted_devices"] = crypt_devices
    data["full_disk_encryption"] = len(crypt_devices) > 0

    # Permisos de archivos sensibles
    sensitive_files = {
        "/etc/shadow": "640 or 000",
        "/etc/passwd": "644",
        "/etc/ssh/sshd_config": "600 or 644",
        "/root": "700 or 750",
        "/etc/gshadow": "640 or 000",
    }
    file_perms = {}
    for fpath, expected in sensitive_files.items():
        try:
            st = os.stat(fpath)
            mode = oct(stat.S_IMODE(st.st_mode))
            file_perms[fpath] = {
                "mode": mode,
                "expected": expected,
                "owner_uid": st.st_uid,
                "owner_gid": st.st_gid,
            }
        except (FileNotFoundError, PermissionError):
            file_perms[fpath] = {"mode": None, "expected": expected, "error": "not_accessible"}
    data["sensitive_file_permissions"] = file_perms

    return data


# ─────────────────────────────────────────────
# FR5 — Flujo restringido de datos
# ─────────────────────────────────────────────

def collect_fr5_restricted_dataflow() -> dict:
    """
    FR5: Restricted Data Flow
    SRs cubiertos:
      SR 5.1  Segmentación de red
      SR 5.2  Protección de zonas
      SR 5.3  Separación general de red
    """
    data = {}

    # Firewall: ufw
    ufw_out, _, ufw_rc = _run(["ufw", "status", "verbose"])
    data["ufw"] = {
        "available": ufw_rc == 0,
        "status": "active" if "Status: active" in ufw_out else "inactive",
        "default_incoming": None,
        "default_outgoing": None,
        "rules_count": 0,
    }
    if ufw_out:
        m_in = re.search(r"Default:\s+(\w+)\s+\(incoming\)", ufw_out)
        m_out = re.search(r"Default:\s+\w+\s+\(incoming\),\s+(\w+)\s+\(outgoing\)", ufw_out)
        data["ufw"]["default_incoming"] = m_in.group(1) if m_in else None
        data["ufw"]["default_outgoing"] = m_out.group(1) if m_out else None
        data["ufw"]["rules_count"] = len(re.findall(r"ALLOW|DENY|REJECT", ufw_out))

    # iptables
    ipt_out, _, ipt_rc = _run(["iptables", "-L", "-n", "--line-numbers"])
    data["iptables"] = {
        "available": ipt_rc == 0,
        "rules": ipt_out[:500] if ipt_out else None,
    }

    # nftables
    nft_out, _, nft_rc = _run(["nft", "list", "ruleset"])
    data["nftables"] = {
        "available": nft_rc == 0,
        "rules": nft_out[:500] if nft_out else None,
    }

    # Interfaces de red
    ip_out, _, _ = _run(["ip", "-j", "addr"])
    interfaces = []
    if ip_out:
        try:
            ifaces = json.loads(ip_out)
            for iface in ifaces:
                interfaces.append({
                    "name": iface.get("ifname"),
                    "state": iface.get("operstate"),
                    "addresses": [a.get("local") for a in iface.get("addr_info", [])],
                })
        except json.JSONDecodeError:
            pass
    data["network_interfaces"] = interfaces

    # IP forwarding (debe estar desactivado en endpoints)
    fw_out, _, _ = _run(["sysctl", "net.ipv4.ip_forward"])
    data["ip_forwarding_enabled"] = "= 1" in (fw_out or "")

    return data


# ─────────────────────────────────────────────
# FR6 — Respuesta oportuna a eventos
# ─────────────────────────────────────────────

def collect_fr6_event_response() -> dict:
    """
    FR6: Timely Response to Events
    SRs cubiertos:
      SR 6.1  Registro de auditoría
      SR 6.2  Monitorización continua
    """
    data = {}

    # SR 6.1 — auditd
    auditd_out, _, auditd_rc = _run(["systemctl", "is-active", "auditd"])
    data["auditd"] = {
        "service_active": auditd_out.strip() == "active",
        "config_exists": Path("/etc/audit/auditd.conf").exists(),
        "rules_file_exists": Path("/etc/audit/audit.rules").exists() or
                             Path("/etc/audit/rules.d/audit.rules").exists(),
    }

    # Reglas de auditoría cargadas
    if _is_root():
        rules_out, _, _ = _run(["auditctl", "-l"])
        data["auditd"]["active_rules_count"] = len(
            [l for l in (rules_out or "").splitlines() if l.startswith("-w") or l.startswith("-a")]
        )
    else:
        data["auditd"]["active_rules_count"] = "requires_root"

    # rsyslog / syslog
    syslog_out, _, syslog_rc = _run(["systemctl", "is-active", "rsyslog"])
    syslog_ng_out, _, syslog_ng_rc = _run(["systemctl", "is-active", "syslog-ng"])
    data["syslog"] = {
        "rsyslog_active": syslog_out.strip() == "active",
        "syslog_ng_active": syslog_ng_out.strip() == "active",
    }

    # journald
    journalctl_out, _, jrc = _run(["journalctl", "--disk-usage"])
    data["journald"] = {
        "active": jrc == 0,
        "disk_usage": journalctl_out,
    }

    # Logrotate
    data["logrotate_configured"] = Path("/etc/logrotate.conf").exists()

    # NTP — sincronización temporal (esencial para correlación de logs)
    timedatectl_out, _, _ = _run(["timedatectl", "show"])
    ntp_params = {}
    for param in ["NTP", "NTPSynchronized", "Timezone", "TimeUSec"]:
        match = re.search(rf"^{param}=(.+)", timedatectl_out, re.MULTILINE)
        ntp_params[param] = match.group(1) if match else None
    data["time_sync"] = ntp_params

    return data


# ─────────────────────────────────────────────
# FR7 — Disponibilidad de recursos
# ─────────────────────────────────────────────

def collect_fr7_availability() -> dict:
    """
    FR7: Resource Availability
    SRs cubiertos:
      SR 7.1  Protección DoS
      SR 7.2  Gestión de capacidad de recursos
      SR 7.3  Backup del sistema de control
      SR 7.6  Determinismo en red
      SR 7.7  Gestión de errores
    """
    data = {}

    # SR 7.1 — Protección DoS: syn cookies, límites de conexión
    syn_cookies, _, _ = _run(["sysctl", "net.ipv4.tcp_syncookies"])
    data["tcp_syncookies"] = "= 1" in (syn_cookies or "")

    # SR 7.2 — Recursos del sistema
    # CPU / RAM
    meminfo = _file_read("/proc/meminfo") or ""
    mem_total_match = re.search(r"MemTotal:\s+(\d+)\s+kB", meminfo)
    mem_avail_match = re.search(r"MemAvailable:\s+(\d+)\s+kB", meminfo)
    data["memory"] = {
        "total_kb": int(mem_total_match.group(1)) if mem_total_match else None,
        "available_kb": int(mem_avail_match.group(1)) if mem_avail_match else None,
    }

    # Disco
    df_out, _, _ = _run(["df", "-h", "--output=target,size,used,avail,pcent"])
    data["disk_usage"] = df_out

    # Ulimits del sistema
    limits_conf = _file_read("/etc/security/limits.conf") or ""
    data["system_limits_configured"] = len(limits_conf.splitlines()) > 10

    # SR 7.3 — Backup
    backup_tools = {}
    for tool in ["rsync", "borgbackup", "restic", "bacula", "amanda", "duplicati"]:
        out, _, rc = _run(["which", tool])
        backup_tools[tool] = rc == 0
    data["backup_tools"] = backup_tools
    data["backup_configured"] = any(backup_tools.values())

    # SR 7.7 — Estado general de servicios
    failed_out, _, _ = _run(["systemctl", "list-units", "--state=failed", "--no-pager", "--plain"])
    failed_services = [
        line.split()[0] for line in failed_out.splitlines()
        if ".service" in line and "failed" in line
    ]
    data["failed_services"] = failed_services
    data["failed_services_count"] = len(failed_services)

    # Uptime
    uptime_out, _, _ = _run(["uptime", "-p"])
    data["uptime"] = uptime_out

    return data


# ─────────────────────────────────────────────
# Recolector principal
# ─────────────────────────────────────────────

def collect_system_info() -> dict:
    """Información general del sistema operativo."""
    uname = platform.uname()

    # Versión de Ubuntu / Distro
    os_release = _file_read("/etc/os-release") or ""
    os_info = {}
    for line in os_release.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            os_info[k] = v.strip('"')

    # Paquetes instalados (primeros 50 actualizables)
    upgradable_out, _, _ = _run(["apt", "list", "--upgradable", "--quiet=2"])
    upgradable = [l.split("/")[0] for l in (upgradable_out or "").splitlines() if "/" in l]

    # Tiempo del sistema
    now = datetime.now(timezone.utc).isoformat()

    return {
        "hostname": uname.node,
        "os_name": os_info.get("NAME", uname.system),
        "os_version": os_info.get("VERSION_ID", uname.release),
        "os_id": os_info.get("ID", ""),
        "kernel": uname.release,
        "architecture": uname.machine,
        "python_version": platform.python_version(),
        "collection_timestamp": now,
        "running_as_root": _is_root(),
        "pending_upgrades_count": len(upgradable),
        "pending_upgrades_sample": upgradable[:10],
    }


def run_full_collection() -> dict:
    """
    Ejecuta la recolección completa de todos los FR.
    Devuelve un dict estructurado listo para el analyzer.
    """
    print("[*] Iniciando recolección IEC 62443-3-3...")

    collection = {
        "meta": collect_system_info(),
        "fr1_identification": collect_fr1_identification(),
        "fr2_use_control": collect_fr2_use_control(),
        "fr3_integrity": collect_fr3_integrity(),
        "fr4_confidentiality": collect_fr4_confidentiality(),
        "fr5_restricted_dataflow": collect_fr5_restricted_dataflow(),
        "fr6_event_response": collect_fr6_event_response(),
        "fr7_availability": collect_fr7_availability(),
    }

    print(f"[+] Recolección completada: {collection['meta']['collection_timestamp']}")
    print(f"    Hostname: {collection['meta']['hostname']}")
    print(f"    OS: {collection['meta']['os_name']} {collection['meta']['os_version']}")
    print(f"    Root: {collection['meta']['running_as_root']}")

    return collection


# ─────────────────────────────────────────────
# Punto de entrada
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="IEC 62443-3-3 Collector — Recopila datos del OS para análisis de cumplimiento"
    )
    parser.add_argument(
        "--output", "-o",
        default="collection_output.json",
        help="Archivo de salida JSON (default: collection_output.json)"
    )
    parser.add_argument(
        "--fr", "-f",
        choices=["fr1", "fr2", "fr3", "fr4", "fr5", "fr6", "fr7", "all"],
        default="all",
        help="FR específico a recolectar (default: all)"
    )
    parser.add_argument(
        "--pretty", "-p",
        action="store_true",
        help="Salida JSON con indentación"
    )
    args = parser.parse_args()

    fr_map = {
        "fr1": lambda: {"meta": collect_system_info(), "fr1_identification": collect_fr1_identification()},
        "fr2": lambda: {"meta": collect_system_info(), "fr2_use_control": collect_fr2_use_control()},
        "fr3": lambda: {"meta": collect_system_info(), "fr3_integrity": collect_fr3_integrity()},
        "fr4": lambda: {"meta": collect_system_info(), "fr4_confidentiality": collect_fr4_confidentiality()},
        "fr5": lambda: {"meta": collect_system_info(), "fr5_restricted_dataflow": collect_fr5_restricted_dataflow()},
        "fr6": lambda: {"meta": collect_system_info(), "fr6_event_response": collect_fr6_event_response()},
        "fr7": lambda: {"meta": collect_system_info(), "fr7_availability": collect_fr7_availability()},
        "all": run_full_collection,
    }

    result = fr_map[args.fr]()

    indent = 2 if args.pretty else None
    output_path = Path(args.output)
    output_path.write_text(json.dumps(result, indent=indent, default=str), encoding="utf-8")
    print(f"\n[+] Resultados guardados en: {output_path.resolve()}")
