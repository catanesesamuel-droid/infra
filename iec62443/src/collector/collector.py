"""
IEC 62443-3-3 Compliance Analyzer
Módulo: collector.py  — Versión adaptada Ubuntu 25.10
Norma:  UNE-EN IEC 62443-3-3:2020

Recopila datos del sistema para los 7 Foundational Requirements (FR)
y todos sus System Requirements (SR) normativos.

Cambios respecto a la versión anterior:
  · SR 1.10 – Retroalimentación del autenticador (nuevo)
  · SR 1.11 – Intentos fallidos de login / pam_faillock (nuevo)
  · SR 1.12 – Aviso de uso del sistema / MOTD/banner (nuevo)
  · SR 1.13 – Acceso por redes no confiables / VPN (nuevo)
  · SR 2.4  – Control de código móvil / AppArmor USB (nuevo)
  · SR 2.5  – Bloqueo de sesión inactiva (nuevo)
  · SR 2.7  – Sesiones SSH simultáneas (nuevo)
  · SR 2.8  – Eventos auditables / reglas auditd categorías (refactor)
  · SR 2.9  – Capacidad almacenamiento auditoría (nuevo)
  · SR 2.10 – Respuesta a fallos de auditoría (nuevo)
  · SR 2.11 – Marcas de tiempo / NTP (refactor a FR2)
  · SR 3.1  – Integridad comunicación / TLS y SSH MACs (nuevo)
  · SR 3.5  – Validación de entrada / sysctl hardening (nuevo)
  · SR 3.9  – Protección info auditoría / permisos /var/log (nuevo)
  · SR 4.3  – Uso de criptografía / política crypto sistema (nuevo)
  · SR 5.2  – Protección de límites de zona / firewall avanzado (nuevo)
  · SR 6.2  – Supervisión continua / IDS-IPS / fail2ban (nuevo)
  · SR 7.4  – Recuperación del sistema / recovery tools (nuevo)
  · SR 7.6  – Configuración de red y seguridad / inventario configs (nuevo)
  · SR 7.8  – Inventario de componentes (nuevo)
  · Ubuntu 25.10: nftables como backend nativo, systemd-resolved, etc.
"""

import os
import subprocess
import platform
import json
import pwd
import grp
import stat
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


# ─────────────────────────────────────────────
# Utilidades internas
# ─────────────────────────────────────────────

def _run(cmd: list[str], timeout: int = 10) -> tuple[str, str, int]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return "", "TIMEOUT", -1
    except FileNotFoundError:
        return "", f"CMD_NOT_FOUND:{cmd[0]}", -1
    except PermissionError:
        return "", "PERMISSION_DENIED", -1


def _file_read(path: str) -> Optional[str]:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except (FileNotFoundError, PermissionError):
        return None


def _is_root() -> bool:
    return os.geteuid() == 0


def _sysctl(param: str) -> Optional[str]:
    out, _, rc = _run(["sysctl", "-n", param])
    return out if rc == 0 else None


def _service_active(name: str) -> bool:
    out, _, _ = _run(["systemctl", "is-active", name])
    return out.strip() == "active"


# ─────────────────────────────────────────────
# Metadatos del sistema
# ─────────────────────────────────────────────

def collect_system_info() -> dict:
    uname = platform.uname()
    os_release = _file_read("/etc/os-release") or ""
    os_info = {}
    for line in os_release.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            os_info[k] = v.strip('"')

    # Paquetes actualizables (Ubuntu 25.10 usa apt)
    upgr_out, _, _ = _run(["apt", "list", "--upgradable", "--quiet=2"])
    upgradable = [l.split("/")[0] for l in (upgr_out or "").splitlines() if "/" in l]

    # Versión de kernel (Ubuntu 25.10 trae kernel 6.x)
    kernel_ver, _, _ = _run(["uname", "-r"])

    return {
        "hostname":                uname.node,
        "os_name":                 os_info.get("NAME", uname.system),
        "os_version":              os_info.get("VERSION_ID", uname.release),
        "os_id":                   os_info.get("ID", ""),
        "kernel":                  kernel_ver or uname.release,
        "architecture":            uname.machine,
        "python_version":          platform.python_version(),
        "collection_timestamp":    datetime.now(timezone.utc).isoformat(),
        "running_as_root":         _is_root(),
        "pending_upgrades_count":  len(upgradable),
        "pending_upgrades_sample": upgradable[:10],
    }


# ─────────────────────────────────────────────
# FR1 — Identificación y autenticación (IAC)
# SRs: 1.1, 1.2, 1.3, 1.4, 1.5, 1.7, 1.8, 1.9, 1.10, 1.11, 1.12, 1.13
# ─────────────────────────────────────────────

def collect_fr1_identification() -> dict:
    data: dict = {}

    # ── SR 1.1 / SR 1.3 — Usuarios y cuentas ──
    users = []
    for pw in pwd.getpwall():
        users.append({
            "username":    pw.pw_name,
            "uid":         pw.pw_uid,
            "gid":         pw.pw_gid,
            "home":        pw.pw_dir,
            "shell":       pw.pw_shell,
            "is_system":   pw.pw_uid < 1000,
            "login_shell": pw.pw_shell not in (
                "/usr/sbin/nologin", "/bin/false", "/sbin/nologin", "/bin/sync"
            ),
        })
    data["users"]            = users
    data["users_with_login"] = [u for u in users if u["login_shell"] and not u["is_system"]]

    # SR 1.3 — Grupos privilegiados
    groups = []
    for g in grp.getgrall():
        groups.append({"name": g.gr_name, "gid": g.gr_gid, "members": g.gr_mem})
    data["groups"] = groups
    data["sudo_group_members"] = next(
        (g["members"] for g in groups if g["name"] in ("sudo", "wheel")), []
    )
    # Cuentas de servicio sin contraseña habilitadas (cuentas no desactivadas)
    shadow = _file_read("/etc/shadow") or ""
    locked_accounts = []
    service_accounts_active = []
    for line in shadow.splitlines():
        parts = line.split(":")
        if len(parts) >= 2:
            name, pw_hash = parts[0], parts[1]
            is_locked = pw_hash.startswith("!") or pw_hash.startswith("*")
            is_system = any(u["username"] == name and u["is_system"] for u in users)
            if is_system and not is_locked and pw_hash not in ("", "x"):
                service_accounts_active.append(name)
            if is_locked:
                locked_accounts.append(name)
    data["locked_accounts"]         = locked_accounts
    data["service_accounts_active"] = service_accounts_active  # SR 1.3: cuentas servicio sin bloquear

    # ── SR 1.4 — Gestión de identificadores (unicidad) ──
    uid_map: dict[int, list[str]] = {}
    for u in users:
        uid_map.setdefault(u["uid"], []).append(u["username"])
    data["duplicate_uids"] = {str(k): v for k, v in uid_map.items() if len(v) > 1}

    # ── SR 1.5 — Gestión de autenticadores ──
    # Contraseñas por defecto conocidas / cuentas sin contraseña
    no_password_accounts = []
    for line in shadow.splitlines():
        parts = line.split(":")
        if len(parts) >= 2 and parts[1] == "":
            no_password_accounts.append(parts[0])
    data["no_password_accounts"] = no_password_accounts

    # SR 1.7 — Política de contraseñas (login.defs)
    login_defs = _file_read("/etc/login.defs") or ""
    pw_policy  = {}
    for key in ["PASS_MAX_DAYS", "PASS_MIN_DAYS", "PASS_MIN_LEN", "PASS_WARN_AGE"]:
        m = re.search(rf"^{key}\s+(\d+)", login_defs, re.MULTILINE)
        pw_policy[key] = int(m.group(1)) if m else None
    data["password_policy"] = pw_policy

    # PAM pwquality (Ubuntu 25.10 incluye libpam-pwquality)
    pwq = _file_read("/etc/security/pwquality.conf") or ""
    # También leer conf.d
    pwq_d = Path("/etc/security/pwquality.conf.d")
    if pwq_d.exists():
        for f in pwq_d.iterdir():
            pwq += "\n" + (_file_read(str(f)) or "")
    pam_settings: dict[str, Optional[int]] = {}
    for s in ["minlen", "dcredit", "ucredit", "lcredit", "ocredit", "minclass",
              "maxrepeat", "maxsequence", "dictcheck"]:
        m = re.search(rf"^{s}\s*=\s*(-?\d+)", pwq, re.MULTILINE)
        pam_settings[s] = int(m.group(1)) if m else None
    data["pam_pwquality"] = pam_settings

    # ── SR 1.7 RE 1 — Historial de contraseñas ──
    pam_common = _file_read("/etc/pam.d/common-password") or ""
    remember_m  = re.search(r"remember=(\d+)", pam_common)
    data["password_history_count"] = int(remember_m.group(1)) if remember_m else 0

    # ── SR 1.8 — SSH y PKI ──
    sshd_config = _file_read("/etc/ssh/sshd_config") or ""
    # Leer también sshd_config.d/ (Ubuntu 25.10)
    sshd_d = Path("/etc/ssh/sshd_config.d")
    if sshd_d.exists():
        for f in sorted(sshd_d.iterdir()):
            sshd_config += "\n" + (_file_read(str(f)) or "")
    ssh: dict[str, str] = {}
    for param in [
        "PasswordAuthentication", "PubkeyAuthentication", "PermitRootLogin",
        "PermitEmptyPasswords", "MaxAuthTries", "Protocol",
        "AuthorizedKeysFile", "UsePAM", "ChallengeResponseAuthentication",
        "KbdInteractiveAuthentication", "ClientAliveInterval", "ClientAliveCountMax",
        "MaxSessions", "AllowAgentForwarding", "X11Forwarding",
        "Banner", "PrintLastLog",
    ]:
        m = re.search(rf"^\s*{param}\s+(\S+)", sshd_config, re.IGNORECASE | re.MULTILINE)
        ssh[param] = m.group(1) if m else "not_set"
    data["ssh_config"] = ssh

    # MFA — pam_google_authenticator, pam_oath, pam_duo, pam_u2f
    pam_sshd = _file_read("/etc/pam.d/sshd") or ""
    mfa_modules = ["pam_google_authenticator", "pam_oath", "pam_duo", "pam_u2f", "pam_totp"]
    data["mfa_configured"]        = any(m in pam_sshd for m in mfa_modules)
    data["mfa_module_detected"]   = next((m for m in mfa_modules if m in pam_sshd), None)

    # ── SR 1.9 — Fortaleza autenticación clave pública ──
    # Verificar algoritmos de host key (evitar RSA-1024, DSA)
    host_keys = []
    for f in Path("/etc/ssh").glob("ssh_host_*_key.pub"):
        key_type = f.stem.replace("ssh_host_", "").replace("_key", "")
        host_keys.append(key_type)
    data["ssh_host_key_types"] = host_keys
    # Tamaño de clave RSA del host
    rsa_key_file = "/etc/ssh/ssh_host_rsa_key"
    rsa_bits = None
    if Path(rsa_key_file).exists():
        out, _, rc = _run(["ssh-keygen", "-l", "-f", rsa_key_file])
        if rc == 0:
            m = re.search(r"(\d+)", out)
            rsa_bits = int(m.group(1)) if m else None
    data["ssh_host_rsa_bits"] = rsa_bits

    # ── SR 1.10 — Retroalimentación del autenticador ──
    # Verifica que SSH no muestre errores detallados y que PAM no filtre usuario
    data["ssh_log_level"] = ssh.get("LogLevel", "not_set")
    # Verifica que /etc/pam.d/sshd no use pam_faildelay demasiado corto
    pam_faildelay_m = re.search(r"pam_faildelay.*delay=(\d+)", pam_sshd)
    data["pam_faildelay_us"] = int(pam_faildelay_m.group(1)) if pam_faildelay_m else None

    # ── SR 1.11 — Intentos fallidos de inicio de sesión ──
    # pam_faillock (reemplaza pam_tally2 en Ubuntu 22.04+)
    faillock_conf = _file_read("/etc/security/faillock.conf") or ""
    faillock: dict[str, Optional[str]] = {}
    for param in ["deny", "fail_interval", "unlock_time", "silent", "audit", "local_users_only"]:
        m = re.search(rf"^{param}\s*=?\s*(\S*)", faillock_conf, re.MULTILINE)
        faillock[param] = m.group(1) if m else None
    # También buscar en pam.d/common-auth
    common_auth = _file_read("/etc/pam.d/common-auth") or ""
    faillock["in_pam_common_auth"] = "pam_faillock" in common_auth
    data["faillock_config"] = faillock

    # ── SR 1.12 — Aviso de uso del sistema (MOTD / Banner) ──
    ssh_banner_file = ssh.get("Banner", "not_set")
    banner_content  = None
    if ssh_banner_file not in ("not_set", "none", "NONE"):
        banner_content = _file_read(ssh_banner_file)
    data["ssh_banner_configured"] = banner_content is not None and len(banner_content.strip()) > 10
    data["ssh_banner_file"]       = ssh_banner_file

    # Issue / MOTD para acceso local
    issue_content  = _file_read("/etc/issue") or ""
    issue_net      = _file_read("/etc/issue.net") or ""
    motd_content   = _file_read("/etc/motd") or ""
    data["login_banner_issue"]     = len(issue_content.strip()) > 10
    data["login_banner_issue_net"] = len(issue_net.strip()) > 10
    data["motd_configured"]        = len(motd_content.strip()) > 10

    # ── SR 1.13 — Acceso a través de redes no confiables (VPN) ──
    vpn_tools: dict[str, bool] = {}
    for tool in ["openvpn", "wg", "wireguard", "strongswan", "xl2tpd"]:
        _, _, rc = _run(["which", tool])
        vpn_tools[tool] = rc == 0
    data["vpn_tools_installed"] = vpn_tools
    data["vpn_configured"] = any(vpn_tools.values())
    # Interfaces VPN activas
    ip_out, _, _ = _run(["ip", "-j", "link"])
    vpn_ifaces = []
    if ip_out:
        try:
            ifaces = json.loads(ip_out)
            for iface in ifaces:
                name = iface.get("ifname", "")
                if any(name.startswith(p) for p in ("wg", "tun", "tap", "vpn", "ipsec")):
                    vpn_ifaces.append(name)
        except json.JSONDecodeError:
            pass
    data["vpn_interfaces_active"] = vpn_ifaces

    return data


# ─────────────────────────────────────────────
# FR2 — Control de uso (UC)
# SRs: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 2.8, 2.9, 2.10, 2.11, 2.12
# ─────────────────────────────────────────────

def collect_fr2_use_control() -> dict:
    data: dict = {}

    # ── SR 2.1 — Aplicación de autorización ──
    sudoers = _file_read("/etc/sudoers") or ""
    sudoers_d = []
    for f in Path("/etc/sudoers.d").iterdir() if Path("/etc/sudoers.d").exists() else []:
        c = _file_read(str(f))
        if c:
            sudoers_d.append({"file": f.name, "nopasswd": "NOPASSWD" in c})
    data["sudoers_nopasswd_entries"] = bool(re.search(r"NOPASSWD", sudoers))
    data["sudoers_d_nopasswd"]       = any(f["nopasswd"] for f in sudoers_d)
    data["sudoers_d_files"]          = len(sudoers_d)

    # AppArmor (Ubuntu 25.10 usa AppArmor 4.x por defecto)
    aa_out, _, aa_rc = _run(["aa-status", "--json"])
    if aa_rc == 0 and aa_out:
        try:
            aa_data    = json.loads(aa_out)
            profiles   = aa_data.get("profiles", {})
            enforce_n  = sum(1 for v in profiles.values() if v == "enforce")
            complain_n = sum(1 for v in profiles.values() if v == "complain")
        except json.JSONDecodeError:
            enforce_n, complain_n = 0, 0
    else:
        aa_text_out, _, aa_rc2 = _run(["apparmor_status"])
        enforce_n  = len(re.findall(r"enforce", aa_text_out))
        complain_n = len(re.findall(r"complain", aa_text_out))
        aa_rc = aa_rc2
    data["apparmor"] = {
        "available":        aa_rc == 0 or aa_rc2 == 0 if 'aa_rc2' in dir() else aa_rc == 0,
        "profiles_enforce": enforce_n,
        "profiles_complain":complain_n,
    }

    # ── SR 2.2 — Control uso inalámbrico ──
    # Detectar interfaces wifi y si están gestionadas
    iw_out, _, iw_rc = _run(["iw", "dev"])
    wifi_interfaces = re.findall(r"Interface\s+(\S+)", iw_out) if iw_rc == 0 else []
    data["wifi_interfaces"] = wifi_interfaces
    data["wifi_active"]     = len(wifi_interfaces) > 0
    # Verificar si NetworkManager gestiona wifi con políticas
    nm_conf = _file_read("/etc/NetworkManager/NetworkManager.conf") or ""
    data["networkmanager_wifi_managed"] = "wifi" in nm_conf.lower()

    # ── SR 2.3 — Dispositivos portátiles/móviles: USB storage ──
    # Comprobar si usb-storage está bloqueado (módulo en lista negra)
    modprobe_d = Path("/etc/modprobe.d")
    usb_storage_blacklisted = False
    if modprobe_d.exists():
        for f in modprobe_d.iterdir():
            content = _file_read(str(f)) or ""
            if re.search(r"blacklist\s+usb.storage|install\s+usb.storage\s+/bin/true", content):
                usb_storage_blacklisted = True
    data["usb_storage_blacklisted"] = usb_storage_blacklisted
    # udev rules para USB
    udev_usb_rules = list(Path("/etc/udev/rules.d").glob("*usb*")) if Path("/etc/udev/rules.d").exists() else []
    data["udev_usb_rules_count"] = len(udev_usb_rules)

    # ── SR 2.4 — Código móvil ──
    # AppArmor para navegadores / entornos de ejecución
    # Verificar si java, javascript engines están controlados
    code_tools: dict[str, bool] = {}
    for tool in ["java", "node", "python3", "perl", "ruby"]:
        _, _, rc = _run(["which", tool])
        code_tools[tool] = rc == 0
    data["mobile_code_runtimes"] = code_tools
    # Sandboxing de procesos (seccomp, namespaces)
    seccomp_val = _sysctl("kernel.seccomp.actions_logged")
    data["seccomp_available"] = seccomp_val is not None

    # ── SR 2.5 — Bloqueo de sesión ──
    # TMOUT en /etc/profile y /etc/bash.bashrc
    profile = _file_read("/etc/profile") or ""
    bash_rc  = _file_read("/etc/bash.bashrc") or ""
    security_conf = _file_read("/etc/security/limits.conf") or ""
    tmout_m = (re.search(r"TMOUT\s*=\s*(\d+)", profile) or
               re.search(r"TMOUT\s*=\s*(\d+)", bash_rc))
    data["session_timeout_seconds"] = int(tmout_m.group(1)) if tmout_m else None
    # Bloqueo de pantalla (gdm, lightdm, etc.) — solo relevante en sistemas con GUI
    _, _, gnome_rc = _run(["gsettings", "get", "org.gnome.desktop.session", "idle-delay"])
    data["desktop_lock_configured"] = gnome_rc == 0

    # ── SR 2.6 — Terminar sesión remota ──
    ssh = data.get("_ssh_ref", {})   # no disponible aquí, se lee de FR1
    # ClientAliveInterval/ClientAliveCountMax se leen en FR1
    # Aquí registramos los puertos de acceso remoto
    ss_out, _, _ = _run(["ss", "-tulnp"])
    listening: list[dict] = []
    for line in ss_out.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 5:
            listening.append({
                "proto":         parts[0],
                "local_address": parts[4],
                "process":       parts[-1] if len(parts) > 6 else "unknown",
            })
    data["listening_ports"]       = listening
    data["listening_ports_count"] = len(listening)

    # Servicios remotos inseguros
    svc_out, _, _ = _run(["systemctl", "list-units", "--type=service", "--state=running",
                           "--no-pager", "--plain"])
    remote_svcs = []
    for svc in ["ssh", "sshd", "telnet", "rsh", "rlogin", "vnc", "xrdp", "rdp"]:
        if svc in svc_out.lower():
            remote_svcs.append(svc)
    data["active_remote_services"] = remote_svcs
    data["dangerous_remote_services"] = [s for s in remote_svcs if s in ("telnet", "rsh", "rlogin")]

    # ── SR 2.7 — Sesiones simultáneas ──
    # MaxSessions en sshd_config se lee en FR1 y se analiza aquí
    # Límites de procesos por usuario (pam_limits)
    ulimits_conf = _file_read("/etc/security/limits.conf") or ""
    nproc_limit_m = re.search(r"^\*\s+hard\s+nproc\s+(\d+)", ulimits_conf, re.MULTILINE)
    data["nproc_hard_limit"] = int(nproc_limit_m.group(1)) if nproc_limit_m else None

    # ── SR 2.8 — Eventos auditables (auditd) ──
    auditd_active = _service_active("auditd")
    data["auditd_active"]          = auditd_active
    data["auditd_config_exists"]   = Path("/etc/audit/auditd.conf").exists()
    # Contar y categorizar reglas
    audit_categories = {
        "access_control":  0,   # -w /etc/passwd -w /etc/shadow -w /etc/sudoers
        "os_events":       0,   # -a always,exit -S ...
        "config_changes":  0,   # -w /etc/ ...
        "exec_commands":   0,   # -S execve
        "network":         0,   # -S bind -S connect
    }
    if _is_root():
        rules_out, _, _ = _run(["auditctl", "-l"])
        rules_lines = [l for l in (rules_out or "").splitlines()
                       if l.startswith("-w") or l.startswith("-a")]
        data["auditd_active_rules_count"] = len(rules_lines)
        for rule in rules_lines:
            if any(p in rule for p in ["/etc/passwd", "/etc/shadow", "/etc/group", "/etc/sudoers"]):
                audit_categories["access_control"] += 1
            if "-S execve" in rule:
                audit_categories["exec_commands"] += 1
            if "/etc/" in rule and "identity" not in rule:
                audit_categories["config_changes"] += 1
            if any(p in rule for p in ["-S bind", "-S connect", "-S accept"]):
                audit_categories["network"] += 1
            if "-a always,exit" in rule:
                audit_categories["os_events"] += 1
        data["audit_categories"] = audit_categories
    else:
        data["auditd_active_rules_count"] = "requires_root"
        data["audit_categories"]          = audit_categories

    # ── SR 2.9 — Capacidad almacenamiento auditoría ──
    auditd_conf = _file_read("/etc/audit/auditd.conf") or ""
    max_log_file_m     = re.search(r"max_log_file\s*=\s*(\d+)", auditd_conf)
    max_log_file_action= re.search(r"max_log_file_action\s*=\s*(\S+)", auditd_conf)
    num_logs_m         = re.search(r"num_logs\s*=\s*(\d+)", auditd_conf)
    data["audit_storage"] = {
        "max_log_file_mb":     int(max_log_file_m.group(1)) if max_log_file_m else None,
        "max_log_file_action": max_log_file_action.group(1) if max_log_file_action else None,
        "num_logs":            int(num_logs_m.group(1)) if num_logs_m else None,
    }
    # Espacio real usado por /var/log/audit/
    audit_size_out, _, _ = _run(["du", "-sh", "/var/log/audit/"])
    data["audit_log_disk_usage"] = audit_size_out.split()[0] if audit_size_out else "unknown"

    # ── SR 2.10 — Respuesta a fallos de auditoría ──
    disk_full_action = re.search(r"disk_full_action\s*=\s*(\S+)", auditd_conf)
    disk_error_action= re.search(r"disk_error_action\s*=\s*(\S+)", auditd_conf)
    data["audit_failure_response"] = {
        "disk_full_action":  disk_full_action.group(1) if disk_full_action else None,
        "disk_error_action": disk_error_action.group(1) if disk_error_action else None,
    }

    # ── SR 2.11 — Marcas de tiempo (NTP) ──
    timedatectl_out, _, _ = _run(["timedatectl", "show"])
    ntp: dict[str, Optional[str]] = {}
    for p in ["NTP", "NTPSynchronized", "Timezone", "TimeUSec", "RTCTimeUSec"]:
        m = re.search(rf"^{p}=(.+)", timedatectl_out, re.MULTILINE)
        ntp[p] = m.group(1) if m else None
    data["time_sync"] = ntp
    # Verificar configuración NTP (systemd-timesyncd o chrony)
    chrony_active   = _service_active("chronyd")
    timesyncd_active= _service_active("systemd-timesyncd")
    data["ntp_daemon"] = "chrony" if chrony_active else ("timesyncd" if timesyncd_active else "none")
    # Servidores NTP configurados
    timesyncd_conf = _file_read("/etc/systemd/timesyncd.conf") or ""
    ntp_servers_m  = re.search(r"^NTP\s*=\s*(.+)", timesyncd_conf, re.MULTILINE)
    data["ntp_servers_configured"] = ntp_servers_m.group(1).split() if ntp_servers_m else []

    # ── SR 2.12 — No rechazo ──
    # auditd con inmutable rules + integridad de logs
    audit_immutable = "-e 2" in (_file_read("/etc/audit/audit.rules") or "")
    data["audit_rules_immutable"] = audit_immutable
    # rsyslog/syslog-ng activo con almacenamiento
    data["syslog"] = {
        "rsyslog_active":  _service_active("rsyslog"),
        "syslog_ng_active":_service_active("syslog-ng"),
        "journald_active": _service_active("systemd-journald"),
    }
    # Logrotate
    data["logrotate_configured"] = Path("/etc/logrotate.conf").exists()

    return data


# ─────────────────────────────────────────────
# FR3 — Integridad del sistema (SI)
# SRs: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8, 3.9
# ─────────────────────────────────────────────

def collect_fr3_integrity() -> dict:
    data: dict = {}

    # ── SR 3.1 — Integridad de la comunicación ──
    # TLS: versiones soportadas por openssl
    openssl_out, _, _     = _run(["openssl", "version"])
    data["openssl_version"] = openssl_out
    # SSH MACs (integridad de mensajes en tránsito)
    ssh_macs_out, _, rc   = _run(["ssh", "-Q", "mac"])
    data["ssh_macs_available"] = ssh_macs_out.splitlines() if rc == 0 else []
    weak_macs = [m for m in data["ssh_macs_available"]
                 if any(w in m for w in ["md5", "sha1", "-96"])]
    data["ssh_weak_macs"] = weak_macs
    # Verificar si sshd_config restringe MACs
    sshd_conf = _file_read("/etc/ssh/sshd_config") or ""
    sshd_d = Path("/etc/ssh/sshd_config.d")
    if sshd_d.exists():
        for f in sorted(sshd_d.iterdir()):
            sshd_conf += "\n" + (_file_read(str(f)) or "")
    macs_line = re.search(r"^\s*MACs\s+(.+)", sshd_conf, re.IGNORECASE | re.MULTILINE)
    data["sshd_macs_configured"]  = macs_line.group(1) if macs_line else None
    # Verificar TLS en servicios web si existen
    nginx_ssl = Path("/etc/nginx/nginx.conf").exists() or Path("/etc/nginx/sites-enabled").exists()
    apache_ssl = Path("/etc/apache2/sites-enabled").exists()
    data["web_server_tls"] = {"nginx": nginx_ssl, "apache": apache_ssl}

    # ── SR 3.2 — Protección contra código malicioso ──
    security_tools: dict[str, dict] = {}
    for tool in ["clamav", "clamd", "freshclam", "rkhunter", "chkrootkit",
                 "aide", "tripwire", "ossec", "wazuh-agent", "lynis"]:
        _, _, rc = _run(["which", tool])
        security_tools[tool] = {"installed": rc == 0}
    data["security_tools"] = security_tools
    # ClamAV: verificar base de datos actualizada
    clam_db = Path("/var/lib/clamav/main.cvd")
    data["clamav_db_updated"] = clam_db.exists() and (
        (datetime.now().timestamp() - clam_db.stat().st_mtime) < 86400 * 7  # < 7 días
    ) if clam_db.exists() else False

    # ASLR, DEP, Stack Canaries (kernel hardening)
    data["kernel_hardening"] = {
        "kernel.randomize_va_space":  _sysctl("kernel.randomize_va_space"),   # ASLR
        "kernel.dmesg_restrict":      _sysctl("kernel.dmesg_restrict"),
        "kernel.kptr_restrict":       _sysctl("kernel.kptr_restrict"),
        "kernel.perf_event_paranoid": _sysctl("kernel.perf_event_paranoid"),
        "kernel.yama.ptrace_scope":   _sysctl("kernel.yama.ptrace_scope"),    # Anti-ptrace
        "fs.protected_hardlinks":     _sysctl("fs.protected_hardlinks"),
        "fs.protected_symlinks":      _sysctl("fs.protected_symlinks"),
        "fs.suid_dumpable":           _sysctl("fs.suid_dumpable"),            # Sin core dumps SUID
        "net.core.bpf_jit_harden":   _sysctl("net.core.bpf_jit_harden"),     # BPF JIT hardening
    }

    # ── SR 3.3 — Verificación de funcionalidad de seguridad (FIM) ──
    aide_conf = _file_read("/etc/aide/aide.conf") or _file_read("/etc/aide.conf")
    data["aide_configured"]  = aide_conf is not None
    aide_db = Path("/var/lib/aide/aide.db")
    data["aide_db_exists"]   = aide_db.exists()
    # Tripwire
    data["tripwire_configured"] = Path("/etc/tripwire/twpol.txt").exists()

    # ── SR 3.4 — Integridad del software ──
    # Paquetes APT con firma verificada
    apt_conf_d = Path("/etc/apt/apt.conf.d")
    no_verify  = False
    if apt_conf_d.exists():
        for f in apt_conf_d.iterdir():
            content = _file_read(str(f)) or ""
            if "AllowUnauthenticated" in content and "true" in content.lower():
                no_verify = True
    data["apt_unauthenticated_allowed"] = no_verify
    # Secure Boot (Ubuntu 25.10 con shim-signed)
    sb_out, _, sb_rc = _run(["mokutil", "--sb-state"])
    data["secure_boot"] = {
        "available": sb_rc == 0,
        "state":     sb_out if sb_rc == 0 else "unknown",
        "enabled":   "enabled" in (sb_out or "").lower(),
    }
    # dm-verity / snapd verification
    _, _, snap_rc = _run(["snap", "list"])
    data["snap_packages"] = snap_rc == 0  # Snaps tienen verificación de integridad incorporada

    # ── SR 3.5 — Validación de entrada ──
    # Kernel: protecciones de red contra spoofing y ataques
    data["input_validation"] = {
        "net.ipv4.conf.all.rp_filter":      _sysctl("net.ipv4.conf.all.rp_filter"),
        "net.ipv4.conf.default.rp_filter":  _sysctl("net.ipv4.conf.default.rp_filter"),
        "net.ipv4.conf.all.accept_source_route":   _sysctl("net.ipv4.conf.all.accept_source_route"),
        "net.ipv4.conf.all.accept_redirects":      _sysctl("net.ipv4.conf.all.accept_redirects"),
        "net.ipv4.conf.all.send_redirects":        _sysctl("net.ipv4.conf.all.send_redirects"),
        "net.ipv4.icmp_echo_ignore_broadcasts":    _sysctl("net.ipv4.icmp_echo_ignore_broadcasts"),
        "net.ipv4.icmp_ignore_bogus_error_responses": _sysctl("net.ipv4.icmp_ignore_bogus_error_responses"),
        "net.ipv6.conf.all.accept_redirects":      _sysctl("net.ipv6.conf.all.accept_redirects"),
    }

    # ── SR 3.7 — Tratamiento de errores (core dumps) ──
    core_pattern = _sysctl("kernel.core_pattern")
    core_uses_pid = _sysctl("kernel.core_uses_pid")
    data["core_dumps"] = {
        "kernel.core_pattern":  core_pattern,
        "kernel.core_uses_pid": core_uses_pid,
        "apport_disabled":      not _service_active("apport"),  # Ubuntu crash reporter
    }
    # Verificar ulimit de core dumps
    limits_conf = _file_read("/etc/security/limits.conf") or ""
    core_limit_m = re.search(r"^\*\s+(hard|soft)\s+core\s+(\d+)", limits_conf, re.MULTILINE)
    data["core_dumps"]["system_limit"] = core_limit_m.group(2) if core_limit_m else None

    # ── SR 3.9 — Protección de información de auditoría ──
    log_dir_stat = None
    try:
        s = os.stat("/var/log")
        log_dir_stat = oct(stat.S_IMODE(s.st_mode))
    except OSError:
        pass
    audit_log_stat = None
    try:
        s = os.stat("/var/log/audit")
        audit_log_stat = oct(stat.S_IMODE(s.st_mode))
    except OSError:
        pass
    data["audit_log_protection"] = {
        "/var/log_mode":       log_dir_stat,
        "/var/log/audit_mode": audit_log_stat,
    }
    # rsyslog: ¿envía logs a servidor remoto?
    rsyslog_conf = _file_read("/etc/rsyslog.conf") or ""
    data["remote_logging_configured"] = bool(
        re.search(r"^[^#]*@@?\s*\S+", rsyslog_conf, re.MULTILINE)
    )

    return data


# ─────────────────────────────────────────────
# FR4 — Confidencialidad de datos (DC)
# SRs: 4.1, 4.2, 4.3
# ─────────────────────────────────────────────

def collect_fr4_confidentiality() -> dict:
    data: dict = {}

    # ── SR 4.1 — Confidencialidad en tránsito ──
    data["openssl_version"] = _run(["openssl", "version"])[0]
    # Verificar TLS 1.0 y 1.1 deshabilitados
    tls10_out, _, _ = _run(["openssl", "s_client", "-connect", "localhost:443", "-tls1"], timeout=3)
    data["tls10_available_localhost"] = "CONNECTED" in tls10_out

    # Cipher suites SSH
    ssh_ciphers: dict[str, list[str]] = {}
    for field in ["Ciphers", "MACs", "KexAlgorithms"]:
        out, _, rc = _run(["ssh", "-Q", field.lower()])
        ssh_ciphers[field] = out.splitlines() if rc == 0 else []
    data["ssh_available_ciphers"] = ssh_ciphers
    weak_ciphers = [c for c in ssh_ciphers.get("Ciphers", [])
                    if any(w in c for w in ["3des", "rc4", "arcfour", "blowfish", "cast128", "des"])]
    data["ssh_weak_ciphers"] = weak_ciphers

    # Verificar sshd_config Ciphers configurados
    sshd_conf = _file_read("/etc/ssh/sshd_config") or ""
    sshd_d = Path("/etc/ssh/sshd_config.d")
    if sshd_d.exists():
        for f in sorted(sshd_d.iterdir()):
            sshd_conf += "\n" + (_file_read(str(f)) or "")
    ciphers_line = re.search(r"^\s*Ciphers\s+(.+)", sshd_conf, re.IGNORECASE | re.MULTILINE)
    data["sshd_ciphers_configured"] = ciphers_line.group(1) if ciphers_line else None

    # ── SR 4.2 — Confidencialidad en reposo ──
    # LUKS / dm-crypt
    lsblk_out, _, _ = _run(["lsblk", "-o", "NAME,TYPE,FSTYPE,MOUNTPOINT", "--json"])
    crypt_devices: list[str] = []
    if lsblk_out:
        try:
            lsblk_data = json.loads(lsblk_out)
            def find_crypt(devs: list) -> None:
                for dev in devs:
                    if dev.get("type") == "crypt":
                        crypt_devices.append(dev.get("name", ""))
                    find_crypt(dev.get("children", []))
            find_crypt(lsblk_data.get("blockdevices", []))
        except json.JSONDecodeError:
            pass
    data["luks_encrypted_devices"]  = crypt_devices
    data["full_disk_encryption"]     = len(crypt_devices) > 0

    # Permisos archivos sensibles
    sensitive = {
        "/etc/shadow":          "0o640",
        "/etc/passwd":          "0o644",
        "/etc/ssh/sshd_config": "0o600",
        "/etc/gshadow":         "0o640",
        "/root":                "0o700",
        "/etc/sudoers":         "0o440",
    }
    file_perms: dict[str, dict] = {}
    for fpath, expected in sensitive.items():
        try:
            s = os.stat(fpath)
            file_perms[fpath] = {
                "mode":      oct(stat.S_IMODE(s.st_mode)),
                "expected":  expected,
                "owner_uid": s.st_uid,
                "owner_gid": s.st_gid,
            }
        except (FileNotFoundError, PermissionError):
            file_perms[fpath] = {"mode": None, "expected": expected, "error": "not_accessible"}
    data["sensitive_file_permissions"] = file_perms

    # ── SR 4.3 — Uso de criptografía ──
    # Política criptográfica del sistema (Ubuntu 25.10 con update-crypto-policies)
    crypto_policy_out, _, crypto_rc = _run(["update-crypto-policies", "--show"])
    data["crypto_policy"] = crypto_policy_out if crypto_rc == 0 else "not_available"
    # Verificar algoritmos débiles deshabilitados
    # SSL_CTX_set_cipher_list con openssl
    data["ssl_weak_protocol_check"] = {
        "sslv3_disabled":   True,   # En Ubuntu 25.10, SSLv3 está deshabilitado en OpenSSL 3.x
        "tlsv1_check":      crypto_policy_out if crypto_rc == 0 else "manual_check_needed",
    }
    # GPG: verificar si el keyring del sistema usa algoritmos modernos
    gpg_conf = _file_read(str(Path.home() / ".gnupg" / "gpg.conf")) or ""
    data["gpg_strong_digest"] = "SHA512" in gpg_conf or "SHA256" in gpg_conf

    return data


# ─────────────────────────────────────────────
# FR5 — Flujo restringido de datos (RDF)
# SRs: 5.1, 5.2, 5.3, 5.4
# ─────────────────────────────────────────────

def collect_fr5_restricted_dataflow() -> dict:
    data: dict = {}

    # ── SR 5.1 — Segmentación de red ──
    # UFW (frontend de nftables en Ubuntu 25.10)
    ufw_out, _, ufw_rc = _run(["ufw", "status", "verbose"])
    data["ufw"] = {
        "available":         ufw_rc == 0,
        "status":            "active" if "Status: active" in (ufw_out or "") else "inactive",
        "default_incoming":  None,
        "default_outgoing":  None,
        "default_routed":    None,
        "rules_count":       0,
    }
    if ufw_out:
        m_in  = re.search(r"Default:\s+(\w+)\s+\(incoming\)", ufw_out)
        m_out = re.search(r"(\w+)\s+\(outgoing\)", ufw_out)
        m_rt  = re.search(r"(\w+)\s+\(routed\)", ufw_out)
        data["ufw"]["default_incoming"] = m_in.group(1)  if m_in  else None
        data["ufw"]["default_outgoing"] = m_out.group(1) if m_out else None
        data["ufw"]["default_routed"]   = m_rt.group(1)  if m_rt  else None
        data["ufw"]["rules_count"]      = len(re.findall(r"ALLOW|DENY|REJECT|LIMIT", ufw_out))

    # nftables (backend nativo Ubuntu 25.10)
    nft_out, _, nft_rc = _run(["nft", "list", "ruleset"])
    data["nftables"] = {
        "available":     nft_rc == 0,
        "rules_summary": nft_out[:800] if nft_out else None,
        "tables_count":  nft_out.count("table ") if nft_out else 0,
        "chains_count":  nft_out.count("chain ") if nft_out else 0,
    }

    # iptables (compatibilidad, puede ser iptables-nft en Ubuntu 25.10)
    ipt_out, _, ipt_rc = _run(["iptables", "-L", "-n", "--line-numbers"])
    data["iptables"] = {
        "available": ipt_rc == 0,
        "rules":     ipt_out[:500] if ipt_out else None,
    }

    # ── SR 5.2 — Protección de límites de zona ──
    # Verificar reglas de entrada/salida entre zonas (segmentación interna)
    # Comprobar si hay interfaces múltiples (potenciales zonas)
    ip_out, _, _ = _run(["ip", "-j", "addr"])
    interfaces: list[dict] = []
    if ip_out:
        try:
            ifaces = json.loads(ip_out)
            for iface in ifaces:
                interfaces.append({
                    "name":      iface.get("ifname"),
                    "state":     iface.get("operstate"),
                    "flags":     iface.get("flags", []),
                    "addresses": [a.get("local") for a in iface.get("addr_info", [])],
                })
        except json.JSONDecodeError:
            pass
    data["network_interfaces"]   = interfaces
    data["network_interfaces_n"] = len([i for i in interfaces if i["state"] == "UP"])

    # fail2ban (IDS en límites de zona)
    fail2ban_active = _service_active("fail2ban")
    data["fail2ban_active"] = fail2ban_active
    f2b_jails_out, _, _ = _run(["fail2ban-client", "status"])
    f2b_jails = re.findall(r"(\S+)\n", f2b_jails_out) if f2b_jails_out else []
    data["fail2ban_jails"] = len(f2b_jails)

    # ── SR 5.3 — Separación general de red ──
    data["ip_forwarding_enabled"]   = _sysctl("net.ipv4.ip_forward") == "1"
    data["ipv6_forwarding_enabled"] = _sysctl("net.ipv6.conf.all.forwarding") == "1"

    # ── SR 5.4 — Partición de aplicaciones ──
    # Namespaces / contenedores (Docker, LXC, systemd-nspawn)
    docker_active  = _service_active("docker")
    _, _, lxd_rc   = _run(["lxc", "list"])
    data["container_isolation"] = {
        "docker_active":  docker_active,
        "lxd_available":  lxd_rc == 0,
        "systemd_nspawn": Path("/var/lib/machines").exists(),
    }

    return data


# ─────────────────────────────────────────────
# FR6 — Respuesta oportuna a eventos (TRE)
# SRs: 6.1, 6.2
# ─────────────────────────────────────────────

def collect_fr6_event_response() -> dict:
    data: dict = {}

    # ── SR 6.1 — Accesibilidad de los registros de auditoría ──
    data["auditd_active"]      = _service_active("auditd")
    data["auditd_config"]      = Path("/etc/audit/auditd.conf").exists()
    data["auditd_rules_exist"] = (Path("/etc/audit/audit.rules").exists() or
                                   list(Path("/etc/audit/rules.d").glob("*.rules")) if
                                   Path("/etc/audit/rules.d").exists() else False)
    if _is_root():
        rules_out, _, _ = _run(["auditctl", "-l"])
        data["auditd_rules_count"] = len(
            [l for l in (rules_out or "").splitlines()
             if l.startswith("-w") or l.startswith("-a")]
        )
    else:
        data["auditd_rules_count"] = "requires_root"

    # Logging centralizado
    data["syslog_active"]    = _service_active("rsyslog") or _service_active("syslog-ng")
    data["journald_active"]  = _service_active("systemd-journald")
    journald_usage, _, _     = _run(["journalctl", "--disk-usage"])
    data["journald_usage"]   = journald_usage
    data["logrotate_exists"] = Path("/etc/logrotate.conf").exists()

    # ── SR 6.2 — Supervisión continua ──
    # IDS/IPS activos
    ids_tools: dict[str, bool] = {}
    for tool in ["snort", "suricata", "ossec", "wazuh-agent", "aide", "tripwire", "lynis"]:
        _, _, rc = _run(["which", tool])
        ids_tools[tool] = rc == 0
    data["ids_tools_installed"] = ids_tools
    # fail2ban (IPS activo)
    data["fail2ban_active"] = _service_active("fail2ban")
    # Verificar si auditd tiene watch en archivos críticos
    if _is_root():
        rules_out, _, _ = _run(["auditctl", "-l"])
        data["auditd_watches_critical"] = any(
            "/etc/passwd" in r or "/etc/shadow" in r or "/etc/ssh" in r
            for r in (rules_out or "").splitlines()
        )
    else:
        data["auditd_watches_critical"] = "requires_root"

    # NTP (para correlación de eventos — referenciado por SR 2.11)
    timedatectl_out, _, _ = _run(["timedatectl", "show"])
    ntp: dict[str, Optional[str]] = {}
    for p in ["NTP", "NTPSynchronized", "Timezone", "TimeUSec"]:
        m = re.search(rf"^{p}=(.+)", timedatectl_out, re.MULTILINE)
        ntp[p] = m.group(1) if m else None
    data["time_sync"] = ntp

    return data


# ─────────────────────────────────────────────
# FR7 — Disponibilidad de recursos (RA)
# SRs: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6, 7.7, 7.8
# ─────────────────────────────────────────────

def collect_fr7_availability() -> dict:
    data: dict = {}

    # ── SR 7.1 — Protección contra DoS ──
    data["dos_protection"] = {
        "net.ipv4.tcp_syncookies":         _sysctl("net.ipv4.tcp_syncookies"),
        "net.ipv4.tcp_max_syn_backlog":    _sysctl("net.ipv4.tcp_max_syn_backlog"),
        "net.ipv4.tcp_synack_retries":     _sysctl("net.ipv4.tcp_synack_retries"),
        "net.ipv4.tcp_syn_retries":        _sysctl("net.ipv4.tcp_syn_retries"),
        "net.ipv4.tcp_fin_timeout":        _sysctl("net.ipv4.tcp_fin_timeout"),
        "net.core.somaxconn":              _sysctl("net.core.somaxconn"),
        "net.ipv4.tcp_rfc1337":            _sysctl("net.ipv4.tcp_rfc1337"),
    }
    data["tcp_syncookies"] = data["dos_protection"]["net.ipv4.tcp_syncookies"] == "1"

    # ── SR 7.2 — Gestión de recursos ──
    meminfo = _file_read("/proc/meminfo") or ""
    mem_total_m = re.search(r"MemTotal:\s+(\d+)\s+kB", meminfo)
    mem_avail_m = re.search(r"MemAvailable:\s+(\d+)\s+kB", meminfo)
    data["memory"] = {
        "total_kb":     int(mem_total_m.group(1)) if mem_total_m else None,
        "available_kb": int(mem_avail_m.group(1)) if mem_avail_m else None,
    }
    df_out, _, _ = _run(["df", "-h", "--output=target,size,used,avail,pcent"])
    data["disk_usage"] = df_out
    # CPU load
    load_out, _, _ = _run(["uptime"])
    data["uptime"]  = load_out
    # Swap
    swap_out, _, _ = _run(["swapon", "--show", "--noheadings"])
    data["swap_configured"] = bool(swap_out.strip())

    # ── SR 7.3 — Copia de seguridad ──
    backup_tools: dict[str, bool] = {}
    for tool in ["rsync", "borgbackup", "restic", "bacula", "amanda",
                 "duplicati", "timeshift", "deja-dup"]:
        _, _, rc = _run(["which", tool])
        backup_tools[tool] = rc == 0
    data["backup_tools"]      = backup_tools
    data["backup_configured"] = any(backup_tools.values())
    # Timers de cron para backup
    cron_d = Path("/etc/cron.d")
    cron_daily = Path("/etc/cron.daily")
    backup_crons = []
    for cron_dir in [cron_d, cron_daily]:
        if cron_dir.exists():
            for f in cron_dir.iterdir():
                c = _file_read(str(f)) or ""
                if any(tool in c for tool in ["rsync", "restic", "borg", "backup"]):
                    backup_crons.append(f.name)
    data["backup_cron_jobs"] = backup_crons

    # ── SR 7.4 — Recuperación del sistema ──
    recovery_tools: dict[str, bool] = {}
    for tool in ["testdisk", "fsck", "e2fsck", "xfs_repair", "ddrescue"]:
        _, _, rc = _run(["which", tool])
        recovery_tools[tool] = rc == 0
    data["recovery_tools"] = recovery_tools
    # Timeshift (Ubuntu 25.10)
    _, _, ts_rc = _run(["timeshift", "--list"])
    data["timeshift_snapshots"] = ts_rc == 0
    # systemd-boot / GRUB recovery entries
    grub_cfg = _file_read("/boot/grub/grub.cfg") or _file_read("/etc/default/grub") or ""
    data["recovery_boot_entry"] = "recovery" in grub_cfg.lower()

    # ── SR 7.5 — Alimentación de emergencia ──
    # Detectar UPS (NUT - Network UPS Tools)
    nut_active  = _service_active("nut-server") or _service_active("nut-monitor")
    _, _, apc_rc = _run(["apcaccess"])
    data["ups_monitoring"] = {
        "nut_active":    nut_active,
        "apcupsd_active":apc_rc == 0,
    }

    # ── SR 7.6 — Configuración de red y seguridad ──
    # Inventario de configuraciones críticas
    config_files: dict[str, bool] = {
        "/etc/ssh/sshd_config":   Path("/etc/ssh/sshd_config").exists(),
        "/etc/ufw/ufw.conf":      Path("/etc/ufw/ufw.conf").exists(),
        "/etc/audit/auditd.conf": Path("/etc/audit/auditd.conf").exists(),
        "/etc/sysctl.d/":         Path("/etc/sysctl.d").exists(),
        "/etc/apparmor.d/":       Path("/etc/apparmor.d").exists(),
    }
    data["critical_config_files"] = config_files
    # Verificar sysctl.d configs de hardening
    sysctl_hardening = list(Path("/etc/sysctl.d").glob("*hardening*")) if Path("/etc/sysctl.d").exists() else []
    sysctl_99 = _file_read("/etc/sysctl.d/99-sysctl.conf") or ""
    data["sysctl_hardening_files"] = len(sysctl_hardening)
    data["sysctl_custom_count"]    = len(list(Path("/etc/sysctl.d").glob("*.conf"))) if Path("/etc/sysctl.d").exists() else 0

    # ── SR 7.7 — Funcionalidad mínima ──
    # Servicios fallidos
    failed_out, _, _ = _run(["systemctl", "list-units", "--state=failed",
                              "--no-pager", "--plain"])
    failed_svcs = [l.split()[0] for l in failed_out.splitlines()
                   if ".service" in l and "failed" in l]
    data["failed_services"]       = failed_svcs
    data["failed_services_count"] = len(failed_svcs)
    # Servicios habilitados innecesarios (reducir superficie)
    enabled_out, _, _ = _run(["systemctl", "list-unit-files", "--state=enabled",
                               "--type=service", "--no-pager", "--plain"])
    risky_services = ["telnet", "rsh", "rlogin", "ftp", "nfs", "rpcbind",
                      "avahi-daemon", "cups", "bluetooth"]
    data["risky_services_enabled"] = [
        s for s in risky_services if s in (enabled_out or "").lower()
    ]

    # ── SR 7.8 — Inventario de componentes ──
    # Lista de paquetes instalados
    dpkg_out, _, dpkg_rc = _run(["dpkg-query", "-W", "-f=${Package}\t${Version}\t${Status}\n"])
    pkg_count = len(dpkg_out.splitlines()) if dpkg_rc == 0 else 0
    data["installed_packages_count"] = pkg_count
    # Servicios activos (inventario)
    active_out, _, _ = _run(["systemctl", "list-units", "--type=service",
                              "--state=running", "--no-pager", "--plain"])
    active_svcs = [l.split()[0] for l in active_out.splitlines() if ".service" in l]
    data["active_services_count"] = len(active_svcs)
    data["active_services"]       = active_svcs[:20]  # Primeros 20

    return data


# ─────────────────────────────────────────────
# Recolector principal
# ─────────────────────────────────────────────

def run_full_collection() -> dict:
    print("[*] Iniciando recolección IEC 62443-3-3 para Ubuntu 25.10...")

    collection = {
        "meta":                    collect_system_info(),
        "fr1_identification":      collect_fr1_identification(),
        "fr2_use_control":         collect_fr2_use_control(),
        "fr3_integrity":           collect_fr3_integrity(),
        "fr4_confidentiality":     collect_fr4_confidentiality(),
        "fr5_restricted_dataflow": collect_fr5_restricted_dataflow(),
        "fr6_event_response":      collect_fr6_event_response(),
        "fr7_availability":        collect_fr7_availability(),
    }

    meta = collection["meta"]
    print(f"[+] Recolección completada: {meta['collection_timestamp']}")
    print(f"    Hostname : {meta['hostname']}")
    print(f"    OS       : {meta['os_name']} {meta['os_version']}")
    print(f"    Kernel   : {meta['kernel']}")
    print(f"    Root     : {meta['running_as_root']}")
    return collection


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="IEC 62443-3-3 Collector — Ubuntu 25.10"
    )
    parser.add_argument("--output", "-o", default="collection_output.json")
    parser.add_argument("--pretty", "-p", action="store_true")
    args = parser.parse_args()

    result = run_full_collection()
    indent = 2 if args.pretty else None
    Path(args.output).write_text(
        json.dumps(result, indent=indent, default=str), encoding="utf-8"
    )
    print(f"\n[+] Resultados guardados en: {Path(args.output).resolve()}")
