"""
IEC 62443-3-3 Compliance Analyzer
Módulo: analyzer.py
Descripción: Analiza los datos recogidos por collector.py y los mapea
             a los System Requirements (SR) de la norma IEC 62443-3-3.
             Determina el Security Level (SL) alcanzado por cada FR.

Security Levels:
  SL0 — Sin protección
  SL1 — Protección contra errores accidentales
  SL2 — Protección contra atacantes con medios simples (objetivo mínimo recomendado)
  SL3 — Protección contra atacantes con conocimiento específico del sistema
  SL4 — Protección contra atacantes con recursos y motivación extrema
"""

import json
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional


# ─────────────────────────────────────────────
# Estructuras de datos
# ─────────────────────────────────────────────

@dataclass
class CheckResult:
    """Resultado de un check individual sobre un SR."""
    sr_id: str           # Ej: "SR 1.1"
    title: str           # Descripción corta
    status: str          # "pass" | "fail" | "warning" | "unknown"
    sl_contribution: int # Cuánto aporta al SL (0-4)
    detail: str          # Qué se encontró
    remediation: str     # Qué hacer para corregirlo (si falla)


@dataclass
class FRResult:
    """Resultado agregado de un Foundational Requirement completo."""
    fr_id: str           # Ej: "FR1"
    title: str
    checks: list[CheckResult] = field(default_factory=list)
    sl_achieved: int = 0
    compliance_percent: float = 0.0
    status: str = "not_evaluated"


@dataclass
class AnalysisReport:
    """Informe completo de cumplimiento."""
    hostname: str
    os_name: str
    os_version: str
    collection_timestamp: str
    fr_results: list[FRResult] = field(default_factory=list)
    overall_sl: int = 0
    overall_compliance_percent: float = 0.0
    total_checks: int = 0
    passed_checks: int = 0
    failed_checks: int = 0
    warning_checks: int = 0


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _sl_from_checks(checks: list[CheckResult]) -> int:
    """
    Calcula el SL alcanzado para un FR basándose en sus checks.
    El SL es el mínimo nivel que se cumple completamente (no hay gaps).
    """
    if not checks:
        return 0
    # Agrupa checks por nivel SL que contribuyen
    levels = {1: [], 2: [], 3: [], 4: []}
    for check in checks:
        if check.sl_contribution in levels:
            levels[check.sl_contribution].append(check)

    # El SL se alcanza si todos los checks de ese nivel pasan
    for sl in [1, 2, 3, 4]:
        level_checks = levels[sl]
        if not level_checks:
            continue
        failed = [c for c in level_checks if c.status == "fail"]
        if failed:
            return sl - 1  # No se supera este nivel
    return 4


def _compliance_percent(checks: list[CheckResult]) -> float:
    if not checks:
        return 0.0
    passed = sum(1 for c in checks if c.status == "pass")
    return round((passed / len(checks)) * 100, 1)


# ─────────────────────────────────────────────
# Analizadores por FR
# ─────────────────────────────────────────────

def analyze_fr1(fr1: dict) -> FRResult:
    """FR1 — Identificación y autenticación."""
    result = FRResult(fr_id="FR1", title="Identificación y autenticación")
    checks = []

    # ── SR 1.1 SL1: No hay usuarios sin shell válida con UID < 1000 activos ──
    users_with_login = fr1.get("users_with_login", [])
    checks.append(CheckResult(
        sr_id="SR 1.1",
        title="Identificación de usuarios humanos",
        status="pass" if len(users_with_login) > 0 else "warning",
        sl_contribution=1,
        detail=f"Usuarios con acceso interactivo: {[u['username'] for u in users_with_login]}",
        remediation="Revisar que solo existan cuentas necesarias con acceso interactivo.",
    ))

    # ── SR 1.3 SL1: Usuarios con privilegios sudo identificados ──
    sudo_members = fr1.get("sudo_group_members", [])
    checks.append(CheckResult(
        sr_id="SR 1.3",
        title="Gestión de cuentas privilegiadas",
        status="pass" if len(sudo_members) <= 3 else "warning",
        sl_contribution=1,
        detail=f"Miembros del grupo sudo/wheel: {sudo_members}",
        remediation="Minimizar el número de usuarios con acceso sudo. Menos de 3 es recomendable.",
    ))

    # ── SR 1.7 SL1: Política de contraseñas mínima ──
    policy = fr1.get("password_policy", {})
    pass_max = policy.get("PASS_MAX_DAYS")
    sl1_pass = pass_max is not None and pass_max <= 365
    checks.append(CheckResult(
        sr_id="SR 1.7",
        title="Política de contraseñas — caducidad",
        status="pass" if sl1_pass else "fail",
        sl_contribution=1,
        detail=f"PASS_MAX_DAYS={pass_max} (recomendado: ≤90 para SL2, ≤365 para SL1)",
        remediation="Editar /etc/login.defs: PASS_MAX_DAYS 90",
    ))

    # ── SR 1.7 SL2: Política de contraseñas estricta ──
    pam = fr1.get("pam_pwquality", {})
    minlen = pam.get("minlen")
    minclass = pam.get("minclass")
    sl2_pass = (
        pass_max is not None and pass_max <= 90 and
        minlen is not None and minlen >= 12 and
        minclass is not None and minclass >= 3
    )
    checks.append(CheckResult(
        sr_id="SR 1.7",
        title="Política de contraseñas — complejidad",
        status="pass" if sl2_pass else "fail",
        sl_contribution=2,
        detail=f"minlen={minlen}, minclass={minclass}, PASS_MAX_DAYS={pass_max}",
        remediation=(
            "Instalar libpam-pwquality y configurar /etc/security/pwquality.conf:\n"
            "  minlen = 12\n  minclass = 3\n"
            "Además: PASS_MAX_DAYS 90 en /etc/login.defs"
        ),
    ))

    # ── SR 1.8 SL1: SSH no permite contraseñas vacías ──
    ssh = fr1.get("ssh_config", {})
    empty_pw = ssh.get("PermitEmptyPasswords", "no").lower()
    checks.append(CheckResult(
        sr_id="SR 1.8",
        title="SSH — contraseñas vacías prohibidas",
        status="pass" if empty_pw in ("no", "not_set") else "fail",
        sl_contribution=1,
        detail=f"PermitEmptyPasswords={empty_pw}",
        remediation="Añadir a /etc/ssh/sshd_config: PermitEmptyPasswords no",
    ))

    # ── SR 1.8 SL2: SSH usa autenticación por clave, no contraseña ──
    pw_auth = ssh.get("PasswordAuthentication", "yes").lower()
    pubkey = ssh.get("PubkeyAuthentication", "yes").lower()
    sl2_ssh = pw_auth == "no" and pubkey in ("yes", "not_set")
    checks.append(CheckResult(
        sr_id="SR 1.8",
        title="SSH — autenticación por clave pública",
        status="pass" if sl2_ssh else "fail",
        sl_contribution=2,
        detail=f"PasswordAuthentication={pw_auth}, PubkeyAuthentication={pubkey}",
        remediation=(
            "En /etc/ssh/sshd_config:\n"
            "  PasswordAuthentication no\n"
            "  PubkeyAuthentication yes\n"
            "Luego: sudo systemctl restart ssh"
        ),
    ))

    # ── SR 1.8 SL2: SSH prohíbe login directo de root ──
    root_login = ssh.get("PermitRootLogin", "yes").lower()
    checks.append(CheckResult(
        sr_id="SR 1.8",
        title="SSH — login root prohibido",
        status="pass" if root_login in ("no", "prohibit-password", "forced-commands-only") else "fail",
        sl_contribution=2,
        detail=f"PermitRootLogin={root_login}",
        remediation="En /etc/ssh/sshd_config: PermitRootLogin no",
    ))

    # ── SR 1.8 SL3: MFA configurado ──
    mfa = fr1.get("mfa_configured", False)
    checks.append(CheckResult(
        sr_id="SR 1.8",
        title="Autenticación multifactor (MFA)",
        status="pass" if mfa else "fail",
        sl_contribution=3,
        detail=f"MFA detectado: {mfa}",
        remediation=(
            "Instalar pam_google_authenticator o pam_oath:\n"
            "  sudo apt install libpam-google-authenticator\n"
            "Configurar en /etc/pam.d/sshd"
        ),
    ))

    result.checks = checks
    result.sl_achieved = _sl_from_checks(checks)
    result.compliance_percent = _compliance_percent(checks)
    result.status = "evaluated"
    return result


def analyze_fr2(fr2: dict) -> FRResult:
    """FR2 — Control de uso."""
    result = FRResult(fr_id="FR2", title="Control de uso")
    checks = []

    # ── SR 2.1 SL1: sudo configurado (no NOPASSWD libre) ──
    nopasswd = fr2.get("sudoers_nopasswd_entries", False)
    checks.append(CheckResult(
        sr_id="SR 2.1",
        title="Control de privilegios sudo",
        status="warning" if nopasswd else "pass",
        sl_contribution=1,
        detail=f"Entradas NOPASSWD en sudoers: {nopasswd}",
        remediation="Revisar /etc/sudoers y /etc/sudoers.d/. Eliminar NOPASSWD salvo casos justificados.",
    ))

    # ── SR 2.1 SL2: AppArmor activo con perfiles en enforce ──
    aa = fr2.get("apparmor", {})
    aa_ok = aa.get("available", False) and aa.get("profiles_enforce", 0) > 0
    checks.append(CheckResult(
        sr_id="SR 2.1",
        title="AppArmor activo y en modo enforce",
        status="pass" if aa_ok else "fail",
        sl_contribution=2,
        detail=f"Disponible: {aa.get('available')}, perfiles enforce: {aa.get('profiles_enforce', 0)}",
        remediation=(
            "sudo systemctl enable --now apparmor\n"
            "sudo aa-enforce /etc/apparmor.d/*"
        ),
    ))

    # ── SR 2.6 SL1: Tiempo de sesión inactiva configurado ──
    timeout = fr2.get("session_timeout_seconds")
    checks.append(CheckResult(
        sr_id="SR 2.6",
        title="Timeout de sesión inactiva",
        status="pass" if timeout and timeout <= 900 else "fail",
        sl_contribution=1,
        detail=f"TMOUT={timeout}s (recomendado: ≤900s / 15 min)",
        remediation="Añadir a /etc/profile o /etc/bash.bashrc: export TMOUT=900",
    ))

    # ── SR 2.6 SL2: SSH MaxAuthTries limitado ──
    # (datos vienen de fr1 pero relacionado con FR2 control de uso)
    ports = fr2.get("listening_ports_count", 0)
    checks.append(CheckResult(
        sr_id="SR 2.6",
        title="Superficie de ataque — puertos expuestos",
        status="pass" if ports <= 5 else "warning",
        sl_contribution=2,
        detail=f"Puertos en escucha: {ports} (recomendado: ≤5 para servidores de propósito específico)",
        remediation="Deshabilitar servicios no necesarios: sudo systemctl disable <servicio>",
    ))

    # ── SR 2.7 SL2: Servicios remotos mínimos ──
    remote_svcs = fr2.get("active_remote_services", [])
    dangerous = [s for s in remote_svcs if s in ("telnet", "rsh", "rlogin")]
    checks.append(CheckResult(
        sr_id="SR 2.7",
        title="Protocolos remotos inseguros deshabilitados",
        status="fail" if dangerous else "pass",
        sl_contribution=2,
        detail=f"Servicios remotos activos: {remote_svcs}, peligrosos: {dangerous}",
        remediation="sudo systemctl disable --now telnet rsh rlogin",
    ))

    result.checks = checks
    result.sl_achieved = _sl_from_checks(checks)
    result.compliance_percent = _compliance_percent(checks)
    result.status = "evaluated"
    return result


def analyze_fr3(fr3: dict) -> FRResult:
    """FR3 — Integridad del sistema."""
    result = FRResult(fr_id="FR3", title="Integridad del sistema")
    checks = []

    # ── SR 3.2 SL1: Herramienta antimalware instalada ──
    tools = fr3.get("security_tools", {})
    has_av = any(v.get("installed") for k, v in tools.items() if k in ("clamav", "clamd"))
    checks.append(CheckResult(
        sr_id="SR 3.2",
        title="Antimalware instalado",
        status="pass" if has_av else "fail",
        sl_contribution=1,
        detail=f"ClamAV instalado: {has_av}",
        remediation="sudo apt install clamav clamav-daemon && sudo freshclam",
    ))

    # ── SR 3.3 SL2: AIDE o similar para integridad de archivos ──
    aide = fr3.get("aide_configured", False)
    has_tripwire = tools.get("tripwire", {}).get("installed", False)
    has_aide = tools.get("aide", {}).get("installed", False)
    integrity_ok = aide or has_tripwire or has_aide
    checks.append(CheckResult(
        sr_id="SR 3.3",
        title="Monitor de integridad de archivos (AIDE/Tripwire)",
        status="pass" if integrity_ok else "fail",
        sl_contribution=2,
        detail=f"AIDE instalado: {has_aide}, configurado: {aide}, Tripwire: {has_tripwire}",
        remediation=(
            "sudo apt install aide\n"
            "sudo aideinit\n"
            "sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db"
        ),
    ))

    # ── SR 3.3 SL2: Rootkit detection ──
    has_rkhunter = tools.get("rkhunter", {}).get("installed", False)
    has_chkrootkit = tools.get("chkrootkit", {}).get("installed", False)
    checks.append(CheckResult(
        sr_id="SR 3.3",
        title="Detección de rootkits",
        status="pass" if (has_rkhunter or has_chkrootkit) else "fail",
        sl_contribution=2,
        detail=f"rkhunter: {has_rkhunter}, chkrootkit: {has_chkrootkit}",
        remediation="sudo apt install rkhunter && sudo rkhunter --update",
    ))

    # ── SR 3.4 SL1: Paquetes sin autenticación no permitidos ──
    unauth = fr3.get("apt_unauthenticated_allowed", False)
    checks.append(CheckResult(
        sr_id="SR 3.4",
        title="Verificación de firma en paquetes APT",
        status="fail" if unauth else "pass",
        sl_contribution=1,
        detail=f"AllowUnauthenticated habilitado: {unauth}",
        remediation="Revisar /etc/apt/apt.conf.d/ y eliminar líneas con AllowUnauthenticated true",
    ))

    # ── SR 3.3 SL2: ASLR activado ──
    kernel = fr3.get("kernel_hardening", {})
    aslr = kernel.get("kernel.randomize_va_space")
    checks.append(CheckResult(
        sr_id="SR 3.3",
        title="ASLR (aleatorización de memoria) activado",
        status="pass" if aslr == "2" else "fail",
        sl_contribution=2,
        detail=f"kernel.randomize_va_space={aslr} (debe ser 2)",
        remediation="sudo sysctl -w kernel.randomize_va_space=2\nPersistir en /etc/sysctl.d/99-hardening.conf",
    ))

    # ── SR 3.3 SL2: Protecciones kernel adicionales ──
    dmesg = kernel.get("kernel.dmesg_restrict")
    kptr = kernel.get("kernel.kptr_restrict")
    kernel_ok = dmesg == "1" and kptr in ("1", "2")
    checks.append(CheckResult(
        sr_id="SR 3.3",
        title="Restricciones de información del kernel",
        status="pass" if kernel_ok else "fail",
        sl_contribution=2,
        detail=f"dmesg_restrict={dmesg}, kptr_restrict={kptr}",
        remediation=(
            "En /etc/sysctl.d/99-hardening.conf:\n"
            "  kernel.dmesg_restrict = 1\n"
            "  kernel.kptr_restrict = 2"
        ),
    ))

    # ── SR 3.4 SL3: Secure Boot activo ──
    sb = fr3.get("secure_boot", {})
    sb_enabled = sb.get("available") and "enabled" in (sb.get("state") or "").lower()
    checks.append(CheckResult(
        sr_id="SR 3.4",
        title="Secure Boot habilitado",
        status="pass" if sb_enabled else "warning",
        sl_contribution=3,
        detail=f"Secure Boot: {sb.get('state', 'no disponible')}",
        remediation="Habilitar Secure Boot en la BIOS/UEFI del sistema.",
    ))

    result.checks = checks
    result.sl_achieved = _sl_from_checks(checks)
    result.compliance_percent = _compliance_percent(checks)
    result.status = "evaluated"
    return result


def analyze_fr4(fr4: dict) -> FRResult:
    """FR4 — Confidencialidad de datos."""
    result = FRResult(fr_id="FR4", title="Confidencialidad de datos")
    checks = []

    # ── SR 4.1 SL1: OpenSSL moderno instalado ──
    openssl_ver = fr4.get("openssl_version", "")
    modern_openssl = any(v in openssl_ver for v in ["3.", "1.1.1"])
    checks.append(CheckResult(
        sr_id="SR 4.1",
        title="Versión de OpenSSL moderna",
        status="pass" if modern_openssl else "fail",
        sl_contribution=1,
        detail=f"OpenSSL: {openssl_ver}",
        remediation="sudo apt update && sudo apt upgrade openssl",
    ))

    # ── SR 4.1 SL2: Algoritmos SSH seguros ──
    ciphers = fr4.get("ssh_available_ciphers", {})
    cipher_list = ciphers.get("Ciphers", [])
    weak_ciphers = [c for c in cipher_list if any(
        w in c for w in ["3des", "rc4", "arcfour", "blowfish", "cast128", "des"]
    )]
    checks.append(CheckResult(
        sr_id="SR 4.1",
        title="Algoritmos de cifrado SSH — sin cifrados débiles",
        status="fail" if weak_ciphers else "pass",
        sl_contribution=2,
        detail=f"Cifrados débiles disponibles: {weak_ciphers[:5]}",
        remediation=(
            "En /etc/ssh/sshd_config añadir:\n"
            "  Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com\n"
            "  MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com"
        ),
    ))

    # ── SR 4.2 SL2: Cifrado en reposo (LUKS) ──
    luks = fr4.get("full_disk_encryption", False)
    checks.append(CheckResult(
        sr_id="SR 4.2",
        title="Cifrado de disco completo (LUKS)",
        status="pass" if luks else "fail",
        sl_contribution=2,
        detail=f"Dispositivos LUKS detectados: {fr4.get('luks_encrypted_devices', [])}",
        remediation=(
            "Para nuevas instalaciones: seleccionar cifrado de disco en el instalador de Ubuntu.\n"
            "Para sistemas existentes: usar cryptsetup para cifrar particiones de datos."
        ),
    ))

    # ── SR 4.2 SL1: Permisos de /etc/shadow correctos ──
    perms = fr4.get("sensitive_file_permissions", {})
    shadow_perm = perms.get("/etc/shadow", {})
    shadow_mode = shadow_perm.get("mode", "")
    shadow_ok = shadow_mode in ("0o0", "0o640", "0o600", "0o400")
    checks.append(CheckResult(
        sr_id="SR 4.2",
        title="Permisos de /etc/shadow restrictivos",
        status="pass" if shadow_ok else "fail",
        sl_contribution=1,
        detail=f"Permisos /etc/shadow: {shadow_mode} (esperado: 0o640 o más restrictivo)",
        remediation="sudo chmod 640 /etc/shadow && sudo chown root:shadow /etc/shadow",
    ))

    # ── SR 4.2 SL2: Permisos de sshd_config correctos ──
    sshd_perm = perms.get("/etc/ssh/sshd_config", {})
    sshd_mode = sshd_perm.get("mode", "")
    sshd_ok = sshd_mode in ("0o600", "0o644", "0o640")
    checks.append(CheckResult(
        sr_id="SR 4.2",
        title="Permisos de sshd_config restrictivos",
        status="pass" if sshd_ok else "fail",
        sl_contribution=2,
        detail=f"Permisos /etc/ssh/sshd_config: {sshd_mode}",
        remediation="sudo chmod 600 /etc/ssh/sshd_config",
    ))

    result.checks = checks
    result.sl_achieved = _sl_from_checks(checks)
    result.compliance_percent = _compliance_percent(checks)
    result.status = "evaluated"
    return result


def analyze_fr5(fr5: dict) -> FRResult:
    """FR5 — Flujo restringido de datos."""
    result = FRResult(fr_id="FR5", title="Flujo restringido de datos")
    checks = []

    # ── SR 5.1 SL1: Firewall activo ──
    ufw = fr5.get("ufw", {})
    ipt = fr5.get("iptables", {})
    nft = fr5.get("nftables", {})
    firewall_active = (
        ufw.get("status") == "active" or
        (ipt.get("available") and ipt.get("rules")) or
        (nft.get("available") and nft.get("rules"))
    )
    checks.append(CheckResult(
        sr_id="SR 5.1",
        title="Firewall activo",
        status="pass" if firewall_active else "fail",
        sl_contribution=1,
        detail=f"UFW={ufw.get('status')}, iptables={ipt.get('available')}, nftables={nft.get('available')}",
        remediation="sudo ufw enable && sudo ufw default deny incoming && sudo ufw default allow outgoing",
    ))

    # ── SR 5.1 SL2: Política por defecto deny incoming ──
    default_in = ufw.get("default_incoming", "")
    deny_by_default = default_in and default_in.lower() in ("deny", "reject")
    checks.append(CheckResult(
        sr_id="SR 5.1",
        title="Política firewall: denegar tráfico entrante por defecto",
        status="pass" if deny_by_default else "fail",
        sl_contribution=2,
        detail=f"UFW default incoming: {default_in}",
        remediation="sudo ufw default deny incoming",
    ))

    # ── SR 5.3 SL1: IP forwarding desactivado ──
    ip_fwd = fr5.get("ip_forwarding_enabled", True)
    checks.append(CheckResult(
        sr_id="SR 5.3",
        title="IP forwarding desactivado",
        status="pass" if not ip_fwd else "fail",
        sl_contribution=1,
        detail=f"net.ipv4.ip_forward={'1 (ACTIVO)' if ip_fwd else '0 (desactivado)'}",
        remediation=(
            "sudo sysctl -w net.ipv4.ip_forward=0\n"
            "Persistir en /etc/sysctl.d/99-hardening.conf: net.ipv4.ip_forward = 0"
        ),
    ))

    # ── SR 5.1 SL2: Reglas UFW definidas ──
    rules = ufw.get("rules_count", 0)
    checks.append(CheckResult(
        sr_id="SR 5.1",
        title="Reglas de firewall definidas",
        status="pass" if rules >= 2 else "warning",
        sl_contribution=2,
        detail=f"Número de reglas UFW: {rules}",
        remediation=(
            "Definir reglas explícitas, por ejemplo:\n"
            "  sudo ufw allow 22/tcp\n"
            "  sudo ufw deny 23/tcp"
        ),
    ))

    result.checks = checks
    result.sl_achieved = _sl_from_checks(checks)
    result.compliance_percent = _compliance_percent(checks)
    result.status = "evaluated"
    return result


def analyze_fr6(fr6: dict) -> FRResult:
    """FR6 — Respuesta oportuna a eventos."""
    result = FRResult(fr_id="FR6", title="Respuesta oportuna a eventos")
    checks = []

    # ── SR 6.1 SL1: auditd instalado ──
    auditd = fr6.get("auditd", {})
    checks.append(CheckResult(
        sr_id="SR 6.1",
        title="auditd instalado y activo",
        status="pass" if auditd.get("service_active") else "fail",
        sl_contribution=1,
        detail=f"auditd activo: {auditd.get('service_active')}, config: {auditd.get('config_exists')}",
        remediation="sudo apt install auditd audispd-plugins && sudo systemctl enable --now auditd",
    ))

    # ── SR 6.1 SL2: Reglas de auditoría configuradas ──
    rules_count = auditd.get("active_rules_count", 0)
    has_rules = isinstance(rules_count, int) and rules_count >= 5
    checks.append(CheckResult(
        sr_id="SR 6.1",
        title="Reglas de auditoría definidas",
        status="pass" if has_rules else "fail",
        sl_contribution=2,
        detail=f"Reglas activas: {rules_count} (mínimo recomendado: 5)",
        remediation=(
            "Añadir reglas en /etc/audit/rules.d/hardening.rules:\n"
            "  -w /etc/passwd -p wa -k identity\n"
            "  -w /etc/shadow -p wa -k identity\n"
            "  -w /etc/sudoers -p wa -k sudoers\n"
            "  -a always,exit -F arch=b64 -S execve -k exec_commands\n"
            "  -w /var/log/auth.log -p wa -k auth_log"
        ),
    ))

    # ── SR 6.1 SL1: syslog activo ──
    syslog = fr6.get("syslog", {})
    syslog_ok = syslog.get("rsyslog_active") or syslog.get("syslog_ng_active")
    checks.append(CheckResult(
        sr_id="SR 6.1",
        title="Sistema de logging activo (rsyslog/syslog-ng)",
        status="pass" if syslog_ok else "fail",
        sl_contribution=1,
        detail=f"rsyslog: {syslog.get('rsyslog_active')}, syslog-ng: {syslog.get('syslog_ng_active')}",
        remediation="sudo apt install rsyslog && sudo systemctl enable --now rsyslog",
    ))

    # ── SR 6.1 SL2: Logrotate configurado ──
    logrotate = fr6.get("logrotate_configured", False)
    checks.append(CheckResult(
        sr_id="SR 6.1",
        title="Rotación de logs configurada",
        status="pass" if logrotate else "fail",
        sl_contribution=2,
        detail=f"Logrotate: {logrotate}",
        remediation="sudo apt install logrotate && verificar /etc/logrotate.conf",
    ))

    # ── SR 6.2 SL1: NTP sincronizado (crítico para correlación de eventos) ──
    time_sync = fr6.get("time_sync", {})
    ntp_sync = time_sync.get("NTPSynchronized", "no")
    checks.append(CheckResult(
        sr_id="SR 6.2",
        title="Sincronización horaria NTP activa",
        status="pass" if ntp_sync == "yes" else "fail",
        sl_contribution=1,
        detail=f"NTPSynchronized={ntp_sync}, Timezone={time_sync.get('Timezone')}",
        remediation=(
            "sudo apt install systemd-timesyncd\n"
            "sudo timedatectl set-ntp true\n"
            "Verificar: timedatectl status"
        ),
    ))

    result.checks = checks
    result.sl_achieved = _sl_from_checks(checks)
    result.compliance_percent = _compliance_percent(checks)
    result.status = "evaluated"
    return result


def analyze_fr7(fr7: dict) -> FRResult:
    """FR7 — Disponibilidad de recursos."""
    result = FRResult(fr_id="FR7", title="Disponibilidad de recursos")
    checks = []

    # ── SR 7.1 SL1: SYN cookies activadas ──
    syn_cookies = fr7.get("tcp_syncookies", False)
    checks.append(CheckResult(
        sr_id="SR 7.1",
        title="Protección SYN flood (TCP SYN cookies)",
        status="pass" if syn_cookies else "fail",
        sl_contribution=1,
        detail=f"net.ipv4.tcp_syncookies={'1 (activo)' if syn_cookies else '0 (inactivo)'}",
        remediation=(
            "sudo sysctl -w net.ipv4.tcp_syncookies=1\n"
            "Persistir: echo 'net.ipv4.tcp_syncookies = 1' >> /etc/sysctl.d/99-hardening.conf"
        ),
    ))

    # ── SR 7.2 SL1: Memoria disponible suficiente ──
    mem = fr7.get("memory", {})
    total_kb = mem.get("total_kb", 0) or 0
    avail_kb = mem.get("available_kb", 0) or 0
    mem_pct = (avail_kb / total_kb * 100) if total_kb > 0 else 0
    checks.append(CheckResult(
        sr_id="SR 7.2",
        title="Memoria disponible suficiente (>20%)",
        status="pass" if mem_pct >= 20 else "warning",
        sl_contribution=1,
        detail=f"Memoria disponible: {avail_kb // 1024}MB de {total_kb // 1024}MB ({mem_pct:.1f}%)",
        remediation="Revisar procesos consumiendo memoria: top -o %MEM",
    ))

    # ── SR 7.3 SL2: Herramienta de backup instalada ──
    backup = fr7.get("backup_configured", False)
    backup_tools = [k for k, v in fr7.get("backup_tools", {}).items() if v]
    checks.append(CheckResult(
        sr_id="SR 7.3",
        title="Herramienta de backup configurada",
        status="pass" if backup else "fail",
        sl_contribution=2,
        detail=f"Herramientas detectadas: {backup_tools if backup_tools else 'ninguna'}",
        remediation=(
            "sudo apt install restic\n"
            "Configurar backup periódico con cron o systemd timer"
        ),
    ))

    # ── SR 7.7 SL1: Sin servicios fallidos ──
    failed = fr7.get("failed_services_count", 0)
    checks.append(CheckResult(
        sr_id="SR 7.7",
        title="Sin servicios críticos en estado fallido",
        status="pass" if failed == 0 else "fail",
        sl_contribution=1,
        detail=f"Servicios fallidos: {failed} — {fr7.get('failed_services', [])}",
        remediation="Revisar: sudo systemctl list-units --state=failed\nsudo journalctl -xe",
    ))

    result.checks = checks
    result.sl_achieved = _sl_from_checks(checks)
    result.compliance_percent = _compliance_percent(checks)
    result.status = "evaluated"
    return result


# ─────────────────────────────────────────────
# Analizador principal
# ─────────────────────────────────────────────

def analyze(collection: dict) -> AnalysisReport:
    """
    Recibe el output del collector y produce el informe de cumplimiento completo.
    """
    meta = collection.get("meta", {})

    report = AnalysisReport(
        hostname=meta.get("hostname", "unknown"),
        os_name=meta.get("os_name", "unknown"),
        os_version=meta.get("os_version", "unknown"),
        collection_timestamp=meta.get("collection_timestamp", ""),
    )

    analyzer_map = {
        "fr1_identification": analyze_fr1,
        "fr2_use_control":    analyze_fr2,
        "fr3_integrity":      analyze_fr3,
        "fr4_confidentiality": analyze_fr4,
        "fr5_restricted_dataflow": analyze_fr5,
        "fr6_event_response": analyze_fr6,
        "fr7_availability":   analyze_fr7,
    }

    for key, fn in analyzer_map.items():
        if key in collection:
            fr_result = fn(collection[key])
            report.fr_results.append(fr_result)

    # Totales
    all_checks = [c for fr in report.fr_results for c in fr.checks]
    report.total_checks = len(all_checks)
    report.passed_checks = sum(1 for c in all_checks if c.status == "pass")
    report.failed_checks = sum(1 for c in all_checks if c.status == "fail")
    report.warning_checks = sum(1 for c in all_checks if c.status == "warning")

    # SL global: el mínimo de todos los FR (el peor es el cuello de botella)
    if report.fr_results:
        report.overall_sl = min(fr.sl_achieved for fr in report.fr_results)
        report.overall_compliance_percent = round(
            sum(fr.compliance_percent for fr in report.fr_results) / len(report.fr_results), 1
        )

    return report


def print_summary(report: AnalysisReport) -> None:
    """Imprime un resumen en consola del análisis."""
    STATUS_ICON = {"pass": "✓", "fail": "✗", "warning": "⚠", "unknown": "?"}
    SL_LABEL = {0: "SL0 (sin protección)", 1: "SL1 (accidental)", 2: "SL2 (intencional simple)",
                3: "SL3 (sofisticado)", 4: "SL4 (avanzado)"}

    print("\n" + "═" * 60)
    print("  IEC 62443-3-3 — INFORME DE CUMPLIMIENTO")
    print("═" * 60)
    print(f"  Host     : {report.hostname}")
    print(f"  OS       : {report.os_name} {report.os_version}")
    print(f"  Timestamp: {report.collection_timestamp}")
    print("─" * 60)
    print(f"  Security Level global : {SL_LABEL.get(report.overall_sl, str(report.overall_sl))}")
    print(f"  Cumplimiento global   : {report.overall_compliance_percent}%")
    print(f"  Checks: {report.passed_checks} ✓  {report.failed_checks} ✗  {report.warning_checks} ⚠  (total: {report.total_checks})")
    print("─" * 60)

    for fr in report.fr_results:
        sl_str = SL_LABEL.get(fr.sl_achieved, str(fr.sl_achieved))
        print(f"\n  [{fr.fr_id}] {fr.title}")
        print(f"       SL alcanzado: {sl_str} | Cumplimiento: {fr.compliance_percent}%")
        for check in fr.checks:
            icon = STATUS_ICON.get(check.status, "?")
            print(f"    {icon} {check.sr_id} — {check.title}")
            if check.status in ("fail", "warning"):
                print(f"        ↳ {check.detail}")
                print(f"        ✎ {check.remediation.splitlines()[0]}")

    print("\n" + "═" * 60)


# ─────────────────────────────────────────────
# Punto de entrada
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="IEC 62443-3-3 Analyzer — Analiza los datos del collector y genera informe"
    )
    parser.add_argument(
        "--input", "-i",
        default="collection_output.json",
        help="Archivo JSON de entrada (output del collector)"
    )
    parser.add_argument(
        "--output", "-o",
        default="analysis_report.json",
        help="Archivo JSON de salida con el informe"
    )
    parser.add_argument(
        "--summary", "-s",
        action="store_true",
        help="Mostrar resumen en consola"
    )
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"[!] Archivo no encontrado: {input_path}")
        print("    Ejecuta primero: sudo python3 collector.py --output collection_output.json")
        exit(1)

    collection = json.loads(input_path.read_text(encoding="utf-8"))
    report = analyze(collection)

    if args.summary:
        print_summary(report)

    output_path = Path(args.output)
    output_path.write_text(
        json.dumps(asdict(report), indent=2, default=str),
        encoding="utf-8"
    )
    print(f"\n[+] Informe guardado en: {output_path.resolve()}")
