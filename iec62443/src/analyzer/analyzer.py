"""
IEC 62443-3-3 Compliance Analyzer
Módulo: analyzer.py  — Versión adaptada Ubuntu 25.10
Norma:  UNE-EN IEC 62443-3-3:2020

Mapeo normativo corregido:
  FR1 (IAC): SR 1.1, 1.2, 1.3, 1.4, 1.5, 1.7, 1.8, 1.9, 1.10, 1.11, 1.12, 1.13
  FR2 (UC):  SR 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 2.8, 2.9, 2.10, 2.11, 2.12
  FR3 (SI):  SR 3.1, 3.2, 3.3, 3.4, 3.5, 3.7, 3.9
  FR4 (DC):  SR 4.1, 4.2, 4.3
  FR5 (RDF): SR 5.1, 5.2, 5.3, 5.4
  FR6 (TRE): SR 6.1, 6.2
  FR7 (RA):  SR 7.1, 7.2, 7.3, 7.4, 7.6, 7.7, 7.8

SL-C por SR según la norma (tabla normativa §5-11):
  SL1 = requisito base del SR
  SL2 = SR + RE (1)  (mejora del requisito 1)
  SL3 = SR + RE (1) (2)
  SL4 = SR + RE (1) (2) (3)
  "No seleccionado" en un SL = el SR no aplica a ese nivel
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
    sr_id:           str
    title:           str
    status:          str    # "pass" | "fail" | "warning" | "not_applicable"
    sl_contribution: int    # SL mínimo que este check habilita (1-4)
    detail:          str
    remediation:     str


@dataclass
class FRResult:
    fr_id:               str
    title:               str
    checks:              list[CheckResult] = field(default_factory=list)
    sl_achieved:         int   = 0
    compliance_percent:  float = 0.0
    status:              str   = "not_evaluated"


@dataclass
class AnalysisReport:
    hostname:                  str
    os_name:                   str
    os_version:                str
    collection_timestamp:      str
    fr_results:                list[FRResult] = field(default_factory=list)
    overall_sl:                int   = 0
    overall_compliance_percent:float = 0.0
    total_checks:              int   = 0
    passed_checks:             int   = 0
    failed_checks:             int   = 0
    warning_checks:            int   = 0


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _sl_from_checks(checks: list[CheckResult]) -> int:
    """
    El SL se alcanza cuando TODOS los checks de ese nivel pasan.
    Un solo fallo en SL-n impide alcanzar SL-n y superiores.
    Conforme a la tabla normativa §4.1 de la IEC 62443-3-3.
    """
    if not checks:
        return 0
    levels: dict[int, list[CheckResult]] = {1: [], 2: [], 3: [], 4: []}
    for c in checks:
        if c.sl_contribution in levels:
            levels[c.sl_contribution].append(c)

    for sl in [1, 2, 3, 4]:
        lvl_checks = levels[sl]
        if not lvl_checks:
            continue  # No hay checks para este SL → no bloquea
        if any(c.status == "fail" for c in lvl_checks):
            return sl - 1
    return 4


def _compliance_percent(checks: list[CheckResult]) -> float:
    applicable = [c for c in checks if c.status != "not_applicable"]
    if not applicable:
        return 0.0
    passed = sum(1 for c in applicable if c.status == "pass")
    return round((passed / len(applicable)) * 100, 1)


# ─────────────────────────────────────────────
# FR1 — Control de identificación y autenticación (IAC)
# Norma §5 — SRs 1.1 a 1.13
# ─────────────────────────────────────────────

def analyze_fr1(fr1: dict) -> FRResult:
    result = FRResult(fr_id="FR1", title="Control de identificación y autenticación")
    checks = []

    # ── SR 1.1 SL1 — Identificación y autenticación de usuarios humanos ──
    # Norma: el SC debe identificar y autenticar a todos los usuarios humanos
    users_with_login = fr1.get("users_with_login", [])
    checks.append(CheckResult(
        sr_id="SR 1.1",
        title="Identificación de usuarios con acceso interactivo",
        status="pass" if len(users_with_login) > 0 else "warning",
        sl_contribution=1,
        detail=f"Usuarios con shell de login: {[u['username'] for u in users_with_login]}",
        remediation="Revisar que únicamente existan cuentas necesarias con acceso interactivo.",
    ))

    # ── SR 1.1 RE1 SL2 — Identificación y autenticación únicas ──
    # Norma §5.3.3.1: el SC debe identificar y autenticar de manera única
    dup_uids = fr1.get("duplicate_uids", {})
    checks.append(CheckResult(
        sr_id="SR 1.1 RE1",
        title="Unicidad de identificadores (sin UIDs duplicados)",
        status="fail" if dup_uids else "pass",
        sl_contribution=2,
        detail=f"UIDs duplicados detectados: {dup_uids}" if dup_uids else "Sin UIDs duplicados",
        remediation="Asignar UIDs únicos: usermod -u <nuevo_uid> <usuario>",
    ))

    # ── SR 1.1 RE2 SL3 — MFA para redes no confiables ──
    # Norma §5.3.3.2: autenticación multifactor para redes no confiables
    mfa = fr1.get("mfa_configured", False)
    checks.append(CheckResult(
        sr_id="SR 1.1 RE2",
        title="Autenticación multifactor (MFA) para acceso remoto",
        status="pass" if mfa else "fail",
        sl_contribution=3,
        detail=f"MFA configurado: {fr1.get('mfa_module_detected', 'ninguno')}",
        remediation=(
            "Instalar pam_google_authenticator:\n"
            "  sudo apt install libpam-google-authenticator\n"
            "Configurar en /etc/pam.d/sshd y habilitar ChallengeResponseAuthentication"
        ),
    ))

    # ── SR 1.2 SL2 — Identificación y autenticación de procesos de software ──
    # Norma §5.4: no seleccionado para SL1, requerido desde SL2
    # En Ubuntu: servicios con usuarios propios, no ejecutar como root
    service_accounts_active = fr1.get("service_accounts_active", [])
    checks.append(CheckResult(
        sr_id="SR 1.2",
        title="Cuentas de servicio con identidad propia (no root)",
        status="warning" if len(service_accounts_active) > 3 else "pass",
        sl_contribution=2,
        detail=f"Cuentas de sistema sin bloquear: {service_accounts_active}",
        remediation=(
            "Bloquear cuentas de servicio no interactivas:\n"
            "  sudo usermod -L -s /usr/sbin/nologin <cuenta_servicio>"
        ),
    ))

    # ── SR 1.3 SL1 — Gestión de cuentas ──
    # Norma §5.5: añadir, activar, modificar, desactivar y eliminar cuentas
    sudo_members = fr1.get("sudo_group_members", [])
    checks.append(CheckResult(
        sr_id="SR 1.3",
        title="Gestión de cuentas privilegiadas (grupo sudo acotado)",
        status="pass" if len(sudo_members) <= 3 else "warning",
        sl_contribution=1,
        detail=f"Miembros del grupo sudo: {sudo_members}",
        remediation="Reducir el número de usuarios con privilegios sudo. Máximo recomendado: 3.",
    ))

    # ── SR 1.3 RE1 SL3 — Gestión de cuentas unificada ──
    # Norma §5.5.3.1: gestión centralizada de cuentas
    no_pw = fr1.get("no_password_accounts", [])
    checks.append(CheckResult(
        sr_id="SR 1.3 RE1",
        title="Sin cuentas sin contraseña (gestión unificada)",
        status="fail" if no_pw else "pass",
        sl_contribution=3,
        detail=f"Cuentas sin contraseña: {no_pw}",
        remediation="sudo passwd -l <usuario> para bloquear cuentas sin contraseña",
    ))

    # ── SR 1.4 SL1 — Gestión de identificadores ──
    # Norma §5.6: gestión de identificadores por usuario, grupo, rol
    locked = fr1.get("locked_accounts", [])
    checks.append(CheckResult(
        sr_id="SR 1.4",
        title="Gestión de identificadores — cuentas inactivas bloqueadas",
        status="pass" if locked else "warning",
        sl_contribution=1,
        detail=f"Cuentas bloqueadas detectadas: {len(locked)}",
        remediation="Bloquear cuentas inactivas: sudo usermod -L <usuario>",
    ))

    # ── SR 1.5 SL1 — Gestión de autenticadores ──
    # Norma §5.7: cambiar contraseñas predeterminadas, proteger autenticadores
    policy = fr1.get("password_policy", {})
    pass_max = policy.get("PASS_MAX_DAYS")
    pass_warn = policy.get("PASS_WARN_AGE")
    sl1_pass = pass_max is not None and pass_max <= 365 and pass_warn is not None and pass_warn >= 7
    checks.append(CheckResult(
        sr_id="SR 1.5",
        title="Gestión de autenticadores — caducidad y aviso de contraseña",
        status="pass" if sl1_pass else "fail",
        sl_contribution=1,
        detail=f"PASS_MAX_DAYS={pass_max}, PASS_WARN_AGE={pass_warn}",
        remediation="En /etc/login.defs: PASS_MAX_DAYS 90 | PASS_WARN_AGE 14",
    ))

    # ── SR 1.7 SL1 — Fortaleza contraseña (base) ──
    # Norma §5.9: longitud mínima y variedad de tipos
    pam = fr1.get("pam_pwquality", {})
    minlen = pam.get("minlen")
    sl1_pwq = minlen is not None and minlen >= 8
    checks.append(CheckResult(
        sr_id="SR 1.7",
        title="Fortaleza de contraseña — longitud mínima (≥8)",
        status="pass" if sl1_pwq else "fail",
        sl_contribution=1,
        detail=f"pam_pwquality minlen={minlen}",
        remediation=(
            "sudo apt install libpam-pwquality\n"
            "En /etc/security/pwquality.conf: minlen = 12"
        ),
    ))

    # ── SR 1.7 RE1 SL3 — Historial y caducidad mínima/máxima ──
    # Norma §5.9.3.1: evitar reutilización, restricciones de vigencia
    pass_min = policy.get("PASS_MIN_DAYS")
    minclass = pam.get("minclass")
    history  = fr1.get("password_history_count", 0)
    sl3_pwq  = (
        pass_max is not None and pass_max <= 90 and
        pass_min is not None and pass_min >= 1  and
        minlen   is not None and minlen >= 12   and
        minclass is not None and minclass >= 3  and
        history >= 5
    )
    checks.append(CheckResult(
        sr_id="SR 1.7 RE1",
        title="Historial, complejidad y caducidad de contraseñas (RE1)",
        status="pass" if sl3_pwq else "fail",
        sl_contribution=3,
        detail=(
            f"minlen={minlen}, minclass={minclass}, "
            f"MAX_DAYS={pass_max}, MIN_DAYS={pass_min}, "
            f"historial={history}"
        ),
        remediation=(
            "En /etc/security/pwquality.conf:\n"
            "  minlen = 12\n  minclass = 3\n  maxrepeat = 3\n"
            "En /etc/login.defs: PASS_MAX_DAYS 90 | PASS_MIN_DAYS 1\n"
            "En /etc/pam.d/common-password añadir: remember=5"
        ),
    ))

    # ── SR 1.8 SL2 — Certificados PKI / SSH ──
    # Norma §5.10: uso de PKI para autenticación
    ssh = fr1.get("ssh_config", {})
    empty_pw   = ssh.get("PermitEmptyPasswords", "no").lower()
    root_login = ssh.get("PermitRootLogin",       "yes").lower()
    pw_auth    = ssh.get("PasswordAuthentication","yes").lower()
    pubkey     = ssh.get("PubkeyAuthentication",  "yes").lower()

    checks.append(CheckResult(
        sr_id="SR 1.8",
        title="SSH — contraseñas vacías prohibidas",
        status="pass" if empty_pw in ("no", "not_set") else "fail",
        sl_contribution=1,
        detail=f"PermitEmptyPasswords={empty_pw}",
        remediation="En /etc/ssh/sshd_config: PermitEmptyPasswords no",
    ))

    sl2_ssh = pw_auth == "no" and pubkey in ("yes", "not_set")
    checks.append(CheckResult(
        sr_id="SR 1.8",
        title="SSH — autenticación por clave pública (PKI)",
        status="pass" if sl2_ssh else "fail",
        sl_contribution=2,
        detail=f"PasswordAuthentication={pw_auth}, PubkeyAuthentication={pubkey}",
        remediation=(
            "En /etc/ssh/sshd_config:\n"
            "  PasswordAuthentication no\n"
            "  PubkeyAuthentication yes\n"
            "  sudo systemctl restart ssh"
        ),
    ))

    checks.append(CheckResult(
        sr_id="SR 1.8",
        title="SSH — login root prohibido",
        status="pass" if root_login in ("no", "prohibit-password", "forced-commands-only") else "fail",
        sl_contribution=2,
        detail=f"PermitRootLogin={root_login}",
        remediation="En /etc/ssh/sshd_config: PermitRootLogin no",
    ))

    # ── SR 1.9 SL2 — Fortaleza autenticación clave pública ──
    # Norma §5.11: validar certificados, revocación, cadena de confianza
    host_key_types = fr1.get("ssh_host_key_types", [])
    rsa_bits       = fr1.get("ssh_host_rsa_bits")
    weak_key_types = [t for t in host_key_types if t in ("dsa", "dss")]
    rsa_strong     = rsa_bits is None or rsa_bits >= 3072
    checks.append(CheckResult(
        sr_id="SR 1.9",
        title="Algoritmos de clave pública SSH robustos (≥Ed25519 / RSA-3072)",
        status="fail" if weak_key_types else ("pass" if rsa_strong else "warning"),
        sl_contribution=2,
        detail=f"Tipos de host key: {host_key_types}, RSA bits: {rsa_bits}",
        remediation=(
            "Eliminar claves DSA/DSS:\n"
            "  sudo rm /etc/ssh/ssh_host_dsa_key*\n"
            "Generar Ed25519: sudo ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ''"
        ),
    ))

    # ── SR 1.10 SL1 — Retroalimentación del autenticador ──
    # Norma §5.12: ocultar retroalimentación durante autenticación
    log_level  = ssh.get("LogLevel", "not_set")
    faildelay  = fr1.get("pam_faildelay_us")
    # LogLevel no debe ser VERBOSE o DEBUG (filtra demasiada info)
    safe_log   = log_level.upper() in ("INFO", "ERROR", "QUIET", "FATAL", "not_set")
    # pam_faildelay debe existir para evitar timing attacks (≥2 segundos = 2000000 µs)
    good_delay = faildelay is not None and faildelay >= 2000000
    checks.append(CheckResult(
        sr_id="SR 1.10",
        title="Retroalimentación del autenticador — sin revelación de información",
        status="pass" if (safe_log and good_delay) else "warning",
        sl_contribution=1,
        detail=f"SSH LogLevel={log_level}, pam_faildelay={faildelay}µs",
        remediation=(
            "En /etc/ssh/sshd_config: LogLevel INFO\n"
            "En /etc/pam.d/sshd añadir:\n"
            "  auth optional pam_faildelay.so delay=4000000"
        ),
    ))

    # ── SR 1.11 SL1 — Intentos fallidos de inicio de sesión ──
    # Norma §5.13: límite de intentos, bloqueo de cuenta
    fc = fr1.get("faillock_config", {})
    deny          = fc.get("deny")
    in_pam        = fc.get("in_pam_common_auth", False)
    deny_ok       = deny is not None and int(deny) <= 5 if deny else False
    checks.append(CheckResult(
        sr_id="SR 1.11",
        title="Límite de intentos fallidos de login (pam_faillock)",
        status="pass" if (deny_ok and in_pam) else "fail",
        sl_contribution=1,
        detail=f"pam_faillock deny={deny}, en PAM={in_pam}",
        remediation=(
            "En /etc/security/faillock.conf:\n"
            "  deny = 5\n  fail_interval = 900\n  unlock_time = 600\n"
            "En /etc/pam.d/common-auth incluir pam_faillock"
        ),
    ))

    # ── SR 1.12 SL1 — Aviso de uso del sistema ──
    # Norma §5.14: mensaje de aviso antes de autenticación
    banner_ok  = fr1.get("ssh_banner_configured", False)
    issue_ok   = fr1.get("login_banner_issue_net", False)
    checks.append(CheckResult(
        sr_id="SR 1.12",
        title="Aviso de uso del sistema (banner SSH y MOTD)",
        status="pass" if (banner_ok or issue_ok) else "fail",
        sl_contribution=1,
        detail=(
            f"SSH Banner configurado: {banner_ok} "
            f"(archivo: {fr1.get('ssh_banner_file', 'not_set')}), "
            f"issue.net: {issue_ok}"
        ),
        remediation=(
            "Crear /etc/ssh/banner.txt con aviso legal y añadir a /etc/ssh/sshd_config:\n"
            "  Banner /etc/ssh/banner.txt\n"
            "Contenido recomendado: aviso de monitorización y acceso autorizado"
        ),
    ))

    # ── SR 1.13 SL1 — Acceso por redes no confiables ──
    # Norma §5.15: supervisar y controlar el acceso por redes no confiables
    vpn_configured = fr1.get("vpn_configured", False)
    vpn_ifaces     = fr1.get("vpn_interfaces_active", [])
    # Para SL1: control de acceso remoto (SSH con clave ya cubre parcialmente)
    # Para SL2 RE1: aprobación explícita (VPN o jump-host)
    ssh_max_tries = ssh.get("MaxAuthTries", "6")
    max_tries_ok  = int(ssh_max_tries) <= 4 if ssh_max_tries.isdigit() else False
    checks.append(CheckResult(
        sr_id="SR 1.13",
        title="Control de acceso por redes no confiables — MaxAuthTries",
        status="pass" if max_tries_ok else "fail",
        sl_contribution=1,
        detail=f"SSH MaxAuthTries={ssh_max_tries}",
        remediation="En /etc/ssh/sshd_config: MaxAuthTries 3",
    ))

    checks.append(CheckResult(
        sr_id="SR 1.13 RE1",
        title="Acceso por redes no confiables — VPN o segmentación",
        status="pass" if (vpn_configured or vpn_ifaces) else "warning",
        sl_contribution=2,
        detail=f"VPN configurada: {vpn_configured}, interfaces VPN: {vpn_ifaces}",
        remediation=(
            "Implementar VPN para acceso remoto:\n"
            "  sudo apt install wireguard  # recomendado\n"
            "O configurar acceso a través de jump host / bastion"
        ),
    ))

    result.checks            = checks
    result.sl_achieved       = _sl_from_checks(checks)
    result.compliance_percent= _compliance_percent(checks)
    result.status            = "evaluated"
    return result


# ─────────────────────────────────────────────
# FR2 — Control de uso (UC)
# Norma §6 — SRs 2.1 a 2.12
# ─────────────────────────────────────────────

def analyze_fr2(fr2: dict) -> FRResult:
    result = FRResult(fr_id="FR2", title="Control de uso")
    checks = []

    # ── SR 2.1 SL1 — Aplicación de la autorización ──
    # Norma §6.3: aplicar autorizaciones asignadas, privilegio mínimo
    nopasswd = fr2.get("sudoers_nopasswd_entries", False) or fr2.get("sudoers_d_nopasswd", False)
    checks.append(CheckResult(
        sr_id="SR 2.1",
        title="Control de privilegios sudo (sin NOPASSWD irrestricto)",
        status="warning" if nopasswd else "pass",
        sl_contribution=1,
        detail=f"Entradas NOPASSWD en sudoers: {nopasswd}",
        remediation="Eliminar NOPASSWD de /etc/sudoers y /etc/sudoers.d/ salvo casos justificados.",
    ))

    # ── SR 2.1 RE1+RE2 SL2 — RBAC / AppArmor ──
    aa = fr2.get("apparmor", {})
    aa_ok = aa.get("available", False) and aa.get("profiles_enforce", 0) > 0
    checks.append(CheckResult(
        sr_id="SR 2.1 RE1",
        title="Control de acceso obligatorio MAC (AppArmor en enforce)",
        status="pass" if aa_ok else "fail",
        sl_contribution=2,
        detail=f"AppArmor disponible: {aa.get('available')}, perfiles enforce: {aa.get('profiles_enforce', 0)}",
        remediation=(
            "sudo systemctl enable --now apparmor\n"
            "sudo aa-enforce /etc/apparmor.d/*"
        ),
    ))

    # ── SR 2.2 SL1 — Control de uso inalámbrico ──
    # Norma §6.4: autorizar, supervisar y aplicar restricciones inalámbricas
    wifi_active = fr2.get("wifi_active", False)
    nm_managed  = fr2.get("networkmanager_wifi_managed", False)
    checks.append(CheckResult(
        sr_id="SR 2.2",
        title="Control de acceso inalámbrico (WiFi gestionado o deshabilitado)",
        status="pass" if (not wifi_active or nm_managed) else "warning",
        sl_contribution=1,
        detail=f"Interfaces WiFi: {fr2.get('wifi_interfaces', [])}, gestionado por NM: {nm_managed}",
        remediation=(
            "Si no se usa WiFi: sudo nmcli radio wifi off\n"
            "Si se usa: asegurar WPA3 y gestión por NetworkManager con políticas"
        ),
    ))

    # ── SR 2.3 SL1 — Control de uso USB/dispositivos móviles ──
    # Norma §6.5: prevenir uso no autorizado de dispositivos portátiles
    usb_blacklisted = fr2.get("usb_storage_blacklisted", False)
    checks.append(CheckResult(
        sr_id="SR 2.3",
        title="Control de acceso a almacenamiento USB (módulo en lista negra)",
        status="pass" if usb_blacklisted else "fail",
        sl_contribution=1,
        detail=f"usb-storage en lista negra: {usb_blacklisted}",
        remediation=(
            "echo 'blacklist usb-storage' | sudo tee /etc/modprobe.d/usb-storage.conf\n"
            "sudo update-initramfs -u"
        ),
    ))

    # ── SR 2.4 SL1 — Código móvil ──
    # Norma §6.6: restricciones de uso para tecnologías de código móvil
    seccomp = fr2.get("seccomp_available", False)
    code_runtimes = fr2.get("mobile_code_runtimes", {})
    unrestricted_runtimes = [k for k, v in code_runtimes.items() if v]
    checks.append(CheckResult(
        sr_id="SR 2.4",
        title="Control de código móvil — seccomp/AppArmor para runtimes",
        status="pass" if (seccomp and aa_ok) else "warning",
        sl_contribution=1,
        detail=f"seccomp disponible: {seccomp}, runtimes instalados: {unrestricted_runtimes}",
        remediation=(
            "Asegurar que AppArmor tiene perfiles para: " + ", ".join(unrestricted_runtimes[:3]) + "\n"
            "Habilitar seccomp para servicios críticos en systemd units:\n"
            "  SystemCallFilter=@system-service"
        ),
    ))

    # ── SR 2.5 SL1 — Bloqueo de sesión ──
    # Norma §6.7: bloquear sesión tras inactividad configurable
    timeout = fr2.get("session_timeout_seconds")
    timeout_ok = timeout is not None and timeout <= 900
    checks.append(CheckResult(
        sr_id="SR 2.5",
        title="Bloqueo de sesión inactiva (TMOUT ≤ 900s)",
        status="pass" if timeout_ok else "fail",
        sl_contribution=1,
        detail=f"TMOUT={timeout}s (máximo recomendado: 900s / 15 min)",
        remediation=(
            "Añadir a /etc/profile.d/tmout.sh:\n"
            "  export TMOUT=900\n  readonly TMOUT"
        ),
    ))

    # ── SR 2.6 SL2 — Terminar sesión remota ──
    # Norma §6.8: finalizar sesión remota tras inactividad (no seleccionado SL1)
    # ClientAliveInterval y ClientAliveCountMax vienen de FR1
    # Los datos de FR2 no tienen ssh_config directamente; usamos listening_ports_count
    ports_count = fr2.get("listening_ports_count", 0)
    dangerous   = fr2.get("dangerous_remote_services", [])
    checks.append(CheckResult(
        sr_id="SR 2.6",
        title="Terminar sesión remota — protocolos inseguros eliminados",
        status="fail" if dangerous else "pass",
        sl_contribution=2,
        detail=f"Protocolos remotos peligrosos: {dangerous}, puertos en escucha: {ports_count}",
        remediation="sudo systemctl disable --now telnet rsh rlogin && sudo apt purge telnet",
    ))

    checks.append(CheckResult(
        sr_id="SR 2.6",
        title="Terminar sesión remota — superficie de ataque (puertos ≤ 5)",
        status="pass" if ports_count <= 5 else "warning",
        sl_contribution=2,
        detail=f"Puertos en escucha: {ports_count}",
        remediation="Deshabilitar servicios no necesarios: sudo systemctl disable <servicio>",
    ))

    # ── SR 2.7 SL3 — Sesiones simultáneas ──
    # Norma §6.9: no seleccionado SL1/SL2, requerido desde SL3
    nproc_limit = fr2.get("nproc_hard_limit")
    checks.append(CheckResult(
        sr_id="SR 2.7",
        title="Límite de sesiones/procesos simultáneos (nproc hard limit)",
        status="pass" if (nproc_limit is not None and nproc_limit <= 1000) else "warning",
        sl_contribution=3,
        detail=f"nproc hard limit: {nproc_limit}",
        remediation=(
            "En /etc/security/limits.conf añadir:\n"
            "  * hard nproc 500\n"
            "Para SSH: MaxSessions 4 en sshd_config"
        ),
    ))

    # ── SR 2.8 SL1 — Eventos auditables ──
    # Norma §6.10: registros pertinentes para la seguridad
    auditd_active = fr2.get("auditd_active", False)
    rules_count   = fr2.get("auditd_active_rules_count", 0)
    rules_ok      = isinstance(rules_count, int) and rules_count >= 5
    checks.append(CheckResult(
        sr_id="SR 2.8",
        title="Registros de auditoría — auditd activo",
        status="pass" if auditd_active else "fail",
        sl_contribution=1,
        detail=f"auditd activo: {auditd_active}, reglas: {rules_count}",
        remediation="sudo apt install auditd audispd-plugins && sudo systemctl enable --now auditd",
    ))

    # ── SR 2.8 RE1 SL3 — Pista de auditoría centralizada ──
    cats = fr2.get("audit_categories", {})
    categories_ok = (
        cats.get("access_control", 0)  >= 3 and
        cats.get("os_events",      0)  >= 2 and
        cats.get("config_changes", 0)  >= 2
    )
    checks.append(CheckResult(
        sr_id="SR 2.8 RE1",
        title="Categorías de auditoría cubiertas (control acceso, SO, configuración)",
        status="pass" if (rules_ok and categories_ok) else "fail",
        sl_contribution=3,
        detail=f"Categorías detectadas: {cats}",
        remediation=(
            "Añadir a /etc/audit/rules.d/hardening.rules:\n"
            "  -w /etc/passwd -p wa -k identity\n"
            "  -w /etc/shadow -p wa -k identity\n"
            "  -w /etc/sudoers -p wa -k sudoers\n"
            "  -a always,exit -F arch=b64 -S execve -k exec\n"
            "  -w /var/log/auth.log -p wa -k auth"
        ),
    ))

    # ── SR 2.9 SL1 — Capacidad de almacenamiento de auditoría ──
    storage = fr2.get("audit_storage", {})
    max_log  = storage.get("max_log_file_mb")
    num_logs = storage.get("num_logs")
    storage_ok = max_log is not None and max_log >= 8 and num_logs is not None and num_logs >= 5
    checks.append(CheckResult(
        sr_id="SR 2.9",
        title="Capacidad de almacenamiento de auditoría (≥8 MB × ≥5 logs)",
        status="pass" if storage_ok else "fail",
        sl_contribution=1,
        detail=f"max_log_file={max_log}MB, num_logs={num_logs}, action={storage.get('max_log_file_action')}",
        remediation=(
            "En /etc/audit/auditd.conf:\n"
            "  max_log_file = 50\n"
            "  num_logs = 10\n"
            "  max_log_file_action = rotate"
        ),
    ))

    # ── SR 2.10 SL1 — Respuesta a fallos de auditoría ──
    # Norma §6.12: alertar y evitar pérdida de funciones esenciales
    fail_resp = fr2.get("audit_failure_response", {})
    disk_full = (fail_resp.get("disk_full_action") or "").lower()
    disk_err  = (fail_resp.get("disk_error_action") or "").lower()
    resp_ok   = disk_full in ("rotate", "syslog", "suspend", "single") and disk_err in ("syslog", "suspend")
    checks.append(CheckResult(
        sr_id="SR 2.10",
        title="Respuesta a fallos de auditoría (disk_full_action configurada)",
        status="pass" if resp_ok else "fail",
        sl_contribution=1,
        detail=f"disk_full_action={disk_full}, disk_error_action={disk_err}",
        remediation=(
            "En /etc/audit/auditd.conf:\n"
            "  disk_full_action = rotate\n"
            "  disk_error_action = syslog"
        ),
    ))

    # ── SR 2.11 SL2 — Marcas de tiempo (NTP) ──
    # Norma §6.13: no seleccionado SL1, requerido desde SL2
    time_sync = fr2.get("time_sync", {})
    ntp_sync  = time_sync.get("NTPSynchronized", "no")
    ntp_daemon = fr2.get("ntp_daemon", "none")
    checks.append(CheckResult(
        sr_id="SR 2.11",
        title="Sincronización horaria NTP activa (marcas de tiempo correctas)",
        status="pass" if ntp_sync == "yes" else "fail",
        sl_contribution=2,
        detail=f"NTPSynchronized={ntp_sync}, daemon={ntp_daemon}, Timezone={time_sync.get('Timezone')}",
        remediation=(
            "sudo apt install chrony && sudo systemctl enable --now chronyd\n"
            "O: sudo timedatectl set-ntp true"
        ),
    ))

    ntp_servers = fr2.get("ntp_servers_configured", [])
    checks.append(CheckResult(
        sr_id="SR 2.11 RE1",
        title="Servidores NTP configurados explícitamente",
        status="pass" if len(ntp_servers) >= 1 else "warning",
        sl_contribution=3,
        detail=f"Servidores NTP: {ntp_servers}",
        remediation=(
            "En /etc/systemd/timesyncd.conf:\n"
            "  NTP=0.es.pool.ntp.org 1.es.pool.ntp.org\n"
            "  FallbackNTP=ntp.ubuntu.com"
        ),
    ))

    # ── SR 2.12 SL3 — No rechazo ──
    # Norma §6.14: no seleccionado SL1/SL2; determinar si usuario realizó acción
    immutable = fr2.get("audit_rules_immutable", False)
    syslog    = fr2.get("syslog", {})
    syslog_ok = syslog.get("rsyslog_active", False) or syslog.get("syslog_ng_active", False)
    checks.append(CheckResult(
        sr_id="SR 2.12",
        title="No rechazo — reglas de auditoría inmutables y syslog activo",
        status="pass" if (immutable and syslog_ok) else "fail",
        sl_contribution=3,
        detail=f"Reglas auditd inmutables (-e 2): {immutable}, syslog activo: {syslog_ok}",
        remediation=(
            "Añadir al final de /etc/audit/rules.d/99-finalize.rules:\n"
            "  -e 2\n"
            "Instalar rsyslog: sudo apt install rsyslog && sudo systemctl enable --now rsyslog"
        ),
    ))

    result.checks            = checks
    result.sl_achieved       = _sl_from_checks(checks)
    result.compliance_percent= _compliance_percent(checks)
    result.status            = "evaluated"
    return result


# ─────────────────────────────────────────────
# FR3 — Integridad del sistema (SI)
# Norma §7 — SRs 3.1 a 3.9
# ─────────────────────────────────────────────

def analyze_fr3(fr3: dict) -> FRResult:
    result = FRResult(fr_id="FR3", title="Integridad del sistema")
    checks = []

    # ── SR 3.1 SL1 — Integridad de la comunicación ──
    # Norma §7.3: proteger integridad de información transmitida
    weak_macs = fr3.get("ssh_weak_macs", [])
    macs_configured = fr3.get("sshd_macs_configured")
    checks.append(CheckResult(
        sr_id="SR 3.1",
        title="Integridad de comunicación SSH — MACs sin algoritmos débiles",
        status="fail" if (not macs_configured and weak_macs) else "pass",
        sl_contribution=1,
        detail=f"MACs débiles disponibles: {weak_macs[:5]}, MACs configurados en sshd: {macs_configured}",
        remediation=(
            "En /etc/ssh/sshd_config:\n"
            "  MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,"
            "umac-128-etm@openssh.com"
        ),
    ))

    # ── SR 3.1 RE1 SL3 — Protección criptográfica de la integridad ──
    # Norma §7.3.3.1: mecanismos criptográficos para reconocer cambios
    openssl_ver = fr3.get("openssl_version", "")
    modern_ssl  = any(v in openssl_ver for v in ["3.", "1.1.1"])
    checks.append(CheckResult(
        sr_id="SR 3.1 RE1",
        title="Protección criptográfica de integridad — OpenSSL moderno",
        status="pass" if modern_ssl else "fail",
        sl_contribution=3,
        detail=f"OpenSSL: {openssl_ver}",
        remediation="sudo apt update && sudo apt upgrade openssl libssl-dev",
    ))

    # ── SR 3.2 SL1 — Protección contra código malicioso ──
    tools = fr3.get("security_tools", {})
    has_av = any(tools.get(t, {}).get("installed") for t in ("clamav", "clamd"))
    checks.append(CheckResult(
        sr_id="SR 3.2",
        title="Antimalware instalado (ClamAV)",
        status="pass" if has_av else "fail",
        sl_contribution=1,
        detail=f"ClamAV: {has_av}, DB actualizada: {fr3.get('clamav_db_updated')}",
        remediation=(
            "sudo apt install clamav clamav-daemon\n"
            "sudo freshclam && sudo systemctl enable --now clamav-daemon"
        ),
    ))

    # ── SR 3.2 RE1 SL2 — Protección en puntos de entrada y salida ──
    has_rkhunter = tools.get("rkhunter", {}).get("installed", False)
    has_chkrootkit = tools.get("chkrootkit", {}).get("installed", False)
    checks.append(CheckResult(
        sr_id="SR 3.2 RE1",
        title="Protección contra rootkits en puntos de entrada (rkhunter/chkrootkit)",
        status="pass" if (has_rkhunter or has_chkrootkit) else "fail",
        sl_contribution=2,
        detail=f"rkhunter: {has_rkhunter}, chkrootkit: {has_chkrootkit}",
        remediation="sudo apt install rkhunter && sudo rkhunter --update && sudo rkhunter --check",
    ))

    # ── SR 3.3 SL1 — Verificación de funcionalidad de seguridad (FIM) ──
    # Norma §7.5: verificar funcionamiento previsto de funciones de seguridad
    has_aide = tools.get("aide", {}).get("installed", False)
    aide_cfg  = fr3.get("aide_configured", False)
    aide_db   = fr3.get("aide_db_exists", False)
    fim_ok    = (has_aide and aide_cfg and aide_db) or fr3.get("tripwire_configured", False)
    checks.append(CheckResult(
        sr_id="SR 3.3",
        title="Monitor de integridad de archivos FIM (AIDE/Tripwire)",
        status="pass" if fim_ok else "fail",
        sl_contribution=2,
        detail=f"AIDE instalado: {has_aide}, configurado: {aide_cfg}, DB: {aide_db}",
        remediation=(
            "sudo apt install aide\n"
            "sudo aideinit\n"
            "sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db\n"
            "Programar verificación semanal en cron"
        ),
    ))

    # ── SR 3.4 SL1 — Integridad del software ──
    # Norma §7.6: verificar integridad del software e información
    unauth = fr3.get("apt_unauthenticated_allowed", False)
    checks.append(CheckResult(
        sr_id="SR 3.4",
        title="Verificación de firma en paquetes APT (sin AllowUnauthenticated)",
        status="fail" if unauth else "pass",
        sl_contribution=1,
        detail=f"AllowUnauthenticated habilitado: {unauth}",
        remediation="Revisar y eliminar AllowUnauthenticated de /etc/apt/apt.conf.d/",
    ))

    # ── SR 3.4 SL3 — Secure Boot ──
    sb = fr3.get("secure_boot", {})
    sb_enabled = sb.get("enabled", False)
    checks.append(CheckResult(
        sr_id="SR 3.4",
        title="Secure Boot habilitado (cadena de confianza arranque)",
        status="pass" if sb_enabled else "warning",
        sl_contribution=3,
        detail=f"Secure Boot: {sb.get('state', 'desconocido')}",
        remediation="Habilitar Secure Boot en BIOS/UEFI. Ubuntu 25.10 incluye shim-signed.",
    ))

    # ── SR 3.5 SL1 — Validación de entrada ──
    # Norma §7.7: validar entradas para prevenir ataques
    iv = fr3.get("input_validation", {})
    rp_filter  = iv.get("net.ipv4.conf.all.rp_filter") == "1"
    no_src_rt  = iv.get("net.ipv4.conf.all.accept_source_route") == "0"
    no_redir   = iv.get("net.ipv4.conf.all.accept_redirects") == "0"
    no_bcast   = iv.get("net.ipv4.icmp_echo_ignore_broadcasts") == "1"
    input_val_ok = rp_filter and no_src_rt and no_redir and no_bcast
    checks.append(CheckResult(
        sr_id="SR 3.5",
        title="Validación de entrada de red — rp_filter, no source routing, no redirects",
        status="pass" if input_val_ok else "fail",
        sl_contribution=2,
        detail=(
            f"rp_filter={iv.get('net.ipv4.conf.all.rp_filter')}, "
            f"accept_source_route={iv.get('net.ipv4.conf.all.accept_source_route')}, "
            f"accept_redirects={iv.get('net.ipv4.conf.all.accept_redirects')}, "
            f"icmp_ignore_broadcasts={iv.get('net.ipv4.icmp_echo_ignore_broadcasts')}"
        ),
        remediation=(
            "En /etc/sysctl.d/99-hardening.conf:\n"
            "  net.ipv4.conf.all.rp_filter = 1\n"
            "  net.ipv4.conf.all.accept_source_route = 0\n"
            "  net.ipv4.conf.all.accept_redirects = 0\n"
            "  net.ipv4.icmp_echo_ignore_broadcasts = 1\n"
            "Aplicar: sudo sysctl --system"
        ),
    ))

    # ── SR 3.5 SL2 — ASLR + Kernel hardening ──
    kh = fr3.get("kernel_hardening", {})
    aslr_ok   = kh.get("kernel.randomize_va_space") == "2"
    dmesg_ok  = kh.get("kernel.dmesg_restrict") == "1"
    kptr_ok   = kh.get("kernel.kptr_restrict") in ("1", "2")
    yama_ok   = kh.get("kernel.yama.ptrace_scope") in ("1", "2", "3")
    hardening_ok = aslr_ok and dmesg_ok and kptr_ok and yama_ok
    checks.append(CheckResult(
        sr_id="SR 3.5",
        title="Endurecimiento de kernel — ASLR, dmesg_restrict, kptr, yama",
        status="pass" if hardening_ok else "fail",
        sl_contribution=2,
        detail=(
            f"ASLR={kh.get('kernel.randomize_va_space')}, "
            f"dmesg_restrict={kh.get('kernel.dmesg_restrict')}, "
            f"kptr_restrict={kh.get('kernel.kptr_restrict')}, "
            f"ptrace_scope={kh.get('kernel.yama.ptrace_scope')}"
        ),
        remediation=(
            "En /etc/sysctl.d/99-hardening.conf:\n"
            "  kernel.randomize_va_space = 2\n"
            "  kernel.dmesg_restrict = 1\n"
            "  kernel.kptr_restrict = 2\n"
            "  kernel.yama.ptrace_scope = 1"
        ),
    ))

    # ── SR 3.7 SL1 — Tratamiento de errores (core dumps) ──
    # Norma §7.9: tratamiento seguro de errores
    core = fr3.get("core_dumps", {})
    apport_disabled = core.get("apport_disabled", False)
    core_limit      = core.get("system_limit")
    core_ok         = apport_disabled and (core_limit == "0" if core_limit else False)
    checks.append(CheckResult(
        sr_id="SR 3.7",
        title="Tratamiento de errores — core dumps deshabilitados",
        status="pass" if core_ok else "warning",
        sl_contribution=2,
        detail=f"apport deshabilitado: {apport_disabled}, core limit: {core_limit}",
        remediation=(
            "sudo systemctl disable --now apport\n"
            "En /etc/security/limits.conf: * hard core 0\n"
            "En /etc/sysctl.d/99-hardening.conf: fs.suid_dumpable = 0"
        ),
    ))

    # ── SR 3.9 SL1 — Protección de información de auditoría ──
    # Norma §7.11: proteger registros de auditoría
    audit_prot = fr3.get("audit_log_protection", {})
    log_mode   = audit_prot.get("/var/log_mode")
    audit_mode = audit_prot.get("/var/log/audit_mode")
    remote_log = fr3.get("remote_logging_configured", False)
    log_ok     = audit_mode in ("0o700", "0o750") if audit_mode else False
    checks.append(CheckResult(
        sr_id="SR 3.9",
        title="Protección de logs de auditoría — permisos /var/log/audit/ y envío remoto",
        status="pass" if (log_ok or remote_log) else "fail",
        sl_contribution=2,
        detail=f"/var/log/audit permisos: {audit_mode}, logging remoto: {remote_log}",
        remediation=(
            "sudo chmod 700 /var/log/audit\n"
            "Configurar envío remoto en /etc/rsyslog.conf:\n"
            "  *.* @@siem.empresa.local:514"
        ),
    ))

    result.checks            = checks
    result.sl_achieved       = _sl_from_checks(checks)
    result.compliance_percent= _compliance_percent(checks)
    result.status            = "evaluated"
    return result


# ─────────────────────────────────────────────
# FR4 — Confidencialidad de datos (DC)
# Norma §8 — SRs 4.1, 4.2, 4.3
# ─────────────────────────────────────────────

def analyze_fr4(fr4: dict) -> FRResult:
    result = FRResult(fr_id="FR4", title="Confidencialidad de datos")
    checks = []

    # ── SR 4.1 SL2 — Confidencialidad en tránsito ──
    openssl_ver = fr4.get("openssl_version", "")
    modern_ssl  = any(v in openssl_ver for v in ["3.", "1.1.1"])
    checks.append(CheckResult(
        sr_id="SR 4.1",
        title="OpenSSL moderno (≥1.1.1 / 3.x)",
        status="pass" if modern_ssl else "fail",
        sl_contribution=1,
        detail=f"OpenSSL: {openssl_ver}",
        remediation="sudo apt update && sudo apt upgrade openssl",
    ))

    weak_ciphers = fr4.get("ssh_weak_ciphers", [])
    ciphers_cfg  = fr4.get("sshd_ciphers_configured")
    checks.append(CheckResult(
        sr_id="SR 4.1",
        title="SSH — sin cifrados débiles (3DES, RC4, Blowfish)",
        status="fail" if (weak_ciphers and not ciphers_cfg) else "pass",
        sl_contribution=2,
        detail=f"Cifrados débiles: {weak_ciphers[:5]}, Ciphers configurados: {ciphers_cfg}",
        remediation=(
            "En /etc/ssh/sshd_config:\n"
            "  Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,"
            "aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"
        ),
    ))

    # ── SR 4.2 SL2 — Confidencialidad en reposo ──
    luks = fr4.get("full_disk_encryption", False)
    checks.append(CheckResult(
        sr_id="SR 4.2",
        title="Cifrado de disco completo (LUKS/dm-crypt)",
        status="pass" if luks else "fail",
        sl_contribution=2,
        detail=f"Dispositivos LUKS: {fr4.get('luks_encrypted_devices', [])}",
        remediation=(
            "Seleccionar cifrado de disco en el instalador de Ubuntu.\n"
            "Para datos existentes: usar cryptsetup luksFormat en la partición."
        ),
    ))

    perms = fr4.get("sensitive_file_permissions", {})
    shadow_perm = perms.get("/etc/shadow", {}).get("mode", "")
    shadow_ok   = shadow_perm in ("0o0", "0o640", "0o600", "0o400")
    checks.append(CheckResult(
        sr_id="SR 4.2",
        title="Permisos de /etc/shadow restrictivos",
        status="pass" if shadow_ok else "fail",
        sl_contribution=1,
        detail=f"Permisos /etc/shadow: {shadow_perm}",
        remediation="sudo chmod 640 /etc/shadow && sudo chown root:shadow /etc/shadow",
    ))

    sshd_perm = perms.get("/etc/ssh/sshd_config", {}).get("mode", "")
    sshd_ok   = sshd_perm in ("0o600", "0o644", "0o640")
    checks.append(CheckResult(
        sr_id="SR 4.2",
        title="Permisos de sshd_config restrictivos",
        status="pass" if sshd_ok else "fail",
        sl_contribution=2,
        detail=f"Permisos /etc/ssh/sshd_config: {sshd_perm}",
        remediation="sudo chmod 600 /etc/ssh/sshd_config",
    ))

    sudoers_perm = perms.get("/etc/sudoers", {}).get("mode", "")
    sudoers_ok   = sudoers_perm in ("0o440", "0o400")
    checks.append(CheckResult(
        sr_id="SR 4.2",
        title="Permisos de /etc/sudoers restrictivos (0o440)",
        status="pass" if sudoers_ok else "fail",
        sl_contribution=2,
        detail=f"Permisos /etc/sudoers: {sudoers_perm}",
        remediation="sudo chmod 440 /etc/sudoers",
    ))

    # ── SR 4.3 SL2 — Uso de criptografía ──
    # Norma §8.5: utilizar criptografía conforme a prácticas aceptadas
    crypto_policy = fr4.get("crypto_policy", "not_available")
    weak_policy   = crypto_policy in ("LEGACY", "DEFAULT:NO-SHA1")
    checks.append(CheckResult(
        sr_id="SR 4.3",
        title="Política criptográfica del sistema (no LEGACY)",
        status="warning" if weak_policy else ("pass" if crypto_policy != "not_available" else "warning"),
        sl_contribution=2,
        detail=f"Política criptográfica: {crypto_policy}",
        remediation=(
            "Ubuntu 25.10 usa OpenSSL 3.x con perfil DEFAULT seguro.\n"
            "Si update-crypto-policies no está disponible, revisar:\n"
            "  /etc/ssl/openssl.cnf — MinProtocol = TLSv1.2"
        ),
    ))

    result.checks            = checks
    result.sl_achieved       = _sl_from_checks(checks)
    result.compliance_percent= _compliance_percent(checks)
    result.status            = "evaluated"
    return result


# ─────────────────────────────────────────────
# FR5 — Flujo restringido de datos (RDF)
# Norma §9 — SRs 5.1 a 5.4
# ─────────────────────────────────────────────

def analyze_fr5(fr5: dict) -> FRResult:
    result = FRResult(fr_id="FR5", title="Flujo restringido de datos")
    checks = []

    # ── SR 5.1 SL1 — Segmentación de red ──
    ufw    = fr5.get("ufw", {})
    nft    = fr5.get("nftables", {})
    ipt    = fr5.get("iptables", {})
    fw_active = (
        ufw.get("status") == "active" or
        (nft.get("available") and nft.get("tables_count", 0) > 0) or
        (ipt.get("available") and ipt.get("rules"))
    )
    checks.append(CheckResult(
        sr_id="SR 5.1",
        title="Firewall activo (UFW/nftables/iptables)",
        status="pass" if fw_active else "fail",
        sl_contribution=1,
        detail=f"UFW={ufw.get('status')}, nftables tablas={nft.get('tables_count',0)}, iptables={ipt.get('available')}",
        remediation=(
            "sudo ufw enable\n"
            "sudo ufw default deny incoming\n"
            "sudo ufw default allow outgoing"
        ),
    ))

    # ── SR 5.1 RE1 SL2 — Política denegación por defecto (deny by default) ──
    default_in   = (ufw.get("default_incoming") or "").lower()
    deny_default = default_in in ("deny", "reject")
    checks.append(CheckResult(
        sr_id="SR 5.1",
        title="Política deny-by-default en tráfico entrante",
        status="pass" if deny_default else "fail",
        sl_contribution=2,
        detail=f"UFW default incoming: {default_in}",
        remediation="sudo ufw default deny incoming",
    ))

    rules_count = ufw.get("rules_count", 0)
    checks.append(CheckResult(
        sr_id="SR 5.1",
        title="Reglas de firewall explícitas definidas (≥2)",
        status="pass" if rules_count >= 2 else "warning",
        sl_contribution=2,
        detail=f"Reglas UFW: {rules_count}",
        remediation=(
            "sudo ufw allow 22/tcp  # SSH\n"
            "sudo ufw deny 23/tcp   # Bloquear Telnet"
        ),
    ))

    # ── SR 5.2 SL1 — Protección de límites de zona ──
    # Norma §9.4: proteger límites entre zonas
    fail2ban  = fr5.get("fail2ban_active", False)
    f2b_jails = fr5.get("fail2ban_jails", 0)
    checks.append(CheckResult(
        sr_id="SR 5.2",
        title="Protección de límites de zona — fail2ban activo con jails",
        status="pass" if (fail2ban and f2b_jails >= 1) else "fail",
        sl_contribution=2,
        detail=f"fail2ban activo: {fail2ban}, jails configurados: {f2b_jails}",
        remediation=(
            "sudo apt install fail2ban\n"
            "sudo systemctl enable --now fail2ban\n"
            "Configurar /etc/fail2ban/jail.local con jail [sshd]"
        ),
    ))

    # ── SR 5.3 SL1 — Separación de red (IP forwarding) ──
    # Norma §9.6: restricciones de comunicación
    ip_fwd   = fr5.get("ip_forwarding_enabled", True)
    ipv6_fwd = fr5.get("ipv6_forwarding_enabled", True)
    checks.append(CheckResult(
        sr_id="SR 5.3",
        title="IP forwarding desactivado (IPv4 e IPv6)",
        status="pass" if (not ip_fwd and not ipv6_fwd) else "fail",
        sl_contribution=1,
        detail=f"IPv4 forward={'ON' if ip_fwd else 'OFF'}, IPv6 forward={'ON' if ipv6_fwd else 'OFF'}",
        remediation=(
            "En /etc/sysctl.d/99-hardening.conf:\n"
            "  net.ipv4.ip_forward = 0\n"
            "  net.ipv6.conf.all.forwarding = 0\n"
            "Aplicar: sudo sysctl --system"
        ),
    ))

    # ── SR 5.4 SL2 — Partición de aplicaciones ──
    # Norma §9.7: separación de diferentes áreas
    container  = fr5.get("container_isolation", {})
    containers_ok = (
        container.get("docker_active", False) or
        container.get("lxd_available", False) or
        container.get("systemd_nspawn", False)
    )
    # AppArmor ya cubre partición a nivel de proceso
    aa_enforce = fr5.get("_aa_enforce", 0)   # viene de FR2
    checks.append(CheckResult(
        sr_id="SR 5.4",
        title="Partición de aplicaciones — contenedores o namespaces disponibles",
        status="pass" if containers_ok else "warning",
        sl_contribution=2,
        detail=f"Docker: {container.get('docker_active')}, LXD: {container.get('lxd_available')}, nspawn: {container.get('systemd_nspawn')}",
        remediation=(
            "Considerar el uso de contenedores (Docker/LXC) o\n"
            "systemd units con namespaces (PrivateNetwork=yes, ProtectSystem=strict)"
        ),
    ))

    result.checks            = checks
    result.sl_achieved       = _sl_from_checks(checks)
    result.compliance_percent= _compliance_percent(checks)
    result.status            = "evaluated"
    return result


# ─────────────────────────────────────────────
# FR6 — Respuesta oportuna a eventos (TRE)
# Norma §10 — SRs 6.1, 6.2
# ─────────────────────────────────────────────

def analyze_fr6(fr6: dict) -> FRResult:
    result = FRResult(fr_id="FR6", title="Respuesta oportuna a eventos")
    checks = []

    # ── SR 6.1 SL1 — Accesibilidad de registros de auditoría ──
    auditd_active = fr6.get("auditd_active", False)
    checks.append(CheckResult(
        sr_id="SR 6.1",
        title="auditd instalado y activo",
        status="pass" if auditd_active else "fail",
        sl_contribution=1,
        detail=f"auditd activo: {auditd_active}, config: {fr6.get('auditd_config')}",
        remediation="sudo apt install auditd audispd-plugins && sudo systemctl enable --now auditd",
    ))

    rules_count = fr6.get("auditd_rules_count", 0)
    has_rules   = isinstance(rules_count, int) and rules_count >= 5
    checks.append(CheckResult(
        sr_id="SR 6.1",
        title="Reglas de auditoría definidas (≥5 reglas activas)",
        status="pass" if has_rules else "fail",
        sl_contribution=2,
        detail=f"Reglas activas: {rules_count}",
        remediation=(
            "Añadir a /etc/audit/rules.d/hardening.rules:\n"
            "  -w /etc/passwd -p wa -k identity\n"
            "  -w /etc/shadow -p wa -k identity\n"
            "  -w /etc/sudoers -p wa -k sudoers\n"
            "  -a always,exit -F arch=b64 -S execve -k exec\n"
            "  -w /var/log/auth.log -p wa -k auth"
        ),
    ))

    watches_critical = fr6.get("auditd_watches_critical", False)
    checks.append(CheckResult(
        sr_id="SR 6.1",
        title="Auditd — watches en archivos críticos (passwd, shadow, ssh)",
        status="pass" if watches_critical else "fail",
        sl_contribution=2,
        detail=f"Watches en archivos críticos: {watches_critical}",
        remediation=(
            "-w /etc/passwd -p wa -k identity\n"
            "-w /etc/shadow -p wa -k identity\n"
            "-w /etc/ssh/sshd_config -p wa -k sshd_config"
        ),
    ))

    syslog_ok = fr6.get("syslog_active", False)
    checks.append(CheckResult(
        sr_id="SR 6.1",
        title="Sistema de logging activo (rsyslog/syslog-ng/journald)",
        status="pass" if syslog_ok else "fail",
        sl_contribution=1,
        detail=f"Syslog activo: {syslog_ok}, journald: {fr6.get('journald_active')}",
        remediation="sudo apt install rsyslog && sudo systemctl enable --now rsyslog",
    ))

    logrotate_ok = fr6.get("logrotate_exists", False)
    checks.append(CheckResult(
        sr_id="SR 6.1",
        title="Rotación de logs configurada (logrotate)",
        status="pass" if logrotate_ok else "fail",
        sl_contribution=2,
        detail=f"logrotate.conf presente: {logrotate_ok}",
        remediation="sudo apt install logrotate && verificar /etc/logrotate.conf",
    ))

    # ── SR 6.2 SL2 — Supervisión continua ──
    # Norma §10.4: herramientas de supervisión activas (IDS/IPS)
    ids_tools    = fr6.get("ids_tools_installed", {})
    fail2ban_act = fr6.get("fail2ban_active", False)
    any_ids      = any(ids_tools.values()) or fail2ban_act
    checks.append(CheckResult(
        sr_id="SR 6.2",
        title="Supervisión continua — IDS/IPS activo (suricata/snort/fail2ban)",
        status="pass" if any_ids else "fail",
        sl_contribution=2,
        detail=f"IDS instalados: {[k for k, v in ids_tools.items() if v]}, fail2ban: {fail2ban_act}",
        remediation=(
            "sudo apt install fail2ban\n"
            "Para IDS avanzado: sudo apt install suricata\n"
            "Configurar suricata con reglas ET Open"
        ),
    ))

    # NTP para correlación temporal de eventos (SR 2.11 referencia en §6)
    time_sync = fr6.get("time_sync", {})
    ntp_ok    = time_sync.get("NTPSynchronized", "no") == "yes"
    checks.append(CheckResult(
        sr_id="SR 6.2",
        title="NTP sincronizado — correlación temporal de eventos garantizada",
        status="pass" if ntp_ok else "fail",
        sl_contribution=1,
        detail=f"NTPSynchronized={time_sync.get('NTPSynchronized')}, Timezone={time_sync.get('Timezone')}",
        remediation="sudo timedatectl set-ntp true && sudo systemctl restart systemd-timesyncd",
    ))

    result.checks            = checks
    result.sl_achieved       = _sl_from_checks(checks)
    result.compliance_percent= _compliance_percent(checks)
    result.status            = "evaluated"
    return result


# ─────────────────────────────────────────────
# FR7 — Disponibilidad de recursos (RA)
# Norma §11 — SRs 7.1 a 7.8
# ─────────────────────────────────────────────

def analyze_fr7(fr7: dict) -> FRResult:
    result = FRResult(fr_id="FR7", title="Disponibilidad de recursos")
    checks = []

    # ── SR 7.1 SL1 — Protección contra DoS ──
    dos = fr7.get("dos_protection", {})
    syncookies = dos.get("net.ipv4.tcp_syncookies") == "1"
    rfc1337    = dos.get("net.ipv4.tcp_rfc1337") == "1"
    checks.append(CheckResult(
        sr_id="SR 7.1",
        title="Protección DoS — SYN cookies y TCP RFC1337",
        status="pass" if (syncookies and rfc1337) else "fail",
        sl_contribution=1,
        detail=f"tcp_syncookies={'1(activo)' if syncookies else '0'}, tcp_rfc1337={'1' if rfc1337 else '0'}",
        remediation=(
            "En /etc/sysctl.d/99-hardening.conf:\n"
            "  net.ipv4.tcp_syncookies = 1\n"
            "  net.ipv4.tcp_rfc1337 = 1"
        ),
    ))

    # ── SR 7.2 SL1 — Gestión de recursos ──
    mem = fr7.get("memory", {})
    total_kb = mem.get("total_kb", 0) or 0
    avail_kb = mem.get("available_kb", 0) or 0
    mem_pct  = (avail_kb / total_kb * 100) if total_kb > 0 else 0
    checks.append(CheckResult(
        sr_id="SR 7.2",
        title="Memoria disponible suficiente (>20%)",
        status="pass" if mem_pct >= 20 else "warning",
        sl_contribution=1,
        detail=f"Disponible: {avail_kb // 1024}MB de {total_kb // 1024}MB ({mem_pct:.1f}%)",
        remediation="Revisar procesos: top -o %MEM | htop",
    ))

    swap_ok = fr7.get("swap_configured", False)
    checks.append(CheckResult(
        sr_id="SR 7.2",
        title="Swap configurado (continuidad ante presión de memoria)",
        status="pass" if swap_ok else "warning",
        sl_contribution=1,
        detail=f"Swap activo: {swap_ok}",
        remediation="sudo fallocate -l 2G /swapfile && sudo chmod 600 /swapfile && sudo mkswap /swapfile && sudo swapon /swapfile",
    ))

    # ── SR 7.3 SL2 — Copia de seguridad ──
    backup = fr7.get("backup_configured", False)
    backup_tools = [k for k, v in fr7.get("backup_tools", {}).items() if v]
    checks.append(CheckResult(
        sr_id="SR 7.3",
        title="Herramienta de backup instalada y configurada",
        status="pass" if backup else "fail",
        sl_contribution=2,
        detail=f"Herramientas: {backup_tools if backup_tools else 'ninguna'}, cron jobs: {fr7.get('backup_cron_jobs', [])}",
        remediation=(
            "sudo apt install restic\n"
            "Configurar cron: 0 2 * * * restic -r /mnt/backup backup /etc /home"
        ),
    ))

    # ── SR 7.4 SL2 — Recuperación del sistema ──
    # Norma §11.4: recuperación y reconstitución
    timeshift = fr7.get("timeshift_snapshots", False)
    recovery_tools = fr7.get("recovery_tools", {})
    recovery_ok    = timeshift or any(recovery_tools.values())
    checks.append(CheckResult(
        sr_id="SR 7.4",
        title="Herramientas de recuperación del sistema disponibles",
        status="pass" if recovery_ok else "fail",
        sl_contribution=2,
        detail=f"Timeshift: {timeshift}, tools: {[k for k, v in recovery_tools.items() if v]}",
        remediation=(
            "sudo apt install timeshift\n"
            "Configurar snapshots automáticos de sistema\n"
            "Documentar procedimiento de recuperación"
        ),
    ))

    # ── SR 7.5 SL1 — Alimentación de emergencia ──
    ups = fr7.get("ups_monitoring", {})
    ups_ok = ups.get("nut_active", False) or ups.get("apcupsd_active", False)
    checks.append(CheckResult(
        sr_id="SR 7.5",
        title="Monitorización de alimentación (UPS con NUT/apcupsd)",
        status="pass" if ups_ok else "warning",
        sl_contribution=1,
        detail=f"NUT activo: {ups.get('nut_active')}, apcupsd: {ups.get('apcupsd_active')}",
        remediation=(
            "Si hay SAI/UPS: sudo apt install nut && configurar /etc/nut/ups.conf\n"
            "Si no hay SAI: documentar en análisis de riesgo como riesgo aceptado"
        ),
    ))

    # ── SR 7.6 SL1 — Configuración de red y seguridad ──
    sysctl_custom = fr7.get("sysctl_custom_count", 0)
    sysctl_harden = fr7.get("sysctl_hardening_files", 0)
    cfg_files     = fr7.get("critical_config_files", {})
    configs_ok    = sum(1 for v in cfg_files.values() if v) >= 3
    checks.append(CheckResult(
        sr_id="SR 7.6",
        title="Configuración de seguridad de red documentada (sysctl.d)",
        status="pass" if (configs_ok and sysctl_custom >= 1) else "fail",
        sl_contribution=1,
        detail=f"Configs críticas presentes: {sum(1 for v in cfg_files.values() if v)}/5, sysctl custom: {sysctl_custom}",
        remediation=(
            "Crear /etc/sysctl.d/99-hardening.conf con parámetros de seguridad.\n"
            "Aplicar: sudo sysctl --system"
        ),
    ))

    # ── SR 7.7 SL1 — Funcionalidad mínima ──
    # Norma §11.7: sin servicios, funciones, puertos innecesarios
    failed   = fr7.get("failed_services_count", 0)
    risky    = fr7.get("risky_services_enabled", [])
    checks.append(CheckResult(
        sr_id="SR 7.7",
        title="Sin servicios fallidos ni servicios de riesgo habilitados",
        status="fail" if (failed > 0 or risky) else "pass",
        sl_contribution=1,
        detail=f"Servicios fallidos: {failed}, servicios de riesgo activos: {risky}",
        remediation=(
            "Ver fallidos: sudo systemctl list-units --state=failed\n"
            "Deshabilitar: sudo systemctl disable --now <servicio>"
        ),
    ))

    # ── SR 7.8 SL1 — Inventario de componentes ──
    # Norma §11.8: inventario de componentes del sistema
    pkg_count  = fr7.get("installed_packages_count", 0)
    svc_count  = fr7.get("active_services_count", 0)
    checks.append(CheckResult(
        sr_id="SR 7.8",
        title="Inventario de componentes — paquetes y servicios documentados",
        status="pass" if pkg_count > 0 else "warning",
        sl_contribution=1,
        detail=f"Paquetes instalados: {pkg_count}, servicios activos: {svc_count}",
        remediation=(
            "Generar inventario: dpkg-query -W -f='${Package}\\t${Version}\\n' > inventory.txt\n"
            "Revisar servicios: systemctl list-units --type=service --state=active"
        ),
    ))

    result.checks            = checks
    result.sl_achieved       = _sl_from_checks(checks)
    result.compliance_percent= _compliance_percent(checks)
    result.status            = "evaluated"
    return result


# ─────────────────────────────────────────────
# Analizador principal
# ─────────────────────────────────────────────

def analyze(collection: dict) -> AnalysisReport:
    meta = collection.get("meta", {})
    report = AnalysisReport(
        hostname             = meta.get("hostname", "unknown"),
        os_name              = meta.get("os_name", "unknown"),
        os_version           = meta.get("os_version", "unknown"),
        collection_timestamp = meta.get("collection_timestamp", ""),
    )

    analyzer_map = {
        "fr1_identification":      analyze_fr1,
        "fr2_use_control":         analyze_fr2,
        "fr3_integrity":           analyze_fr3,
        "fr4_confidentiality":     analyze_fr4,
        "fr5_restricted_dataflow": analyze_fr5,
        "fr6_event_response":      analyze_fr6,
        "fr7_availability":        analyze_fr7,
    }

    for key, fn in analyzer_map.items():
        if key in collection:
            report.fr_results.append(fn(collection[key]))

    all_checks = [c for fr in report.fr_results for c in fr.checks]
    report.total_checks   = len(all_checks)
    report.passed_checks  = sum(1 for c in all_checks if c.status == "pass")
    report.failed_checks  = sum(1 for c in all_checks if c.status == "fail")
    report.warning_checks = sum(1 for c in all_checks if c.status == "warning")

    if report.fr_results:
        report.overall_sl = min(fr.sl_achieved for fr in report.fr_results)
        report.overall_compliance_percent = round(
            sum(fr.compliance_percent for fr in report.fr_results) / len(report.fr_results), 1
        )

    return report


def print_summary(report: AnalysisReport) -> None:
    STATUS_ICON = {"pass": "✓", "fail": "✗", "warning": "⚠", "unknown": "?"}
    SL_LABEL    = {
        0: "SL0 (sin protección)",
        1: "SL1 (accidental)",
        2: "SL2 (intencional simple)",
        3: "SL3 (sofisticado)",
        4: "SL4 (avanzado)",
    }
    print("\n" + "═" * 64)
    print("  IEC 62443-3-3 — INFORME DE CUMPLIMIENTO")
    print("═" * 64)
    print(f"  Host      : {report.hostname}")
    print(f"  OS        : {report.os_name} {report.os_version}")
    print(f"  Timestamp : {report.collection_timestamp}")
    print("─" * 64)
    print(f"  Security Level global : {SL_LABEL.get(report.overall_sl, str(report.overall_sl))}")
    print(f"  Cumplimiento global   : {report.overall_compliance_percent}%")
    print(f"  Checks: {report.passed_checks} ✓  {report.failed_checks} ✗  {report.warning_checks} ⚠  (total: {report.total_checks})")
    print("─" * 64)
    for fr in report.fr_results:
        sl_str = SL_LABEL.get(fr.sl_achieved, str(fr.sl_achieved))
        print(f"\n  [{fr.fr_id}] {fr.title}")
        print(f"       SL: {sl_str} | Cumplimiento: {fr.compliance_percent}%")
        for check in fr.checks:
            icon = STATUS_ICON.get(check.status, "?")
            print(f"    {icon} {check.sr_id} — {check.title}")
            if check.status in ("fail", "warning"):
                print(f"        ↳ {check.detail}")
                print(f"        ✎ {check.remediation.splitlines()[0]}")
    print("\n" + "═" * 64)


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="IEC 62443-3-3 Analyzer — Ubuntu 25.10"
    )
    parser.add_argument("--input",   "-i", default="collection_output.json")
    parser.add_argument("--output",  "-o", default="analysis_report.json")
    parser.add_argument("--summary", "-s", action="store_true")
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"[!] Archivo no encontrado: {input_path}")
        exit(1)

    collection = json.loads(input_path.read_text(encoding="utf-8"))
    report     = analyze(collection)

    if args.summary:
        print_summary(report)

    output_path = Path(args.output)
    output_path.write_text(
        json.dumps(asdict(report), indent=2, default=str), encoding="utf-8"
    )
    print(f"\n[+] Informe guardado en: {output_path.resolve()}")
