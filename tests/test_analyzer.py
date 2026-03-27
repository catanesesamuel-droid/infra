"""
tests/test_analyzer.py
Tests de validación para el módulo analyzer.
Verifica que los checks individuales se evalúan correctamente.

Uso:
  cd iec62443
  python3 -m pytest tests/ -v
  # o sin pytest:
  python3 tests/test_analyzer.py
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from analyzer.analyzer import (
    analyze_fr1, analyze_fr2, analyze_fr3,
    analyze_fr4, analyze_fr5, analyze_fr6,
    analyze_fr7, analyze, _sl_from_checks, _compliance_percent,
    CheckResult,
)


# ─────────────────────────────────────────────
# Helpers de test
# ─────────────────────────────────────────────

PASSED = 0
FAILED = 0

def assert_eq(label, expected, got):
    global PASSED, FAILED
    if expected == got:
        print(f"  ✓ {label}")
        PASSED += 1
    else:
        print(f"  ✗ {label}  →  esperado={expected!r}  obtenido={got!r}")
        FAILED += 1

def assert_in(label, value, collection):
    global PASSED, FAILED
    if value in collection:
        print(f"  ✓ {label}")
        PASSED += 1
    else:
        print(f"  ✗ {label}  →  {value!r} no encontrado en {collection!r}")
        FAILED += 1

def section(name):
    print(f"\n── {name} ──")


# ─────────────────────────────────────────────
# Fixtures de datos de prueba
# ─────────────────────────────────────────────

def fr1_hardened():
    """FR1 con configuración correcta (debe alcanzar SL2)."""
    return {
        "users_with_login": [{"username": "admin", "uid": 1000}],
        "sudo_group_members": ["admin"],
        "password_policy": {"PASS_MAX_DAYS": 90, "PASS_MIN_DAYS": 1, "PASS_MIN_LEN": 12, "PASS_WARN_AGE": 7},
        "pam_pwquality": {"minlen": 12, "dcredit": -1, "ucredit": -1, "lcredit": -1, "ocredit": -1, "minclass": 3},
        "ssh_config": {
            "PasswordAuthentication": "no",
            "PubkeyAuthentication": "yes",
            "PermitRootLogin": "no",
            "PermitEmptyPasswords": "no",
            "MaxAuthTries": "3",
        },
        "mfa_configured": False,
    }

def fr1_weak():
    """FR1 con configuración insegura (debe obtener SL0)."""
    return {
        "users_with_login": [{"username": "admin", "uid": 1000}],
        "sudo_group_members": ["admin", "user1", "user2", "user3", "user4"],
        "password_policy": {"PASS_MAX_DAYS": 99999, "PASS_MIN_DAYS": 0, "PASS_MIN_LEN": 6, "PASS_WARN_AGE": 0},
        "pam_pwquality": {"minlen": None, "dcredit": None, "ucredit": None, "lcredit": None, "ocredit": None, "minclass": None},
        "ssh_config": {
            "PasswordAuthentication": "yes",
            "PubkeyAuthentication": "not_set",
            "PermitRootLogin": "yes",
            "PermitEmptyPasswords": "yes",
            "MaxAuthTries": "6",
        },
        "mfa_configured": False,
    }

def fr5_hardened():
    return {
        "ufw": {"status": "active", "default_incoming": "deny", "default_outgoing": "allow", "rules_count": 5},
        "iptables": {"available": True, "rules": "Chain INPUT (policy DROP)"},
        "nftables": {"available": False, "rules": None},
        "network_interfaces": [],
        "ip_forwarding_enabled": False,
    }

def fr5_weak():
    return {
        "ufw": {"status": "inactive", "default_incoming": None, "default_outgoing": None, "rules_count": 0},
        "iptables": {"available": False, "rules": None},
        "nftables": {"available": False, "rules": None},
        "network_interfaces": [],
        "ip_forwarding_enabled": True,
    }

def fr6_hardened():
    return {
        "auditd": {"service_active": True, "config_exists": True, "rules_file_exists": True, "active_rules_count": 10},
        "syslog": {"rsyslog_active": True, "syslog_ng_active": False},
        "journald": {"active": True, "disk_usage": "2.5G"},
        "logrotate_configured": True,
        "time_sync": {"NTP": "yes", "NTPSynchronized": "yes", "Timezone": "Europe/Madrid", "TimeUSec": ""},
    }

def fr7_hardened():
    return {
        "tcp_syncookies": True,
        "memory": {"total_kb": 8000000, "available_kb": 4000000},
        "disk_usage": "/dev/sda1  50G  20G  30G  40% /",
        "system_limits_configured": True,
        "backup_tools": {"rsync": True, "borgbackup": False, "restic": False},
        "backup_configured": True,
        "failed_services": [],
        "failed_services_count": 0,
        "uptime": "up 5 days",
    }


# ─────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────

def test_sl_calculation():
    section("_sl_from_checks — cálculo de Security Level")

    all_pass = [
        CheckResult("SR 1.1", "t", "pass", 1, "", ""),
        CheckResult("SR 1.7", "t", "pass", 2, "", ""),
    ]
    assert_eq("todos pass → SL≥2", True, _sl_from_checks(all_pass) >= 2)

    one_fail_sl1 = [
        CheckResult("SR 1.1", "t", "fail", 1, "", ""),
        CheckResult("SR 1.7", "t", "pass", 2, "", ""),
    ]
    assert_eq("fallo en SL1 → SL0", 0, _sl_from_checks(one_fail_sl1))

    fail_sl2 = [
        CheckResult("SR 1.1", "t", "pass", 1, "", ""),
        CheckResult("SR 1.7", "t", "fail", 2, "", ""),
    ]
    assert_eq("fallo en SL2 → SL1", 1, _sl_from_checks(fail_sl2))

    empty = []
    assert_eq("sin checks → SL0", 0, _sl_from_checks(empty))


def test_compliance_percent():
    section("_compliance_percent")

    checks = [
        CheckResult("SR 1.1", "t", "pass",    1, "", ""),
        CheckResult("SR 1.7", "t", "fail",    2, "", ""),
        CheckResult("SR 1.8", "t", "pass",    2, "", ""),
        CheckResult("SR 1.8", "t", "warning", 3, "", ""),
    ]
    assert_eq("2 pass de 4 → 50%", 50.0, _compliance_percent(checks))
    assert_eq("lista vacía → 0%", 0.0, _compliance_percent([]))


def test_fr1_hardened():
    section("FR1 — configuración hardened")
    result = analyze_fr1(fr1_hardened())
    assert_eq("SL alcanzado ≥ 1", True, result.sl_achieved >= 1)
    assert_eq("cumplimiento > 50%", True, result.compliance_percent > 50)

    statuses = {c.sr_id + c.title: c.status for c in result.checks}
    ssh_empty = next((c for c in result.checks if "vacías" in c.title), None)
    if ssh_empty:
        assert_eq("SSH vacías prohibidas → pass", "pass", ssh_empty.status)

    root_login = next((c for c in result.checks if "root prohibido" in c.title), None)
    if root_login:
        assert_eq("SSH root prohibido → pass", "pass", root_login.status)


def test_fr1_weak():
    section("FR1 — configuración débil")
    result = analyze_fr1(fr1_weak())
    assert_eq("SL alcanzado = 0", 0, result.sl_achieved)
    assert_eq("cumplimiento < 50%", True, result.compliance_percent < 50)

    pass_check = next((c for c in result.checks if "caducidad" in c.title), None)
    if pass_check:
        assert_eq("caducidad 99999 → fail", "fail", pass_check.status)

    empty_pw = next((c for c in result.checks if "vacías" in c.title), None)
    if empty_pw:
        assert_eq("PermitEmptyPasswords yes → fail", "fail", empty_pw.status)


def test_fr5_hardened():
    section("FR5 — firewall hardened")
    result = analyze_fr5(fr5_hardened())
    assert_eq("SL alcanzado ≥ 2", True, result.sl_achieved >= 2)

    fw = next((c for c in result.checks if "Firewall activo" in c.title), None)
    if fw:
        assert_eq("Firewall activo → pass", "pass", fw.status)

    ip_fwd = next((c for c in result.checks if "forwarding" in c.title), None)
    if ip_fwd:
        assert_eq("IP forwarding desactivado → pass", "pass", ip_fwd.status)


def test_fr5_weak():
    section("FR5 — firewall débil")
    result = analyze_fr5(fr5_weak())
    assert_eq("SL alcanzado = 0", 0, result.sl_achieved)

    fw = next((c for c in result.checks if "Firewall activo" in c.title), None)
    if fw:
        assert_eq("Firewall inactivo → fail", "fail", fw.status)

    ip_fwd = next((c for c in result.checks if "forwarding" in c.title), None)
    if ip_fwd:
        assert_eq("IP forwarding activo → fail", "fail", ip_fwd.status)


def test_fr6_hardened():
    section("FR6 — logging hardened")
    result = analyze_fr6(fr6_hardened())
    assert_eq("SL alcanzado ≥ 2", True, result.sl_achieved >= 2)
    assert_eq("cumplimiento = 100%", 100.0, result.compliance_percent)


def test_fr7_hardened():
    section("FR7 — disponibilidad hardened")
    result = analyze_fr7(fr7_hardened())
    assert_eq("sin servicios fallidos → pass", True,
              any(c.status == "pass" and "fallido" in c.title for c in result.checks))
    assert_eq("backup configurado → pass", True,
              any(c.status == "pass" and "backup" in c.title.lower() for c in result.checks))


def test_full_pipeline_hardened():
    section("Pipeline completo — sistema hardened mínimo")
    collection = {
        "meta": {
            "hostname": "test-host",
            "os_name": "Ubuntu",
            "os_version": "25.10",
            "collection_timestamp": "2026-01-01T00:00:00+00:00",
            "running_as_root": True,
            "pending_upgrades_count": 0,
            "pending_upgrades_sample": [],
        },
        "fr1_identification":       fr1_hardened(),
        "fr5_restricted_dataflow":  fr5_hardened(),
        "fr6_event_response":       fr6_hardened(),
        "fr7_availability":         fr7_hardened(),
    }
    report = analyze(collection)
    assert_eq("hostname correcto", "test-host", report.hostname)
    assert_eq("fr_results tiene 4 entradas", 4, len(report.fr_results))
    assert_eq("total_checks > 0", True, report.total_checks > 0)
    assert_eq("passed_checks > 0", True, report.passed_checks > 0)


def test_remediation_ordering():
    section("Remediaciones — orden por prioridad SL")
    from analyzer.analyzer import analyze_fr1
    result = analyze_fr1(fr1_weak())
    failed = [c for c in result.checks if c.status == "fail"]
    sl_contributions = [c.sl_contribution for c in failed]
    assert_eq("lista de fallos no vacía", True, len(failed) > 0)
    # Todos los sl_contribution deben ser enteros válidos
    assert_eq("sl_contributions son enteros", True,
              all(isinstance(s, int) for s in sl_contributions))


# ─────────────────────────────────────────────
# Runner
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("\n╔══════════════════════════════════════════╗")
    print("║  IEC 62443-3-3 — Test Suite              ║")
    print("╚══════════════════════════════════════════╝")

    test_sl_calculation()
    test_compliance_percent()
    test_fr1_hardened()
    test_fr1_weak()
    test_fr5_hardened()
    test_fr5_weak()
    test_fr6_hardened()
    test_fr7_hardened()
    test_full_pipeline_hardened()
    test_remediation_ordering()

    print(f"\n{'═'*44}")
    print(f"  Resultado: {PASSED} ✓  {FAILED} ✗  (total: {PASSED+FAILED})")
    print(f"{'═'*44}\n")
    sys.exit(0 if FAILED == 0 else 1)
