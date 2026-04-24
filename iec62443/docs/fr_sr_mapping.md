# Mapeo FR → SR — IEC 62443-3-3:2020 (Ubuntu 25.10)

Referencia normativa: UNE-EN IEC 62443-3-3:2020

## Tabla de SL-C por SR (extracto normativo)

| SR | SL1 | SL2 | SL3 | SL4 |
|----|-----|-----|-----|-----|
| SR 1.1 | ✓ base | +RE1 único | +RE2 MFA untrusted | +RE3 MFA all |
| SR 1.2 | No selec. | ✓ base | +RE1 único | +RE1 |
| SR 1.3 | ✓ base | ✓ base | +RE1 unificado | +RE1 |
| SR 1.4 | ✓ base | ✓ base | ✓ base | ✓ base |
| SR 1.5 | ✓ base | ✓ base | +RE1 hardware | +RE1 |
| SR 1.7 | ✓ base | ✓ base | +RE1 historial | +RE1+RE2 |
| SR 1.8 | No selec. | ✓ base | ✓ base | ✓ base |
| SR 1.9 | No selec. | ✓ base | +RE1 hardware | +RE1 |
| SR 1.10 | ✓ base | ✓ base | ✓ base | ✓ base |
| SR 1.11 | ✓ base | ✓ base | ✓ base | ✓ base |
| SR 1.12 | ✓ base | ✓ base | ✓ base | ✓ base |
| SR 1.13 | ✓ base | +RE1 aprobación | +RE1 | +RE1 |
| SR 2.1 | ✓ base | +RE1+RE2 | +RE1+RE2+RE3 | +RE1..RE4 |
| SR 2.2 | ✓ base | ✓ base | +RE1 detect | +RE1 |
| SR 2.3 | ✓ base | ✓ base | +RE1 estado seg | +RE1 |
| SR 2.4 | ✓ base | ✓ base | +RE1 integridad | +RE1 |
| SR 2.5 | ✓ base | ✓ base | ✓ base | ✓ base |
| SR 2.6 | No selec. | ✓ base | ✓ base | ✓ base |
| SR 2.7 | No selec. | No selec. | ✓ base | ✓ base |
| SR 2.8 | ✓ base | ✓ base | +RE1 central | +RE1 |
| SR 2.9 | ✓ base | ✓ base | +RE1 alerta | +RE1 |
| SR 2.10 | ✓ base | ✓ base | ✓ base | ✓ base |
| SR 2.11 | No selec. | ✓ base | +RE1 sync | +RE1+RE2 |
| SR 2.12 | No selec. | No selec. | ✓ base | +RE1 |
| SR 3.1 | ✓ base | ✓ base | +RE1 cripto | +RE1 |
| SR 3.2 | ✓ base | +RE1 entry | +RE1+RE2 | +RE1+RE2 |
| SR 3.3 | ✓ base | ✓ base | +RE1 auto | +RE1+RE2 |
| SR 3.4 | ✓ base | ✓ base | ✓ base | ✓ base |
| SR 3.5 | ✓ base | ✓ base | ✓ base | ✓ base |
| SR 3.7 | ✓ base | ✓ base | ✓ base | ✓ base |
| SR 3.9 | ✓ base | ✓ base | ✓ base | ✓ base |
| SR 4.1 | ✓ base | ✓ base | ✓ base | ✓ base |
| SR 4.2 | ✓ base | ✓ base | ✓ base | ✓ base |
| SR 4.3 | No selec. | ✓ base | ✓ base | ✓ base |
| SR 5.1 | ✓ base | ✓ base | ✓ base | ✓ base |
| SR 5.2 | ✓ base | ✓ base | ✓ base | ✓ base |
| SR 5.3 | ✓ base | ✓ base | ✓ base | ✓ base |
| SR 5.4 | No selec. | ✓ base | ✓ base | ✓ base |
| SR 6.1 | ✓ base | ✓ base | +RE1 central | +RE1 |
| SR 6.2 | No selec. | ✓ base | ✓ base | ✓ base |
| SR 7.1 | ✓ base | ✓ base | ✓ base | ✓ base |
| SR 7.2 | ✓ base | ✓ base | ✓ base | ✓ base |
| SR 7.3 | ✓ base | ✓ base | ✓ base | ✓ base |
| SR 7.4 | ✓ base | ✓ base | ✓ base | ✓ base |
| SR 7.5 | ✓ base | ✓ base | ✓ base | ✓ base |
| SR 7.6 | ✓ base | ✓ base | ✓ base | ✓ base |
| SR 7.7 | ✓ base | ✓ base | ✓ base | ✓ base |
| SR 7.8 | No selec. | ✓ base | ✓ base | ✓ base |

---

## FR1 — Control de identificación y autenticación (IAC)

| SR | RE | Descripción | SL | Control en Ubuntu 25.10 |
|----|----|-------------|-----|--------------------------|
| SR 1.1 | — | Identificación y autenticación de usuarios humanos | SL1 | Usuarios con shell de login (`/etc/passwd`) |
| SR 1.1 | RE1 | Identificación y autenticación únicas | SL2 | Sin UIDs duplicados en `/etc/passwd` |
| SR 1.1 | RE2 | MFA para redes no confiables | SL3 | `pam_google_authenticator` / `pam_u2f` en sshd |
| SR 1.1 | RE3 | MFA para todas las redes | SL4 | MFA en login local + SSH |
| SR 1.2 | — | Identificación de procesos y dispositivos | SL2 | Cuentas de servicio con nologin, no ejecutar como root |
| SR 1.3 | — | Gestión de cuentas | SL1 | Grupo sudo acotado (≤3), cuentas activas documentadas |
| SR 1.3 | RE1 | Gestión de cuentas unificada | SL3 | Sin cuentas sin contraseña activas |
| SR 1.4 | — | Gestión de identificadores | SL1 | UIDs únicos, cuentas inactivas bloqueadas (`usermod -L`) |
| SR 1.5 | — | Gestión de autenticadores | SL1 | `PASS_MAX_DAYS ≤ 365`, `PASS_WARN_AGE ≥ 7` |
| SR 1.7 | — | Fortaleza de contraseña base | SL1 | `pam_pwquality minlen ≥ 8` |
| SR 1.7 | RE1 | Historial, complejidad y caducidad | SL3 | `minlen=12, minclass=3, remember=5, MAX_DAYS=90` |
| SR 1.8 | — | PKI / SSH clave pública | SL2 | `PubkeyAuthentication yes`, `PasswordAuthentication no`, `PermitRootLogin no` |
| SR 1.9 | — | Fortaleza autenticación clave pública | SL2 | Ed25519 / RSA ≥ 3072, sin DSA/DSS |
| SR 1.10 | — | Retroalimentación del autenticador | SL1 | SSH `LogLevel INFO`, `pam_faildelay ≥ 2s` |
| SR 1.11 | — | Intentos fallidos de login | SL1 | `pam_faillock deny=5 fail_interval=900 unlock_time=600` |
| SR 1.12 | — | Aviso de uso del sistema | SL1 | `Banner /etc/ssh/banner.txt` + `/etc/issue.net` |
| SR 1.13 | — | Acceso por redes no confiables | SL1 | SSH `MaxAuthTries ≤ 4` |
| SR 1.13 | RE1 | Aprobación explícita de solicitud de acceso | SL2 | VPN (WireGuard/OpenVPN) o bastion host |

## FR2 — Control de uso (UC)

| SR | RE | Descripción | SL | Control en Ubuntu 25.10 |
|----|----|-------------|-----|--------------------------|
| SR 2.1 | — | Aplicación de la autorización | SL1 | Sin `NOPASSWD` irrestricto en sudoers |
| SR 2.1 | RE1 | Autorización para todos los usuarios (MAC) | SL2 | `AppArmor` en modo enforce (perfiles activos) |
| SR 2.2 | — | Control de uso inalámbrico | SL1 | WiFi gestionado por NetworkManager o deshabilitado |
| SR 2.3 | — | Control de dispositivos portátiles/móviles | SL1 | `usb-storage` en lista negra (`/etc/modprobe.d/`) |
| SR 2.4 | — | Control de código móvil | SL1 | seccomp disponible, AppArmor para runtimes |
| SR 2.5 | — | Bloqueo de sesión inactiva | SL1 | `TMOUT=900` en `/etc/profile.d/tmout.sh` |
| SR 2.6 | — | Terminar sesión remota | SL2 | Eliminar telnet/rsh/rlogin, puertos ≤ 5 |
| SR 2.7 | — | Control de sesiones simultáneas | SL3 | `nproc hard limit`, SSH `MaxSessions` |
| SR 2.8 | — | Eventos auditables | SL1 | `auditd` activo con reglas definidas |
| SR 2.8 | RE1 | Pista de auditoría centralizada | SL3 | Categorías cubiertas: acceso, SO, config, ejecución |
| SR 2.9 | — | Capacidad de almacenamiento de auditoría | SL1 | `max_log_file ≥ 8MB`, `num_logs ≥ 5` |
| SR 2.10 | — | Respuesta a fallos de auditoría | SL1 | `disk_full_action = rotate`, `disk_error_action = syslog` |
| SR 2.11 | — | Marcas de tiempo (NTP) | SL2 | `NTPSynchronized=yes` (chrony o timesyncd) |
| SR 2.11 | RE1 | Sincronización interna configurable | SL3 | Servidores NTP explícitos en `timesyncd.conf` |
| SR 2.12 | — | No rechazo | SL3 | Reglas auditd inmutables (`-e 2`) + rsyslog activo |

## FR3 — Integridad del sistema (SI)

| SR | RE | Descripción | SL | Control en Ubuntu 25.10 |
|----|----|-------------|-----|--------------------------|
| SR 3.1 | — | Integridad de la comunicación | SL1 | SSH MACs sin md5/sha1/etm débiles |
| SR 3.1 | RE1 | Protección criptográfica de integridad | SL3 | OpenSSL ≥ 1.1.1 / 3.x |
| SR 3.2 | — | Protección contra código malicioso | SL1 | ClamAV instalado y actualizado |
| SR 3.2 | RE1 | Protección en puntos de entrada/salida | SL2 | rkhunter/chkrootkit |
| SR 3.3 | — | Verificación de funcionalidad de seguridad | SL2 | AIDE configurado con BD inicial |
| SR 3.4 | — | Integridad del software (firmas APT) | SL1 | Sin `AllowUnauthenticated` en apt.conf.d |
| SR 3.4 | — | Secure Boot | SL3 | `mokutil --sb-state` = enabled |
| SR 3.5 | — | Validación de entrada (red) | SL2 | `rp_filter=1`, no source routing, no redirects |
| SR 3.5 | — | Kernel hardening | SL2 | ASLR=2, dmesg_restrict=1, kptr_restrict=2, yama=1 |
| SR 3.7 | — | Tratamiento de errores | SL2 | apport deshabilitado, core dumps deshabilitados |
| SR 3.9 | — | Protección de información de auditoría | SL2 | `/var/log/audit` permisos 700, logging remoto |

## FR4 — Confidencialidad de datos (DC)

| SR | RE | Descripción | SL | Control en Ubuntu 25.10 |
|----|----|-------------|-----|--------------------------|
| SR 4.1 | — | Confidencialidad en tránsito | SL1 | OpenSSL ≥ 1.1.1, sin 3DES/RC4 en SSH |
| SR 4.1 | — | SSH sin cifrados débiles | SL2 | Ciphers restringidos en `sshd_config` |
| SR 4.2 | — | Confidencialidad en reposo (LUKS) | SL2 | `cryptsetup luksFormat` / Ubuntu installer encryption |
| SR 4.2 | — | Permisos archivos sensibles | SL1/2 | `/etc/shadow 640`, `sshd_config 600`, `sudoers 440` |
| SR 4.3 | — | Uso de criptografía | SL2 | Política criptográfica no LEGACY (OpenSSL 3.x default) |

## FR5 — Flujo restringido de datos (RDF)

| SR | RE | Descripción | SL | Control en Ubuntu 25.10 |
|----|----|-------------|-----|--------------------------|
| SR 5.1 | — | Segmentación de red — firewall activo | SL1 | UFW activo / nftables tablas definidas |
| SR 5.1 | — | Política deny-by-default | SL2 | `ufw default deny incoming` |
| SR 5.1 | — | Reglas explícitas definidas | SL2 | ≥2 reglas UFW |
| SR 5.2 | — | Protección de límites de zona | SL2 | fail2ban activo con ≥1 jail |
| SR 5.3 | — | Separación de red (no routing) | SL1 | `ip_forward=0`, `ipv6 forwarding=0` |
| SR 5.4 | — | Partición de aplicaciones | SL2 | Docker/LXD/nspawn disponible |

## FR6 — Respuesta oportuna a eventos (TRE)

| SR | RE | Descripción | SL | Control en Ubuntu 25.10 |
|----|----|-------------|-----|--------------------------|
| SR 6.1 | — | Accesibilidad de registros de auditoría | SL1 | auditd activo + rsyslog + logrotate |
| SR 6.1 | — | Reglas de auditoría definidas | SL2 | ≥5 reglas activas en auditctl |
| SR 6.1 | — | Watches en archivos críticos | SL2 | `-w /etc/passwd -w /etc/shadow -w /etc/ssh` |
| SR 6.2 | — | Supervisión continua (IDS/IPS) | SL2 | fail2ban / suricata / snort |
| SR 6.2 | — | NTP sincronizado (correlación temporal) | SL1 | `NTPSynchronized=yes` |

## FR7 — Disponibilidad de recursos (RA)

| SR | RE | Descripción | SL | Control en Ubuntu 25.10 |
|----|----|-------------|-----|--------------------------|
| SR 7.1 | — | Protección contra DoS | SL1 | `tcp_syncookies=1`, `tcp_rfc1337=1` |
| SR 7.2 | — | Gestión de recursos | SL1 | Memoria disponible >20%, swap configurado |
| SR 7.3 | — | Copia de seguridad | SL2 | restic/rsync/borgbackup + cron |
| SR 7.4 | — | Recuperación del sistema | SL2 | Timeshift snapshots, herramientas de recovery |
| SR 7.5 | — | Alimentación de emergencia | SL1 | NUT/apcupsd o riesgo documentado |
| SR 7.6 | — | Configuración de red y seguridad | SL1 | sysctl.d con configs de hardening |
| SR 7.7 | — | Funcionalidad mínima | SL1 | Sin servicios fallidos, sin telnet/ftp/rsh activos |
| SR 7.8 | — | Inventario de componentes | SL2 | `dpkg-query` + `systemctl list-units` documentado |

---

## Cambios vs versión anterior

### SRs añadidos
- **SR 1.2** Identificación de procesos de software (§5.4)
- **SR 1.4** Gestión de identificadores — unicidad de UIDs (§5.6)
- **SR 1.5** Gestión de autenticadores — caducidad y aviso (§5.7, antes mezclado en SR 1.7)
- **SR 1.7 RE1** Historial de contraseñas y restricciones de vigencia (§5.9.3.1)
- **SR 1.9** Fortaleza autenticación clave pública — tipos de host key (§5.11)
- **SR 1.10** Retroalimentación del autenticador — LogLevel y faildelay (§5.12)
- **SR 1.11** Intentos fallidos de login — pam_faillock (§5.13)
- **SR 1.12** Aviso de uso del sistema — Banner SSH + issue.net (§5.14)
- **SR 1.13** Acceso por redes no confiables — MaxAuthTries + VPN (§5.15)
- **SR 2.2** Control de uso inalámbrico (§6.4)
- **SR 2.3** Control de dispositivos portátiles — USB blacklist (§6.5)
- **SR 2.4** Control de código móvil — seccomp (§6.6)
- **SR 2.5** Bloqueo de sesión inactiva — TMOUT (§6.7)
- **SR 2.6** Terminar sesión remota — protocolos inseguros (§6.8)
- **SR 2.7** Control de sesiones simultáneas — nproc limit (§6.9, sólo SL3+)
- **SR 2.8 RE1** Pista de auditoría por categorías (§6.10.3.1)
- **SR 2.9** Capacidad de almacenamiento de auditoría (§6.11)
- **SR 2.10** Respuesta a fallos de auditoría (§6.12)
- **SR 2.11** Marcas de tiempo NTP — movido a FR2 (§6.13, sólo desde SL2)
- **SR 2.12** No rechazo — reglas inmutables + syslog (§6.14, sólo SL3+)
- **SR 3.1** Integridad de comunicación — MACs SSH (§7.3)
- **SR 3.5** Validación de entrada de red — sysctl (§7.7)
- **SR 3.7** Tratamiento de errores — core dumps (§7.9)
- **SR 3.9** Protección de logs de auditoría (§7.11)
- **SR 4.3** Uso de criptografía — política crypto (§8.5)
- **SR 5.2** Protección de límites de zona — fail2ban (§9.4)
- **SR 5.4** Partición de aplicaciones — contenedores (§9.7, sólo SL2+)
- **SR 6.2** Supervisión continua — IDS/IPS (§10.4)
- **SR 7.4** Recuperación del sistema — Timeshift (§11.4)
- **SR 7.5** Alimentación de emergencia — NUT/UPS (§11.5)
- **SR 7.6** Configuración de red y seguridad — sysctl.d (§11.6)
- **SR 7.8** Inventario de componentes — dpkg+systemctl (§11.8)

### Correcciones de mapeo SL-C
- **SR 1.8** ahora empieza en SL2 (antes se asignaba desde SL1, incorrecto per §5.10.4)
- **SR 2.6** ahora empieza en SL2 (§6.8.4 "No seleccionado" para SL1)
- **SR 2.7** ahora sólo desde SL3 (§6.9.4)
- **SR 2.11** ahora desde SL2 (§6.13.4 "No seleccionado" para SL1)
- **SR 2.12** ahora desde SL3 (§6.14.4)
- **SR 5.4** desde SL2 (§9.7.4)
- **SR 6.2** desde SL2 (§10.4.4)
