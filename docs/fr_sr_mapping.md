# Mapeo FR → SR implementados

## FR1 — Identificación y autenticación

| SR | Descripción | SL | Control en Ubuntu |
|----|-------------|----|--------------------|
| SR 1.1 | Identificación de usuarios humanos | SL1 | Usuarios con shell de login |
| SR 1.3 | Gestión de cuentas privilegiadas | SL1 | Miembros del grupo sudo |
| SR 1.7 | Caducidad de contraseñas | SL1/SL2 | `/etc/login.defs` PASS_MAX_DAYS |
| SR 1.7 | Complejidad de contraseñas | SL2 | `pam_pwquality` minlen, minclass |
| SR 1.8 | Sin contraseñas vacías | SL1 | `sshd_config` PermitEmptyPasswords |
| SR 1.8 | Autenticación por clave pública | SL2 | `sshd_config` PubkeyAuthentication |
| SR 1.8 | Login root prohibido | SL2 | `sshd_config` PermitRootLogin |
| SR 1.8 | MFA configurado | SL3 | pam_google_authenticator / pam_oath |

## FR2 — Control de uso

| SR | Descripción | SL | Control en Ubuntu |
|----|-------------|----|--------------------|
| SR 2.1 | Control de privilegios sudo | SL1 | Ausencia de NOPASSWD en sudoers |
| SR 2.1 | MAC — AppArmor enforce | SL2 | `apparmor_status` perfiles enforce |
| SR 2.6 | Timeout de sesión inactiva | SL1 | TMOUT en `/etc/profile` |
| SR 2.6 | Superficie de ataque (puertos) | SL2 | `ss -tulnp` ≤5 puertos |
| SR 2.7 | Protocolos remotos inseguros | SL2 | Ausencia de telnet/rsh/rlogin |

## FR3 — Integridad del sistema

| SR | Descripción | SL | Control en Ubuntu |
|----|-------------|----|--------------------|
| SR 3.2 | Antimalware instalado | SL1 | ClamAV |
| SR 3.3 | Monitor de integridad (FIM) | SL2 | AIDE / Tripwire |
| SR 3.3 | Detección de rootkits | SL2 | rkhunter / chkrootkit |
| SR 3.3 | ASLR activado | SL2 | `kernel.randomize_va_space=2` |
| SR 3.3 | Restricciones de info del kernel | SL2 | `dmesg_restrict`, `kptr_restrict` |
| SR 3.4 | Verificación firma paquetes APT | SL1 | AllowUnauthenticated=false |
| SR 3.4 | Secure Boot | SL3 | mokutil --sb-state |

## FR4 — Confidencialidad de datos

| SR | Descripción | SL | Control en Ubuntu |
|----|-------------|----|--------------------|
| SR 4.1 | OpenSSL moderno | SL1 | openssl version ≥1.1.1 / 3.x |
| SR 4.1 | Sin cifrados SSH débiles | SL2 | Ausencia de 3des-cbc, rc4... |
| SR 4.2 | Cifrado de disco (LUKS) | SL2 | lsblk type=crypt |
| SR 4.2 | Permisos /etc/shadow | SL1 | chmod 640 |
| SR 4.2 | Permisos sshd_config | SL2 | chmod 600 |

## FR5 — Flujo restringido de datos

| SR | Descripción | SL | Control en Ubuntu |
|----|-------------|----|--------------------|
| SR 5.1 | Firewall activo | SL1 | UFW / iptables / nftables |
| SR 5.1 | Política deny incoming | SL2 | UFW default deny incoming |
| SR 5.1 | Reglas explícitas definidas | SL2 | ufw status ≥2 reglas |
| SR 5.3 | IP forwarding desactivado | SL1 | `net.ipv4.ip_forward=0` |

## FR6 — Respuesta oportuna a eventos

| SR | Descripción | SL | Control en Ubuntu |
|----|-------------|----|--------------------|
| SR 6.1 | auditd activo | SL1 | systemctl is-active auditd |
| SR 6.1 | Reglas de auditoría | SL2 | auditctl -l ≥5 reglas |
| SR 6.1 | rsyslog/syslog-ng activo | SL1 | systemctl is-active rsyslog |
| SR 6.1 | Logrotate configurado | SL2 | /etc/logrotate.conf existe |
| SR 6.2 | NTP sincronizado | SL1 | timedatectl NTPSynchronized=yes |

## FR7 — Disponibilidad de recursos

| SR | Descripción | SL | Control en Ubuntu |
|----|-------------|----|--------------------|
| SR 7.1 | SYN cookies activas | SL1 | `net.ipv4.tcp_syncookies=1` |
| SR 7.2 | Memoria disponible >20% | SL1 | /proc/meminfo MemAvailable |
| SR 7.3 | Herramienta de backup | SL2 | restic / rsync / borg... |
| SR 7.7 | Sin servicios fallidos | SL1 | systemctl --state=failed |
