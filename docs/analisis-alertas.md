# docs/analisis-alertas.md

# Análisis de alertas SOC

> Documento de triage elaborado con el formato utilizado por un analista SOC L1 para revisar las alertas más relevantes del laboratorio.

---

## Resumen ejecutivo

- Total de alertas analizadas: 4
- Patrón recurrente: el mismo origen externo (`10.10.10.40`) aparece en varios eventos de reconocimiento y acceso.
- Impacto principal: compromiso de credenciales y preparación para persistencia administrativa.
- Severidades observadas: 2 altas, 2 medias.
- Resultado clave: el laboratorio demuestra una cadena completa de ataque consistente con reconocimiento, fuerza bruta, acceso no autorizado y preparación de persistencia.

### Síntesis rápida

| Alerta | Tipo | Severidad | Estado | Actor principal |
|---|---|---:|---|---|
| 1 | Fuerza bruta SSH | Alta | Comprometida la contraseña | `10.10.10.40` |
| 2 | Escaneo de puertos | Media | Reconocimiento previo al ataque | `10.10.10.40` |
| 3 | Fallos de logon RDP | Media | Intento sin éxito | `10.10.10.40` |
| 4 | Cuenta añadida a Administrators | Alta | Persistencia administrativa sospechosa | local en `win-server` |

### Hallazgos principales

- La secuencia de eventos sugiere un ataque dirigido y progresivo.
- El atacante realizó reconocimiento inicial, validó acceso a servicios críticos y luego intentó establecer persistencia.
- Los indicadores de compromiso coinciden con tácticas típicas de `credential access`, `reconnaissance` y `persistence`.

---

## Alerta 1 — Fuerza bruta SSH

| Campo | Contenido |
|---|---|
| Alerta / regla | `100101` · LAB: fuerza bruta SSH (nivel 12) |
| Fecha y agente | 17 Oct 2026, 18:28:46 – 18:30:55 UTC · `ubuntu-victim` |
| Origen y destino | `10.10.10.40` (kali-attacker) → `10.10.10.20:22` (ubuntu-victim), usuario `labuser` |
| Evidencia | 41 alertas de la regla `100101` disparadas en ~2 minutos, cada una describiendo "fuerza bruta SSH desde 10.10.10.40 (8 fallos en 2 min)"; ataque ejecutado con `hydra -l labuser -P ~/pass.txt -t 4 ssh://10.10.10.20` |
| Técnica MITRE | T1110.001 · Credential Access · Password Guessing |
| Evaluación | Verdadero positivo. El patrón de fallos repetidos desde una sola IP externa al rango de administración, en una ventana muy corta, coincide exactamente con un ataque de diccionario automatizado; no hay actividad legítima que explique 300 intentos de login en minutos |
| Severidad y decisión | Alta (nivel 12). La contraseña fue comprometida (`sunshine`, encontrada por Hydra). En un entorno real: escalar a L2 de inmediato y forzar cambio de contraseña del usuario `labuser` |
| Acción recomendada | Deshabilitar autenticación por contraseña (usar solo llaves SSH), limitar intentos con fail2ban o la respuesta activa de Wazuh, y aplicar MFA si el servicio lo permite |

## Alerta 2 — Escaneo de puertos

| Campo | Contenido |
|---|---|
| Alerta / regla | `100100` · LAB: posible escaneo de puertos (Suricata) |
| Fecha y agente | 17 Oct 2026, ~16:27:00 UTC · `ubuntu-victim` |
| Origen y destino | `10.10.10.40` (kali-attacker) → `10.10.10.20` (ubuntu-victim), los 65.535 puertos TCP |
| Evidencia | 34.281 alertas de Suricata (regla `sid:1000001`, "LAB Possible port scan (SYN)") escaladas por Wazuh con la regla `100100`; ataque ejecutado con `nmap -sS -sV -p- -T4 10.10.10.20`, que reportó los puertos 22 (SSH) y 80 (HTTP) abiertos |
| Técnica MITRE | T1046 · Discovery · Network Service Discovery |
| Evaluación | Verdadero positivo. Un host externo consultando miles de puertos en segundos es el patrón clásico de reconocimiento previo a un ataque dirigido |
| Severidad y decisión | Media (nivel 10). No hay explotación todavía, solo reconocimiento. Monitorear al origen y correlacionar con actividad posterior del mismo IP (en este laboratorio, el mismo origen reaparece en la Alerta 1) |
| Acción recomendada | Bloquear o limitar la IP origen a nivel de firewall perimetral, revisar si los servicios expuestos (SSH, HTTP) son realmente necesarios desde el exterior, y correlacionar escaneos con intentos de explotación posteriores |

## Alerta 3 — Fallos de logon RDP

| Campo | Contenido |
|---|---|
| Alerta / regla | `60122` · Logon Failure - Unknown user or bad password (nivel 5) |
| Fecha y agente | 17 Oct 2026, 21:44:53 – 21:45:45 UTC · `win-server` |
| Origen y destino | `10.10.10.40` (kali-attacker) → `10.10.10.30:3389` (win-server), usuario `Administrator` |
| Evidencia | 29 eventos de Windows (ID 4625) decodificados por la regla `60122`, uno por cada contraseña fallida; ataque ejecutado con `hydra -t 1 -l Administrator -P ~/pass30.txt rdp://10.10.10.30`, que finalizó sin encontrar una contraseña válida (`0 valid password found`) |
| Técnica MITRE | T1110 · Credential Access · Brute Force |
| Evaluación | Verdadero positivo como intento de ataque, sin éxito. Los 29 fallos consecutivos en ~1 minuto, contra una cuenta administrativa, descartan un simple error de tipeo de un usuario legítimo |
| Severidad y decisión | Media (nivel 5 por evento individual). El ataque no comprometió la cuenta — la contraseña real de `Administrator` resistió el diccionario de 30 claves comunes —, pero el intento queda registrado y debe monitorearse por si el origen reintenta con un diccionario más grande |
| Acción recomendada | Restringir el acceso RDP solo a IPs de administración conocidas (VPN o bastion host), habilitar Network Level Authentication, y considerar un umbral de bloqueo de cuenta tras N intentos fallidos |

## Alerta 4 — Cuenta agregada a Administrators

| Campo | Contenido |
|---|---|
| Alerta / regla | `100102` · LAB: usuario agregado a Administrators |
| Fecha y agente | 17 Oct 2026, 22:18:45 UTC · `win-server` |
| Origen y destino | Ejecutado localmente en `win-server`, cuenta `labbackdoor` agregada al grupo `Administrators` |
| Evidencia | 1 alerta de la regla `100102` ("LAB: usuario agregado al grupo Administrators en WIN-1NBQC1DP..."), nivel 12, generada tras `net user labbackdoor "P@ssw0rd-Lab1" /add` y `net localgroup Administrators labbackdoor /add` (eventos de Windows 4720 y 4732 subyacentes) |
| Técnica MITRE | T1136.001 · T1098 |
| Evaluación | Verdadero positivo. La creación de una cuenta nueva y su adición inmediata al grupo Administrators, fuera de cualquier proceso de aprovisionamiento conocido, es evidencia directa de un intento de establecer persistencia con privilegios elevados |
| Severidad y decisión | Alta (nivel 12). Escalar de inmediato a L2/IR: esta alerta indica que el atacante ya tiene, o está intentando asegurar, acceso administrativo persistente al sistema |
| Acción recomendada | Eliminar la cuenta no autorizada de inmediato (`net user labbackdoor /delete`), auditar qué otras acciones se realizaron con las credenciales comprometidas, y revisar la política de creación de cuentas administrativas |

---

## Conclusión general

El conjunto de alertas forma una narrativa coherente de un ataque en varias fases: reconocimiento inicial, fuerza bruta contra servicios expuestos, intento de acceso a cuentas privilegiadas y finalmente una actividad orientada a persistencia administrativa. La correlación entre el origen recurrente (`10.10.10.40`) y la progresión del impacto refuerza la evaluación de verdadero positivo en cada caso.

Desde una perspectiva operativa, la respuesta más apropiada habría sido: contención inmediata del origen, bloqueo de servicios expuestos, revisión de cuentas involucradas y fortalecimiento de políticas de acceso, autenticación y monitorización. El laboratorio resultó especialmente útil para validar cómo un SOC L1 debe priorizar eventos, correlacionar evidencia y documentar decisiones con base técnica.
