#!/usr/bin/env bash
# Один прогон на ЖЕРТВЕ.  Запуск:  sudo ./trial.sh eltex on 7
# аргументы: стенд (eltex|cit), DAI (on|off), номер прогона (1..20)
set -u
STAND=$1; DAI=$2; N=$3
IF=enp3s0
GW=192.168.10.1
GW_MAC=00:23:ab:87:de:41
KALI_MAC=08:00:27:ce:96:be
SENT=100                                   # тестовых пакетов на прогон
OUT=results.csv
mkdir -p logs
LOG=logs/${STAND}_${DAI}_$(printf %02d "$N").log
exec > >(tee -a "$LOG") 2>&1

gw_mac() { ip neigh show "$GW" dev "$IF" | grep -oP 'lladdr \K\S+' || echo none; }
loss()   { ping -c "$1" -i 0.2 -W 1 -p "$2" "$GW" | grep -oP '[0-9.]+(?=% packet loss)'; }

echo "== $(date -Is)  стенд=$STAND  DAI=$DAI  прогон=$N"
VIP=$(ip -4 -o addr show "$IF" | awk '{print $4}')
echo "адрес жертвы: $VIP"

# 1. Сброс и проверка исходного состояния
ip neigh flush all
PRE_LOSS=$(loss 10 aa); PRE_LOSS=${PRE_LOSS:-100}
PRE_MAC=$(gw_mac)
echo "до атаки: MAC шлюза=$PRE_MAC  потери=${PRE_LOSS}%"
if [ "$PRE_MAC" != "$GW_MAC" ] || [ "${PRE_LOSS%.*}" -ne 0 ]; then
  echo "ИСХОДНОЕ СОСТОЯНИЕ НЕ ВОССТАНОВЛЕНО — прогон не засчитывается"; exit 1
fi

# 2. Атака
read -r
sleep 10

# 3. Замер во время атаки: метка прогона в данных пакетов
PATTERN=$(printf '%02x' "$N")c0de
ATT_MAC1=$(gw_mac)
ATT_LOSS=$(loss "$SENT" "$PATTERN"); ATT_LOSS=${ATT_LOSS:-100}
ATT_MAC2=$(gw_mac)
SPOOF=0
if [ "$ATT_MAC1" = "$KALI_MAC" ] || [ "$ATT_MAC2" = "$KALI_MAC" ]; then SPOOF=1; fi
echo "во время атаки: MAC шлюза=$ATT_MAC1 / $ATT_MAC2  подмена=$SPOOF  потери=${ATT_LOSS}%"

[ -f "$OUT" ] || echo "time,stand,dai,trial,victim_ip,pre_mac,pre_loss,att_mac,spoof,att_loss,pattern,sent" > "$OUT"
echo "$(date -Is),$STAND,$DAI,$N,$VIP,$PRE_MAC,$PRE_LOSS,$ATT_MAC2,$SPOOF,$ATT_LOSS,$PATTERN,$SENT" >> "$OUT"
