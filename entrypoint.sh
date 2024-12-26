#!/bin/sh
set -e

exec_time=${EXEC_TIME:-"05:05"}  # 05:05 AM by default

echo "{\"name\":\"system\",\"exec_time\":\"$exec_time\",\"current_time\":\"$(date +"%H:%M")\"}"
echo '{"name":"system","message":"warmup_start"}'
python3 main.py
echo '{"name":"system","message":"loop_start"}'

while true; do
  current_time=$(date +"%H:%M")

  if [ "$current_time" = "$exec_time" ]; then
    python3 main.py
  fi

  sleep 60
done