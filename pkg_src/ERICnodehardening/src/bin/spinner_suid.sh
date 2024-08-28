#!/bin/bash


echo "SUID check is in progress..."
echo ""
i=0
while [ $i -le 2000 ]; do
  for s in / - \\ \|; do
    printf '\r%s' "$s"
    sleep .1
  done
  i=$((i+1))
  if [ ! -f /ericsson/security/bin/checkfile ]
  then
    break
  fi
done
