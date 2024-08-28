#!/bin/bash


echo "Please wait ..."
echo ""
i=0
while [ $i -le 2000 ]; do
  for s in / - \\ \|; do
    printf '\r%s' "$s"
    sleep .1
  done
  i=$((i+1))
  if [ -f /root/.gnupg/trustdb.gpg ]
  then
    break
  fi
done
