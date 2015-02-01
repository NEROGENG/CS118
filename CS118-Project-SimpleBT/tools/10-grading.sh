#!/bin/bash

echo "Run 7 test cases..."

./tools/sbt-tracker 60207 tests/test-torrent/test.torrent &

sleep 1

./build/simple-bt 60207 tests/test-torrent/test.torrent >/tmp/peers-client &
# ./build/simple-bt 60207 tests/test-torrent/test.torrent 2>/dev/null >/tmp/peers-client &

sleep 1

pgrep "simple-bt" > /dev/null

if [ $? -ne 0 ] ; then
    pgrep "sbt-tracker" | xargs kill
    echo "FATAL ERROR: no working simple-bt"
    exit

fi

pgrep "sbt-tracker" > /dev/null

while [ $? -ne 1 ] ; do
    sleep 1
    pgrep "sbt-tracker" > /dev/null
done

cat /tmp/peers-client | sort > /tmp/peers-sorted-client
cat /tmp/peers | sort > /tmp/peers-sorted-server

cmp /tmp/peers-sorted-client /tmp/peers-sorted-server

if [ $? -eq 0 ] ; then
    echo "[Test case 7] Passed"
else
    echo "[Test case 7] Failed (wrong peer list)"
fi

pgrep "simple-bt" | xargs kill
