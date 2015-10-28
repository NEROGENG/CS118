#!/bin/bash

# 21-grading.sh

rm -f ./text.txt
rm -f ./tools/text.txt
rm -f ./complete.tmp
rm -f ./test.result

cp ./tools/text.txt.bak ./tools/text.txt

echo "Run 6 test cases..."

./tools/sbt-tracker 60207 ./tools/test-2.torrent > ./test.result 2>/dev/null &

sleep 1

./tools/sbt-peer 11111 ./tools/test-2.torrent ./tools/ SIMPLEBT.TEST.111111 2>/dev/null &
./tools/sbt-peer 22222 ./tools/test-2.torrent ./tools/ SIMPLEBT.TEST.222222 2>/dev/null &

sleep 1

./build/simple-bt 60207 ./tools/test-2.torrent > /dev/null 2>&1 &


for ((x = 0; x < 15; x++)); do
  printf %s .
  sleep 1
done
echo

killall sbt-tracker > /dev/null 2>&1

sleep 1

cat ./test.result

cmp ./text.txt ./tools/text.txt > /dev/null 2>&1

if [ $? -eq 0 ] ; then
    echo "[Test case 5] Passed"
else
    echo "[Test case 5] Failed (In consistent file)"
fi

if [ -e ./complete.tmp ] ; then
    echo "[Test case 6] Passed"
else
    echo "[Test case 6] Failed (did not send have msg correctly)"
fi

rm -f ./text.txt
rm -f ./tools/text.txt
rm -f ./complete.tmp
rm -f ./test.result
