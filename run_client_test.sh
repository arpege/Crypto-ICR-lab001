#!/bin/bash

# initial timestamp
timestamp=$(date +%s)

echo "[CORRECT RESPONSE EXPECTED]"
./client.py $timestamp 'correct response ?'

echo ""
echo "[INCORRECT LENGTH EXPECTED]"
./client.py $((timestamp++)) 'incorrect length ?'

echo ""
echo "[INCORRECT CODE EXPECTED]"
./client.py $((timestamp++)) 'incorrect code ?'

echo ""
echo "[INCORRECT TIMESTAMP EXPECTED]"
./client.py $((timestamp++)) 'incorrect time ?'

echo ""
echo "[INCORRECT MAC EXPECTED]"
./client.py $((timestamp++)) 'incorrect mac ?'

