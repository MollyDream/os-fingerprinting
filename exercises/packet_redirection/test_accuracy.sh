#!/bin/sh

# Usage:
# (1) Run 'make' and install signatures onto switch using 'mycontroller.py'
# (2) Run p0f on h1:
# $ cd <p0f directory>
# $ ./p0f -i h1-eth0 -m 1,1 -o p0f-output.log
# (3) Run send_test_pkts.py in mininet console:
# $ h1 python send_test_pkts.py 10.0.3.3
# (4) Run this script

POF_DIR="/home/p4/p0f-3.09b"

sudo grep -E "(os=|app=)" ${POF_DIR}/p0f-output.log > p0f-result.txt
grep "Action entry is MyIngress.set_result" logs/s1.log > p4-result.txt

python compare_results.py

