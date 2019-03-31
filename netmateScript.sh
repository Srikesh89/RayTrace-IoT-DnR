#!/bin/bash
sudo netmate -r netmate-flowcalc-master/netAi-rules-stats-ni.xml -f /home/eric/sdn-sim-master/16-09-25.pcap
cat netmate-flowcalc-master/header netmate.out > netmate.arff