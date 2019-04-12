import os
import sys

if(len(sys.argv) < 2):
    print("Please pass in pcap file path and output filename when executing")
    exit()

pcapFileName = sys.argv[1]
outputFileName = "Arff_Editor_Outputs/netmate.arff"

os.system("python3 pcap_parser.py " + pcapFileName)
print()

netmate_cmd = "sudo netmate -r /home/eric/netmate-flowcalc-master/netAI-rules-stats-ni.xml -f " + pcapFileName
cat_cmd = "cat /home/eric/netmate-flowcalc-master/header Netmate_Outputs/netmate.out > Netmate_Outputs/netmate.arff" 

os.system(netmate_cmd)
os.system(cat_cmd)
print()

os.system("python3 arff_editor.py Netmate_Outputs/netmate.arff")
print()

print("Success!")
print("File: " + outputFileName + " created")