import os
import sys

# Example usage: python ready_arff.py Pcaps/16-09-25.pcap /home/eric/netmate-flowcalc-master/

if(len(sys.argv) < 3):
    print("Please pass in pcap file path and netmate path when executing")
    exit()

pcapFileName = sys.argv[1]
outputFileName = "Arff_Editor_Outputs/output_arff.arff"

netmatePath = sys.argv[2]

os.system("python pcap_parser.py " + pcapFileName)
print()

netmate_cmd = "sudo netmate -r " + netmatePath + "/netAI-rules-stats-ni.xml -f " + pcapFileName
cat_cmd = "cat " + netmatePath + "/header Netmate_Outputs/netmate.out > Netmate_Outputs/netmate.arff" 

os.system(netmate_cmd)
os.system(cat_cmd)
print()

os.system("python arff_editor.py Netmate_Outputs/netmate.arff")
print()

print("Success!")
print("File: " + outputFileName + " created")