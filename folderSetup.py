import os
import sys

path = os.getcwd()  
pathArffEditorOutputs = path + "/Arff_Editor_Outputs"
pathNetmateOutputs =  path + "/Netmate_Outputs"
pathOutputs = path + "/Outputs"
pathPcaps = path + "/Pcaps"

try:  
    os.mkdir(pathArffEditorOutputs)
    os.mkdir(pathNetmateOutputs)
    os.mkdir(pathOutputs)
    os.mkdir(pathPcaps)
except OSError:  
    print ("Creation of the directories failed.")
else:  
    print ("Successfully created directories.")