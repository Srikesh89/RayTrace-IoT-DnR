import arff
import json

data = arff.load(open('netmate.arff', 'r')) #open the original arff file we want to add our classification of IoT or nonIoT to

iP2MAC_Table = open('Ip2MAC_Table.txt', 'r') #open the file that holds a table of IPs and their Associated MAC addresses for the pcap we used

iP2MAC_Dict = {} #will be the matching of IPs to MACs extracted from the file
line = iP2MAC_Table.readline() #will hold each line of the table file while we convert it to a dictionary

#parse the table file and convert to dictionary
while line:
    seperated = line.split('-') #split on '-' since that is how the file has the values seperated 
    iP2MAC_Dict[seperated[0]] = seperated[1] #the first value on the line is the IP address and will be the key and the second value is the MAC address and will be the value

    line = iP2MAC_Table.readline() #read the next line in the file


# 
# Adding the class attribute to the arff file. 
# The class attribute will be a 'yes' or 'no' value and will denote whether that flow is an IoT device or not.
#
class_attribute_list = ['class', '{yes, no}'] #[<name of attribute>, <type>] | find a way to get this automated to be this nominal thing
data['attributes'].append(class_attribute_list) #append the attribute to the object we extracted from the file


#iterate through each row in the arff file's data section
for key in data['data']:
    #if the source IP address on the current line is in our dictionary then we know that that device is an IoT device so we append yes(the value of the class attribute)
    try:
        iP2MAC_Dict[key[0]]
        key.append('yes')
    #if we do not have the IP address in the dictionary we assume it is not an IoT device so we append no
    except:
        key.append('no')

#for testing print the JSON version to a file
output = open('output_arff.txt', 'w')
print(json.dumps(data, indent=1), file=output)

#save our new arff file
print(arff.dumps(data), file=open('output_arff.arff','w'))