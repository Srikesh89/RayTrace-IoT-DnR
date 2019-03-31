from scapy.all import * # Packet manipulation
import pandas as pd # Pandas - Create and Manipulate DataFrames
import numpy as np # Math Stuff (don't worry only used for one line :] )
import binascii # Binary to Ascii 
import seaborn as sns
import matplotlib.pyplot as plt

import pprint
import requests #for MacLookup
import json
import codecs

sns.set(color_codes=True)

ip_fields = [field.name for field in IP().fields_desc] #all of the ip fields in an array, used for checking each ip_field in the packets
tcp_fields = [field.name for field in TCP().fields_desc] #similar to above but with tcp fields
udp_fields = [field.name for field in UDP().fields_desc] #similar to above but with UDP fields, unused at the moment

dataframe_fields = ip_fields + ['time'] + tcp_fields + ['payload','payload_raw','payload_hex'] #defining the columns that will be in our pandas dataframe
df = pd.DataFrame(columns=dataframe_fields) #creating a data frame that has the columns we defined in dataframe_fields

##########################################################
arp_fields = [field.name for field in ARP().fields_desc]

dataframe_fields_ARP = arp_fields 
df_ARP = pd.DataFrame(columns=dataframe_fields_ARP) 
##########################################################

progress = 0

known_devices = {}
with open("Known_Devices.txt", "r") as f:
    for line in f:
        temp = line.split();   
        known_devices[temp[0]] = temp[1]

#print(known_devices) 

############################################################################################
# Function for extracting fields from given packet and saving them to our pandas dataframe #
############################################################################################
def method_filter_HTTP(pkt):
    #Global variables for the dataframe we are saving data to and the columns of the dataframe defined in dataframe_fields
    global df
    global dataframe_fields

    global df_ARP
    global dataframe_fields_ARP

    global progress

    #save the different portions of the packet to seperate variables
    ethernet_frame = pkt
    ip_packet = ethernet_frame.payload
    segment = ip_packet.payload
    data = segment.payload

    field_values = [] #used to store the values in the ip and tcp fields
    field_values_ARP = []

    # iterate through the ip fields and append the options to our dataframe
    # try/except is for if no option is found  
    for field in ip_fields:
        try: 
            if field == 'options':
                field_values.append(len(pkt[IP].fields[field]))
            else:
                field_values.append(pkt[IP].fields[field])
        except:
            field_values.append(None)

    flag_arp = 0
    if pkt.haslayer(ARP):
        for field in arp_fields:
            try: 
                if field == 'options':
                    field_values_ARP.append(len(pkt[ARP].fields[field]))
                else:
                    field_values_ARP.append(pkt[ARP].fields[field])
            except:
                field_values_ARP.append(None)
    else:
        flag_arp = 1

    flag = 0 # a flag to print debug info if no time or layer type is found
   
    try:
        field_values.append(pkt.time)
    except:
        print("No time value.")
        flag = 1

    try:
        layer_type = type(pkt[IP].payload)
    except:
        layer_type = None
        #print("No layer type given.")
        flag = 1

    # print info about packets that do not have a time value or a layer type
    # if flag == 1:
    #     print(ethernet_frame.summary())
    #     print(ip_packet.summary())
    #     print(segment.summary())
    #     # print(data.summary())

    #     print()
    #     ethernet_frame.show()
    #     print()
    #     print()

    # collect all tcp field values or if none add None
    for field in tcp_fields:
        try:
            if field == 'options':
                field_values.append(len(pkt[layer_type].fields[field]))
            else:
                field_values.append(pkt[layer_type].fields[field])
        except:
            field_values.append(None)
    
    # Append payload
    field_values.append(len(pkt[layer_type].payload))
    field_values.append(pkt[layer_type].payload.original)
    field_values.append(binascii.hexlify(pkt[layer_type].payload.original))

    # Add row to DF
    df_append = pd.DataFrame([field_values], columns=dataframe_fields)
    df = pd.concat([df, df_append], axis=0)

    if not flag_arp:
        df_append_ARP = pd.DataFrame([field_values_ARP], columns=dataframe_fields_ARP)
        df_ARP = pd.concat([df_ARP, df_append_ARP], axis=0)
    
    if(progress % 100 == 0):
        print(progress)
    progress = progress + 1

# scapy function that allows us to perform a function on each packet in our pcap
# prn is the function to pass each packet to
# timeout is the amount of time to process packets (using this because the pcap is so large) 
sniff(offline="16-09-25.pcap",prn=method_filter_HTTP,store=0, timeout=3)
# Reset Index
df = df.reset_index()

# Drop old index column
df = df.drop(columns="index")

# print the dataframe to a file (will be a table)
output = open("output.txt", "w+")
print(df.to_string(), file=output)

output_arp = open("output_arp.txt", "w+")
print(df_ARP.to_string(), file=output_arp)

IP_to_MAC_Table = open('Ip2MAC_Table.txt','w')

print()
#print('MAC               - IP            - Is the MAC known?  -  MAC Lookup Company Name')
unique_arp = df_ARP['hwsrc'].unique()
for hwsrc in unique_arp:
    psrc = ((df_ARP[df_ARP.hwsrc == hwsrc])['psrc'])[:1]
    psrc = psrc[0]

    try:
        value = known_devices[hwsrc]
    except:
        value = 'no known'

    MAC_URL = 'http://macvendors.co/api/%s'
    r = requests.get(MAC_URL % hwsrc)
    r = r.json()

    print(psrc + '-' + hwsrc, file=IP_to_MAC_Table)#+ ' - '+ value + ' -  Company: ' + r['result']['company'], file=IP_to_MAC_Table)

# print simple metrics
print()
print("Unique Sources")
print(df['src'].unique())

print()
print("Unique Destination Addresses")
print(df['dst'].unique())

# create a simple graph of a ip addresses and how much data they sent then write this to a pdf
source_addresses = df.groupby("src")['payload'].sum()
chart = source_addresses.plot(kind='barh',title="Addresses Sending Payloads",figsize=(8,5))
fig = chart.get_figure()
fig.savefig("myplot.pdf", bbox_inches="tight")