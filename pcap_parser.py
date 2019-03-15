from scapy.all import * # Packet manipulation
import pandas as pd # Pandas - Create and Manipulate DataFrames
import numpy as np # Math Stuff (don't worry only used for one line :] )
import binascii # Binary to Ascii 
import seaborn as sns
import matplotlib.pyplot as plt
sns.set(color_codes=True)

ip_fields = [field.name for field in IP().fields_desc] #all of the ip fields in an array, used for checking each ip_field in the packets
tcp_fields = [field.name for field in TCP().fields_desc] #similar to above but with tcp fields
udp_fields = [field.name for field in UDP().fields_desc] #similar to above but with UDP fields, unused at the moment

dataframe_fields = ip_fields + ['time'] + tcp_fields + ['payload','payload_raw','payload_hex'] #defining the columns that will be in our pandas dataframe
df = pd.DataFrame(columns=dataframe_fields) #creating a data frame that has the columns we defined in dataframe_fields

############################################################################################
# Function for extracting fields from given packet and saving them to our pandas dataframe #
############################################################################################
def method_filter_HTTP(pkt):
    #Global variables for the dataframe we are saving data to and the columns of the dataframe defined in dataframe_fields
    global df
    global dataframe_fields

    #save the different portions of the packet to seperate variables
    ethernet_frame = pkt
    ip_packet = ethernet_frame.payload
    segment = ip_packet.payload
    data = segment.payload

    field_values = [] #used to store the values in the ip and tcp fields

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
        print("No layer type given.")
        flag = 1

    # print info about packets that do not have a time value or a layer type
    if flag == 1:
        print(ethernet_frame.summary())
        print(ip_packet.summary())
        print(segment.summary())
        # print(data.summary())

        print()
        ethernet_frame.show()
        print()
        print()

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

# scapy function that allows us to perform a function on each packet in our pcap
# prn is the function to pass each packet to
# timeout is the amount of time to process packets (using this because the pcap is so large) 
sniff(offline="16-09-23.pcap",prn=method_filter_HTTP,store=0, timeout=100)

# Reset Index
df = df.reset_index()

# Drop old index column
df = df.drop(columns="index")

# print the dataframe to a file (will be a table)
print(df.shape)
output = open("output.txt", "w+")
print(df.to_string(), file=output)

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