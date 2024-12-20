import os

def folder(f_name): #this function creates a folder.
    try:
        if not os.path.exists(f_name):
            os.makedirs(f_name)
    except OSError:
        print ("The folder could not be created!")


def load_device_file(device_file):
   """
   Load the mapping between devices and mac addresses
   """
   file_data = open(device_file, "r")
   device_mac_map = {}
   
   for line in file_data:
       if line.strip() == "":
           continue
       device = line.split(",")[0].replace(" ", "").lower()
       mac = line.split(",")[1]
       device_mac_map[mac.strip()] = device.strip()

   return device_mac_map


def list_files(path, ext):
    pcap_list = []

    for r, d, f in os.walk(path):
        for file in f:
            if ext in file:
                pcap_list.append(os.path.join(r, file))
    return pcap_list