import pandas as pd
import os
from scapy.all import*


class FeatureExtraction:

    def __init__(self):
        self.pcap_list = []

        self.train  = []
        self.test  = []
        self.validation = []

    def list_files(self, path):
        # r=root, d=directories, f = files
        for r, d, f in os.walk(path):
            for file in f:
                if ".pcap" in file or ".pcapng" in file:
                    self.pcap_list.append(os.path.join(r, file))


    def split_data(self):
        for iter, file_path in enumerate(self.pcap_list):
            if iter%5!=0:
                if iter%4==0:
                    self.validation.append(file_path)
                    self.test.append(self.pcap_list[iter+1])

                else:
                    self.train.append(iter)
        print(len(self.train), len(self.test), len(self.validation))