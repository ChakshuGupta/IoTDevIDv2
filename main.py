from datetime import datetime
import logging
import os
import sys
import yaml

from src.feature_extraction import extract_features
from src.util import load_device_file


def list_files(path):
    pcap_list = []
    # r=root, d=directories, f = files
    for r, d, f in os.walk(path):
        for file in f:
            if ".pcap" in file or ".pcapng" in file:
                pcap_list.append(os.path.join(r, file))
    return pcap_list


def split_data(pcap_list):
    train  = []
    test  = []
    validation = []

    for iter, file_path in enumerate(pcap_list):
        if iter%5!=0:
            if iter%4==0:
                validation.append(file_path)
                test.append(pcap_list[iter+1])

            else:
                train.append(iter)
    return(train, test, validation)



if __name__ == "__main__":
    if len(sys.argv) < 1:
        print("ERROR! THe script requires the path to the config file as argument")
    
    # Get the path to the config file from the argument
    config_file = sys.argv[1]
    # Validate the file path
    if not config_file.endswith("yml") and not config_file.endswith("yaml"):
        print("ERROR! The config file is not a YAML file.")
        exit(1)
    if not os.path.exists(config_file):
        print("ERROR! The path to the config file does not exist.")
        exit(1)
    # Load the config values
    with open(config_file, "r") as cfg:
        config = yaml.load(cfg, Loader=yaml.Loader)
    
    ####### Set up Logger ########

    if not os.path.exists("logs"):
        os.makedirs("logs")
    log_filepath = os.path.join("logs" , "log_" + datetime.now().strftime("%Y%m%d_%H%M%S") + ".log")

    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    
    handler = logging.FileHandler(log_filepath)
    handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)

    logger.addHandler(handler)

    ######## Read the dataset directory #########

    pcap_list = list_files(config["dataset-path"])
    train, test, validation = split_data(pcap_list)
    
    device_mac_map = load_device_file(config["device-file"].format(config["dataset-path"]))
    print(device_mac_map)

    extract_features(pcap_list, device_mac_map)