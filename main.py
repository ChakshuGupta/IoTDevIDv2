from datetime import datetime
import logging
import os
import sys
import yaml

import pandas as pd
from sklearn.model_selection import train_test_split

from src.evaluation import target_name, train_model, test_model
from src.feature_extraction import extract_features, replace_flags
from src.util import load_device_file, list_files, folder


def split_data(name_list):

    for name in name_list:    
        df = pd.read_csv(name)#,header=None)
        df.fillna(value = 0)
        X = df[df.columns[0:-1]]
        df[df.columns[-1]] = df[df.columns[-1]].astype('category')
        y=df[df.columns[-1]]

        # setting up testing and training sets
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.20, train_size=0.8, random_state=27, stratify=y)

        # concatenate our training data back together
        train = pd.concat([X_train, y_train], axis=1)
        file_name = os.path.basename(name)

        file = name[0:-4]+"_"+"_TRAIN.csv"
        print(file)
        train.to_csv(file,index=False)

        test= pd.concat([X_test, y_test], axis=1)

        file = name[0:-4]+"_"+"_TEST.csv"
        print(file)
        test.to_csv(file,index=False)


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

    pcap_list = list_files(config["dataset-path"], ".pcap")
   
    device_mac_map = load_device_file(config["device-file"].format(config["dataset-path"]))
    print(device_mac_map)

    # Extract the features
    extract_features(pcap_list, device_mac_map)

    csv_list = list_files(config["dataset-path"], ".csv")
    
    split_data(csv_list)
    
    # # Create the directory
    folder(config["dataset-name"])
    train_file = os.path.join(config["dataset-name"], config["dataset-name"] + "_train.csv")
    test_file = os.path.join(config["dataset-name"], config["dataset-name"] + "_test.csv")

    replace_flags(config["dataset-path"], "TRAIN.csv", train_file)
    replace_flags(config["dataset-path"], "TEST.csv", test_file)

    feature_dict = {'pck_size': int, 'Ether_type': int, 'LLC_ctrl': int, 'EAPOL_version': int, 'EAPOL_type': int, 'IP_ihl': int, 'IP_tos': int, 'IP_len': int, 'IP_flags': int,
                    'IP_DF': int, 'IP_ttl': int, 'IP_options': int, 'ICMP_code': int, 'TCP_dataofs': int, 'TCP_FIN': int, 'TCP_ACK': int,
                    'TCP_window': int, 'UDP_len': int, 'DHCP_options': int, 'BOOTP_hlen': int, 'BOOTP_flags': int, 'BOOTP_sname': int,
                    'BOOTP_file': int, 'BOOTP_options': int, 'DNS_qr': int, 'DNS_rd': int, 'DNS_qdcount': int, 'dport_class': int,
                    'payload_bytes': int, 'entropy': float, "MAC": object, 'Label': object}

    ### MIXED

    mixed=True
    step=13
    sayac=1
    
    output_csv = config["dataset-name"]+str(sayac)+"_"+str(step)+"_"+str(mixed)+".csv"
    target_names = target_name(test_file)

    # Train the models
    train_time, list_models = train_model(train_file, feature_dict)

    # Test the models
    test_model(list_models, test_file, output_csv, feature_dict, step, mixed, config["dataset-name"], target_names, train_time)