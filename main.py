from datetime import datetime
import logging
import os
import sys
import yaml

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.utils import shuffle

from src.constants import FEATURE_DICT
from src.evaluation import target_name, train_model, test_model, compute_result
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

    # Train the models
    cols = list(FEATURE_DICT.keys())
    df = pd.read_csv(train_file)
    df = df[cols]

    print(df.dtypes)
    m_train = df["MAC"]
    del df["MAC"]
    
    x_train = df[df.columns[0:-1]]
    x_train = x_train.to_numpy()

    df[df.columns[-1]] = df[df.columns[-1]].astype('category')
    y_train=df[df.columns[-1]].cat.codes

    train_time, list_models = train_model(x_train, y_train)

    ### MIXED

    mixed=True
    step=13
    sayac=1
    
    output_csv = config["dataset-name"]+str(sayac)+"_"+str(step)+"_"+str(mixed)+".csv"
    target_names = target_name(test_file)

    # Test the models
    df2 = pd.read_csv(test_file)
    df2 = df2[cols]

    print(df2.dtypes)
    df2 = shuffle(df2, random_state=42)

    m_test=df2["MAC"]
    del df2["MAC"]

    x_test = df2[df2.columns[0:-1]]
    x_test = x_test.to_numpy()
    df2[df2.columns[-1]] = df2[df2.columns[-1]].astype('category')
    y_test=df2[df2.columns[-1]].cat.codes
    y_true_all, y_pred, test_time, y_true_per_rep, y_predict_per_rep = test_model(x_test, y_test, list_models)

    print(m_test)

    compute_result(y_true_per_rep, y_predict_per_rep, target_names, output_csv, m_test, step, mixed, config["dataset-name"], train_time, test_time, 100)