from datetime import datetime
import logging
import os
import sys
import yaml

from src.feature_extraction import FeatureExtraction


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

    feature_extractor = FeatureExtraction()
    feature_extractor.list_files(config["dataset-path"])
    feature_extractor.split_data()
