import requests
import whois
import csv
from url import URL
import numpy as np
import json
from tqdm import tqdm

MAXNUMPHISH = 2000
MAXNUMLEGIT = 2000

#Function for random selection between the 2 datasets. When the max number of one of the two is reached, the other is returned
#Return 0 or 1: 0->read from legit dataset, 1->read from phish dataset
def take_from_phish_or_from_legit(numPhish, numLegit):
    if numPhish == MAXNUMPHISH:
        return 0
    elif numLegit == MAXNUMLEGIT:
        return 1
    return np.random.randint(2)

#Function for building the dataset, in a random way but with balanced legit and phishing URLs
def build_dataset(legit_dataset_path, phish_dataset_path, final_dataset_out_path, maxnumlegit, maxnumphish):
    num_phish = 0
    num_legit = 0
    with open(legit_dataset_path) as legit_dataset, open(phish_dataset_path) as phish_dataset, open(final_dataset_out_path, 'w') as fout:
        for i in tqdm(range(maxnumlegit + maxnumphish)):
            selection = take_from_phish_or_from_legit(num_phish, num_legit)
            if selection == 0: #read from legit dataset
                num_legit += 1
                fout.write(legit_dataset.readline().rstrip() + " " + "0" + "\n")
            else: #read from phish dataset
                num_phish += 1
                fout.write(phish_dataset.readline().rstrip() + " " + "1" + "\n")

#Function written for process the "data_legitimate_36400.json" dataset taken from https://github.com/ebubekirbbr/pdd/tree/master/input
#This function builds another dataset in which there is one URL for each line
def process_json_dataset(dataset_in_path, dataset_out_path):
    with open(dataset_in_path) as fin, open(dataset_out_path, 'w') as fout:
        urls = json.load(fin)
        for url in tqdm(urls):
            fout.write(url+'\n')

#Function written for process the "verified_online.csv" dataset taken from http://phishtank.org/
#This function builds another dataset in which there is one URL for each line
def process_csv_dataset(dataset_in_path, dataset_out_path):
    with open(dataset_in_path) as fin, open(dataset_out_path, 'w') as fout:
        csv_reader = csv.DictReader(fin)
        line_count = 0
        for row in tqdm(csv_reader):
            if line_count == 0:
                print(f'Column names are {", ".join(row)}')
                line_count += 1
            fout.write(row["url"]+'\n')
            line_count += 1

#Function written for building the final dataset used both for training and testing the agent
#This function builds another dataset in which there is one URL and all the related features separated by a comma for each line
def extract_features(dataset_in_path, dataset_out_path):
    #with open(dataset_in_path) as fin, open(dataset_out_path, 'w') as fout:
    with open(dataset_in_path) as fin, open(dataset_out_path, 'a') as fout:
        i = 0
        for line in tqdm(fin):
            i +=1
            if i <= 3872:
                continue
            rawUrl, isPhish = line.rstrip().split(" ")
            print(rawUrl)
            url = URL(rawUrl, isPhish)
            fout.write(str(url.print_csv()) + "\n") # small bug noticed later: also the last feature is followed by a comma


process_json_dataset("./Dataset/data_legitimate_36400.json", "./Dataset/legit_dataset.txt")
process_csv_dataset("./Dataset/verified_online.csv", "./Dataset/phish_dataset.txt")
build_dataset("./Dataset/legit_dataset.txt", "./Dataset/phish_dataset.txt", "./Dataset/final_dataset_without_features.txt", MAXNUMLEGIT, MAXNUMPHISH)
extract_features("./Dataset/final_dataset_without_features.txt", "./Dataset/final_dataset.txt")