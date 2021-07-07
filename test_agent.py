from DQN import DQN
from tqdm import tqdm
import tensorflow as tf
import numpy as np

trained_agent = DQN()
trained_agent.load_model("./Models/phishing_model_90.h5")

true_positive, true_negative = 0, 0
false_positive, false_negative = 0, 0
end_training = 3600  # As said, I've decided to split the dataset into 9 : 1 for training and testing purposes
end_dataset = 3989   # Due to some problems in extracting features from 11 URLs, the dataset is smaller than intended

with open("./Dataset/final_dataset.txt") as dataset:
    for i in tqdm(range(end_training, end_dataset)):
        line_list = dataset.readline().rstrip().split(', ')
        url = line_list[0]
        isPhishing = int(line_list[1])
        features = tf.constant([int(line_list[x].replace(',', '')) for x in range(2, 13)])

        action = np.argmax(trained_agent.model.predict(tf.reshape(features, [1, 11]))[0])
        # action == 0->benign URL, action == 1->phishing URL
        if action == 0:
            if isPhishing == 0:
                true_negative += 1
                print(f"{url} correctly classified as benign URL")
            else: 
                false_negative += 1
                print(f"{url} wrongly classified as benign URL")
        else: # action == 1
            if isPhishing == 0:
                false_positive += 1
                print(f"{url} wrongly classified as phishing URL")
            else:
                true_positive += 1
                print(f"{url} correctly classified as phishing URL")
    
    precision = true_positive / (true_positive + false_positive)
    recall = true_positive / (true_positive + false_negative)
    accuracy = (true_negative + true_positive) / (true_negative + true_positive + false_negative + false_positive)
    F_score = 2 * ((precision * recall) / (precision + recall))

    print(f"Total number of processed URLs: {true_positive + true_negative + false_positive + false_negative}")
    print(f"Total number of correctly classified URLs: {true_positive + true_negative}")
    print(f"Precision: {precision}")
    print(f"Recall: {recall}")
    print(f"Accuracy: {accuracy}")
    print(f"F-score: {F_score}")