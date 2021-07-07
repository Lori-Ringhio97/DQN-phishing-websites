from DQN import DQN
from tqdm import tqdm
import tensorflow as tf

epochs = 90
dqn_agent = DQN()
dataset_split = 3600 #I've decided to split the dataset into 9 : 1 for training and testing purposes

for epoch in tqdm(range(epochs)):
    reward_sum = 0
    reward_num = 0
    with open("./Dataset/final_dataset.txt") as fin:
        line_list = fin.readline().rstrip().split(', ')
        url = line_list[0]
        isPhishing = int(line_list[1])
        old_state = tf.constant([int(line_list[x].replace(',', '')) for x in range(2, 13)])
        #old_state = tf.reshape(old_state, [11, 1])
        for i in tqdm(range(dataset_split)):
            action = dqn_agent.epsilon_greedy_policy(tf.reshape(old_state, [1, 11]))

            if action == 0:
                if isPhishing == 0:
                    reward = 1
                else:
                    reward = -1
            else: #action == 1
                if isPhishing == 1:
                    reward = 1
                else:
                    reward = -1

            line_list = fin.readline().rstrip().split(', ')
            url = line_list[0]
            isPhishing = int(line_list[1])
            new_state = tf.constant([int(line_list[x].replace(',', '')) for x in range(2, 13)])
            #new_state = tf.reshape(new_state, [11, 1])

            reward_sum += reward
            reward_num += 1

            dqn_agent.save_in_buffer_replay_memory(old_state, action, reward, new_state, False)
            if i > 50:
                dqn_agent.training_step()

            old_state = new_state

    print("Completed epoch", epoch, "Total reward", reward_sum, "Average reward", reward_sum/reward_num)

print("Saving model")
dqn_agent.save_model(f"./Models/phishing_model_{epochs}.h5")