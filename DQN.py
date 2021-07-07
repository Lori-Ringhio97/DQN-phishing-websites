import numpy as np
import tensorflow as tf
from tensorflow import keras
from collections import deque

num_features = 11 # number of features
num_actions = 2 # 0->benign URL, 1->phishing URL

class DQN:
    def __init__(self):
        self.replay_buffer = deque(maxlen=2000)
        
        self.discount_factor = 0.95
        self.epsilon = 1
        self.epsilon_min = 0.1
        self.epsilon_decay = 0.999999
        self.learning_rate = 0.001
        self.batch_size = 32

        self.loss_fn = tf.keras.losses.MeanSquaredError()
        self.optimizer = tf.keras.optimizers.Adam(lr=self.learning_rate)

        self.model = self.create_model()
        self.target_model = self.create_model()

    def create_model(self):
        model = keras.models.Sequential()
        model.add(keras.layers.Dense(32, input_shape=(1, num_features)))
        model.add(keras.layers.Dense(32, activation="relu"))
        model.add(keras.layers.Dense(32, activation="relu"))
        model.add(keras.layers.Dense(num_actions, activation='softmax'))
        model.compile(optimizer=self.optimizer, loss=self.loss_fn, metrics=['accuracy'])
        return model

    def epsilon_greedy_policy(self, state):
        self.epsilon *= self.epsilon_decay
        self.epsilon = max(self.epsilon_min, self.epsilon)
        if np.random.rand() < self.epsilon:
            return np.random.randint(0, num_actions)
        else:
            Q_values = self.model.predict(state)
            return np.argmax(Q_values[0]) 
    
    def sample_experiences_from_buffer_reply_memory(self):
        indices = np.random.randint(len(self.replay_buffer), size=self.batch_size)
        batch = [self.replay_buffer[index] for index in indices]
        states, actions, rewards, next_states, dones = [np.array([experience[field_index] for experience in batch])for field_index in range(5)]
        return states, actions, rewards, next_states, dones
    
    def training_step(self):
        states, actions, rewards, next_states, dones = self.sample_experiences_from_buffer_reply_memory()
        next_Q_values = self.target_model.predict(next_states)
        max_next_Q_values = np.max(next_Q_values, axis=1)
        target_Q_values = (rewards + (1-dones)*self.discount_factor*max_next_Q_values)
        mask = tf.one_hot(actions, num_actions, on_value=1, off_value=0)
        with tf.GradientTape() as tape:
            all_Q_values = self.model(states)
            Q_values = tf.reduce_sum(tf.constant(all_Q_values)*tf.cast(mask, tf.float32), axis=1, keepdims=True)
            loss = tf.reduce_mean(self.loss_fn(target_Q_values, Q_values))      #loss = tf.math.reduce_mean(tf.square(target_Q_values - Q_values))      #loss = tf.reduce_mean(self.loss_fn(tf.reshape(target_Q_values, [32,1]), Q_values))
        variables = self.model.trainable_variables
        grads = tape.gradient(loss, variables)
        self.optimizer.apply_gradients(zip(grads, variables))

    def save_in_buffer_replay_memory(self, state, action, reward, new_state, done):
        self.replay_buffer.append([state, action, reward, new_state, done])
    
    def save_model(self, fn):
        self.model.save(fn)

    def load_model(self, fn):
        self.model.load_weights(fn)
        self.target_model.load_weights(fn)
