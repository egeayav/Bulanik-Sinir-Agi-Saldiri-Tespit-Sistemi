import pandas as pd
import os
import tensorflow as tf
from pickle import dump,load
import numpy as np
from keras.models import Model
from keras.layers import Input, Dense, Layer
from sklearn.metrics.pairwise import euclidean_distances
from sklearn.model_selection import train_test_split
import keras 
import time

class FuzzyLayer(Layer):
	def __init__(self, output_dim, **kwargs):
		super(FuzzyLayer, self).__init__(**kwargs)
		self.output_dim = output_dim
	def build(self, input_shape):
		self.kernel = self.add_weight(name='kernel',
			shape=(input_shape[1], self.output_dim),
			initializer='uniform',
			trainable=True)

	def call(self, x):
		return tf.math.sigmoid(tf.matmul(x, self.kernel))


oldlen=0
def read_data():
	global oldlen
    
	try:

		df1=pd.read_csv("/home/ayav/gitProjects/TCPDUMP_and_CICFlowMeter/pcap/egeayav.pcap.csv")

	except:
		return False, None
	else: 

		df2 = df1[['bwd_iat_tot','flow_iat_max','fwd_iat_std','bwd_pkts_s','init_fwd_win_byts','bwd_pkt_len_std','bwd_pkt_len_min','pkt_len_min','fwd_seg_size_min']]
		df_cleaned = df2.copy()
		df_cleaned = df_cleaned.reset_index()
		# Removing un-needed index column added by reset_index method
		df_cleaned.drop('index', axis=1, inplace=True)
		df_scaled = MinMaxScaler().fit_transform(df_cleaned)

		if len(df1) != oldlen:
			oldlen=len(df1)
			return True,df_scaled
		else:
			return False,None
    
def detect(measure):
   test=np.array([np.array(measure)])
   pred = model2.predict(test, verbose=False)
   index = np.argmax(pred[0], axis=0)
   return r_mapping[index]
   
 	
mapping={'BENIGN': 0,
 'DDoS': 1,
 'PortScan': 2,
 'Bot': 3,
 'Infiltration': 4,
 'Web Attack � Brute Force': 5,
 'Web Attack � XSS': 6,
 'Web Attack � Sql Injection': 7}

r_mapping = {v:k for k,v in mapping.items()}

# load the scaler
scaler = load(open('/home/ayav/tolga/EgePrj3/scaler.pkl', 'rb'))


input_layer = Input(shape=(9,))
fuzzy_layer = FuzzyLayer(64)(input_layer)
hidden_layer_1 = Dense(32, activation='tanh')(fuzzy_layer)
hidden_layer_2 = Dense(16, activation='tanh')(hidden_layer_1)
hidden_layer_3 = Dense(8, activation='tanh')(hidden_layer_2)
output_layer = Dense(8)(hidden_layer_3)

model = Model(inputs=input_layer, outputs=output_layer)
model.compile(optimizer='adam', loss='mean_squared_error',
metrics=['mae', 'accuracy'])


model.load_weights('/home/ayav/tolga/EgePrj3/checkpoint')


result=""  
   
while True:

	r, df = read_data()
	if r == False:
		time.sleep(1)
		continue
		
	else:
		for m in df:
	    		res = detect(m)
	    		if res != result:
	    			print(res)
	    		
	    		result = res
    


