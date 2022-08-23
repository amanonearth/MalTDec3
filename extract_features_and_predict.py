import pandas as pd
import external as ex
import pickle as pk
from tensorflow.keras.models import load_model

FEATURES = ['protocol_type', 'service', 'src_IP', 'dest_IP', 'failed_login', 'root_shell', 'su_attempted', 'file_creation',
			'file_access', 'outbound_conn', 'log_accessed', 'packet_len']

data_dir = ''
final_df = []
next_row_index = 0

def read():
	global next_row_index
	dataframe = []
	row = ' '
	while ex.new_rows_count > 0:
			row = ex.packetRow[next_row_index]
			protocol_type = service = ''
			failed_login = root_shell = su_attempted = file_creation = 0
			file_access = outbound_conn = log_accessed = 0
			if '' in row[3]:
				protocol_type = 'TCP'
			elif '' in row[3]:
				protocol_type = 'SSH'
			elif '' in row[3]:
				protocol_type = 'FTP'
			if '' in row[3]:
				service = 'VSFTPD'
			elif '' in row[3]:
				service = 'SSHv2'
			elif '' in row[3]:
				service = 'FTP'

			if protocol_type == 'TCP':
				if 'Login incorrect' in row[3]:
					failed_login = 1
				if 'USER root' in row[3]:
					root_shell = 1
				if 'USER root' in row[3]:
					su_attempted = 1
				if 'MKD' in row[3]:
					file_creation = 1
				if 'LIST' in row[3] or 'CWD' in row[3]:
					file_access = 1
				if '/var/log' in row[3]:
					log_accessed = 1
			elif protocol_type == 'SSH':
				if 'Login incorrect' in row[3]:
					failed_login = 1
				if 'USER root' in row[3]:
					root_shell = 1
				if 'USER root' in row[3]:
					su_attempted = 1
				if 'MKD' in row[3]:
					file_creation = 1
				if 'LIST' in row[3] or 'CWD' in row[3]:
					file_access = 1
				if '/var/log' in row[3]:
					log_accessed = 1
			elif protocol_type == 'FTP':
				if 'Login incorrect' in row[3]:
					failed_login = 1
				if 'USER root' in row[3]:
					root_shell = 1
				if 'USER root' in row[3]:
					su_attempted = 1
				if 'MKD' in row[3]:
					file_creation = 1
				if 'LIST' in row[3] or 'CWD' in row[3]:
					file_access = 1
				if '/var/log' in row[3]:
					log_accessed = 1
			
			dataframe.append([protocol_type, service, row[0], row[1],
				failed_login, root_shell, su_attempted, file_creation, 
				file_access, outbound_conn, log_accessed, row[2]])

			next_row_index += 1
			ex.new_rows_count -= 1

	return pd.DataFrame(dataframe, columns = FEATURES)

def merge(df1, df2):
	return pd.concat([df1, df2], axis = 1)

def read_and_merge(data):
	if type(data) != pd.DataFrame:
		return read()
	return merge(data, read())

# final_df = read_and_merge(final_df)

def get_mal_IPs():
	global final_df
	
	model_df = pd.get_dummies(final_df.drop(columns = ['src_IP', 'dest_IP']))
	
	encoder = load_model('trained_encoder.h5')
	reduced_df = encoder.predict(model_df)
	 
	model = pk.load(open("OneClassSVM_auto.pickle", 'rb'))
	pred = pd.Series(model.predict(reduced_df), name = 'Predictions')
	Mal_src_IP = final_df[pred == -1]['src_IP']
	Mal_dest_IP = final_df[pred == -1]['dest_IP']
	Mal_df = pd.concat([Mal_src_IP, Mal_dest_IP], names = ['src_IP', 'dest_IP'], 
                        axis = 1)
	
	return Mal_df


# Calling all_read_and_merge() will read extract features and merge them to 'final_df'
# Calling get_mal_IPs will return a dataframe containing src and dest IP of Malicious data points in 'final_df'