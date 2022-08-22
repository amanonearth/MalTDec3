import platform
import pandas as pd
import external as ex
import pickle as pk
from tensorflow.keras.models import load_model

FEATURES = ['protocol_type', 'service', 'src_IP', 'dest_IP', 'failed_login', 'root_shell', 'su_attempted', 'file_creation',
			'file_access', 'outbound_conn', 'log_accessed', 'packet_len']

data_dir = ''
final_df = []

def all_read_and_merge():
	global final_df

	def ftp_read():
		if platform.system() == 'Linux':
			data_dir = '/var/log/vsftpd.log' # directory of the file
		elif platform.system() == 'Windows':
			data_dir = '/var/log/vsftpd.log' # directory of the file

		dataframe = []
		row = ' '
		with open(data_dir, 'r') as f: 
			while row != '':
				row = f.readline()
				with open('vsftpd.log.bak', 'a') as fb:
					fb.write(row)
				failed_login = root_shell = su_attempted = file_creation = 0
				file_access = outbound_conn = log_accessed = 0
				if 'Login incorrect' in row:
					failed_login = 1
				if 'USER root' in row:
					root_shell = 1
				if 'USER root' in row:
					su_attempted = 1
				if 'MKD' in row:
					file_creation = 1
				if 'LIST' in row or 'CWD' in row:
					file_access = 1
				if '/var/log' in row:
					log_accessed = 1			
				dataframe.append(['TCP', 'FTP', ex.ftp_src_IP, ex.ftp_dest_IP,
					failed_login, root_shell, su_attempted, file_creation, 
					file_access, outbound_conn, log_accessed, ex.ftp_packet_len])
		with open(data_dir, 'w') as f:
			f.write('')
		return pd.DataFrame(dataframe, columns = FEATURES)

	def merge(df1, df2):
		return pd.concat([df1, df2], axis = 1)

	def ftp_read_and_merge(data):
		if type(data) != pd.DataFrame:
			return ftp_read()
		return merge(data, ftp_read())

	def ssh_read():
		if platform.system() == 'Linux':
			data_dir = '/var/log/auth.log' # directory of the file
		elif platform.system() == 'Windows':
			data_dir = '/var/log/auth.log' # directory of the file

		dataframe = []
		row = ' '
		with open(data_dir, 'r') as f: 
			while row != '':
				row = f.readline()
				with open('auth.log.bak', 'a') as fb:
					fb.write(row)
				failed_login = root_shell = su_attempted = file_creation = 0
				file_access = outbound_conn = log_accessed = 0
				if 'Login incorrect' in row:
					failed_login = 1
				if 'USER root' in row:
					root_shell = 1
				if 'USER root' in row:
					su_attempted = 1
				if 'MKD' in row:
					file_creation = 1
				if 'LIST' in row or 'CWD' in row:
					file_access = 1
				if '/var/log' in row:
					log_accessed = 1			
				dataframe.append(['TCP', 'FTP', ex.ssh_src_IP, ex.ssh_dest_IP,
					failed_login, root_shell, su_attempted, file_creation, 
					file_access, outbound_conn, log_accessed, ex.ssh_packet_len])
		with open(data_dir, 'w') as f:
			f.write('')
		return pd.DataFrame(dataframe, columns = FEATURES)

	def ssh_read_and_merge(data):
		if type(data) != pd.DataFrame:
			return ftp_read()
		return merge(data, ssh_read())

	def tcp_read():
		if platform.system() == 'Linux':
			data_dir = 'test.txt' # directory of the file
		elif platform.system() == 'Windows':
			data_dir = 'test.txt' # directory of the file

		dataframe = []
		row = ' '
		with open(data_dir, 'r') as f: 
			while row != '':
				row = f.readline()
				with open('vsftpd.log.bak', 'a') as fb:
					fb.write(row)
				failed_login = root_shell = su_attempted = file_creation = 0
				file_access = outbound_conn = log_accessed = 0
				if 'Login incorrect' in row:
					failed_login = 1
				if 'USER root' in row:
					root_shell = 1
				if 'USER root' in row:
					su_attempted = 1
				if 'MKD' in row:
					file_creation = 1
				if 'LIST' in row or 'CWD' in row:
					file_access = 1
				if '/var/log' in row:
					log_accessed = 1			
				dataframe.append(['TCP', 'FTP', ex.tcp_src_IP, ex.tcp_dest_IP,
					failed_login, root_shell, su_attempted, file_creation, 
					file_access, outbound_conn, log_accessed, ex.tcp_packet_len])
		with open(data_dir, 'w') as f:
			f.write('')
		return pd.DataFrame(dataframe, columns = FEATURES)

	def tcp_read_and_merge(data):
		if type(data) != pd.DataFrame:
			return ftp_read()
		return merge(data, tcp_read())

	final_df = ftp_read_and_merge(final_df) 
	final_df = tcp_read_and_merge(final_df)
	final_df = ssh_read_and_merge(final_df)

def get_mal_IPs():
	global final_df
	
	model_df = final_df.drop(columns = ['src_IP', 'dest_IP'])
	
	encoder = load_model('trained_encoder.h5')
	reduced_df = encoder.predict(model_df)

    # pca = pk.load(open('trained_PCA.pickle', 'rb'))
    # reduced_df = pca.transform(model_df)
	 
	model = pk.load(open("OneClassSVM_auto.pickle", 'rb'))
	pred = pd.Series(model.predict(reduced_df), name = 'Predictions')
	Mal_src_IP = final_df[pred == -1]['src_IP']
	Mal_dest_IP = final_df[pred == -1]['dest_IP']
	Mal_df = pd.concat([Mal_src_IP, Mal_dest_IP], names = ['src_IP', 'dest_IP'], 
                        axis = 1)
	
	return Mal_df


# Calling all_read_and_merge() will read extract features and merge them to 'final_df'
# Calling get_mal_IPs will return a dataframe containing src and dest IP of Malicious data points in 'final_df'