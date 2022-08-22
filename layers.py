import pandas as pd
from extract_features_and_predict import get_mal_IPs
import threading


suspect = []


def layer1_process():
    col_list1 = ["IP_ADDR", "No"]
    column1_df = pd.read_csv("malicious_IPs.csv", usecols=col_list1)
    df1 = list(column1_df["IP_ADDR"])

    col_list2 = ["Destination.IP"]
    column2_df = pd.read_csv("temp1.csv", usecols=col_list2)
    df2 = list(column2_df["Destination.IP"])

    for i in df1:
        for y in df2:
            if i == y:
                if i not in suspect:
                    suspect.append(i)
    # print(suspect)


def layer2_process():
    Malicious_col = pd.read_csv('Malicious IPs.csv')['Malicious IPs']
    User_col = pd.read_csv('User IPs.csv')['User IPs']
    for i in User_col:
        row = i.split(' ')
        for num1 in row:
            for num2 in Malicious_col:
                if num1 == str(num2):
                    if num1 not in suspect:
                        suspect.append(num1)
    # print(suspect)

def layer3_process():
    timer = threading.Timer(600, get_mal_IPs)
    timer.start()
    






# if __name__ == "__main__":
#     layers_inspection()

