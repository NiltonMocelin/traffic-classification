#concatena csvs, com apenas um descritor

import os
import pandas as pd

dir_list = os.listdir()

contador_total= 0

linhas_menor_arquivo=9999999999


llabels = ['ar-100kbps', 'ae-2Mbps','vr-1.5Mbps',
           've-5Mbps', 'chat-128kbps', 'down-max', 'up-max'
             'email-10kbps']

#contar linhas
for x in dir_list:
    
    labels = [0,0,0,0,0,0,0,0]

    if x.endswith(".csv"):
        data = pd.read_csv(x)

        print("Arquivo {}".format(x))
        #contar quantas entradas de cada label
        lista_labels = data['class'].tolist()

        for l in lista_labels:
            if l == 'ar-100kbps':
                labels[0]+=1
            
            elif l == 'ae-2Mbps':
                labels[1]+=1
            elif l == 'vr-1.5Mbps':
                labels[2]+=1
            elif l == 've-5Mbps':
                labels[3]+=1
            elif l == 'chat-128kbps':
                labels[4]+=1
            elif l == 'down-max':
                labels[5]+=1
            elif l == 'up-max':
                labels[6]+=1
            elif l == 'email-10kbps':
                labels[7]+=1
        print(x)
        print(llabels)
        print(labels)
        print('\n')



