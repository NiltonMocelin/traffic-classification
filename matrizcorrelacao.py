#gerara matriz de correlacao das features
#gerar nivel de importancia de cada feature

import pandas as pd
import seaborn as sn
import matplotlib.pyplot as plt

import os

dir_list = os.listdir()
for x in dir_list:
    
    if x.endswith("10pkts_batch.csv"):
        print("Lendo arquivo {}".format(x))
        data = pd.read_csv(x)

        data2 = data

        #remover contador de bloco, qtd de pacotes e a label
        ##errei o IAT_std :(((
        
        # correlacao baixa com tds < |0.30|: 'IAT_std','tcp_urg_flags','tcp_rst_flags','tcp_windowsize_std','tcp_windowsize_media','tcp_syn_flags','tcp_fin_flags', 'header_tam_std'
        #push_flag eh um candidato a sair
        #IAT_soma (remover)+-= IAT_media
        data = data.drop(columns=['cont','pkts','class', 'tcp_urg_flags','header_tam_std', 'tcp_push_flags','dport', 'tcp_rst_flags','tcp_syn_flags', 'tcp_fin_flags'])#,'IAT_std', 'tcp_rst_flags','tcp_windowsize_std', 'tcp_windowsize_media','tcp_syn_flags', 'tcp_fin_flags',])

        if x.endswith("stream.csv"):
            data = data.drop(columns=['id2','id'])

        correlation = data.corr()
        correlation.to_csv('correlacao_'+x, sep=',')

        sn.heatmap(correlation,
                    annot = False,
                    fmt = '.2f',
                    cmap='YlGnBu')
        plt.title('Correlação {}'.format(x))
        plt.show()


        #calcular feature importancia -- todos os rotulos
        classes = data2['class'].tolist()
        # print("q q eh isso", classes)

        from sklearn.model_selection import train_test_split
        from sklearn.ensemble import RandomForestClassifier

        X_train, X_test, y_train, y_test = train_test_split(data, classes,test_size=0.2, random_state=42)# Treinando modelo
        model  = RandomForestClassifier()
        model.fit(X_train, y_train)# Mostrando importância de cada feature

        # Create a series containing feature importances from the model and feature names from the training data
        feature_importances = pd.Series(model.feature_importances_, index=X_train.columns).sort_values(ascending=False)

        # Plot a simple bar charta
        feature_importances.plot.bar()
        plt.show()