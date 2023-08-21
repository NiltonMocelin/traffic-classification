#gerara matriz de correlacao das features
#gerar nivel de importancia de cada feature

# Obs: esse erro parece apontar que na coluna 35 todos os valores são 0 !! 
# /usr/lib/python3.11/site-packages/sklearn/feature_selection/_univariate_selection.py:112: UserWarning: Features [35] are constant.
#   warnings.warn("Features %s are constant." % constant_features_idx, UserWarning)
# /usr/lib/python3.11/site-packages/sklearn/feature_selection/_univariate_selection.py:113: RuntimeWarning: invalid value encountered in divide
#   f = msb / msw
# -> pode observar a coluna para tirar mais conclusões
# # Realmente a coluna 35 eram todos zerados --- removidos
# print('mostrando coluna 35:', data.columns[35])
# print(data[data.columns[35]].to_list())


import pandas as pd
import seaborn as sn
import matplotlib.pyplot as plt

from sklearn.feature_selection import SelectKBest

# #chi2 é para variaveis categoricas
from sklearn.feature_selection import chi2

#anova f é para variáveis numericas e saidas categoricas
from sklearn.feature_selection import f_classif


from sklearn.feature_selection import SequentialFeatureSelector


import numpy as np
np.float = float
from skmultiflow.trees import HoeffdingTreeClassifier

data = pd.read_csv("10pkts_batch.csv")

#obter as labels
classes = data['class'].tolist()

#data -- so com as features
data = data.drop(columns=['cont','pkts','class', 'tcp_urg_flags', 'dport'])#,'IAT_std', , 'tcp_rst_flags','tcp_syn_flags', 'tcp_fin_flags','header_tam_std', 'tcp_push_flags'])


# Setup Hoeffding Tree estimator
ht = HoeffdingTreeClassifier()

sfs = SequentialFeatureSelector(ht, n_features_to_select='auto')

nova_classes_treino=[]

for cl in classes:
    if cl == 'ae-2Mbps':
        nova_classes_treino.append(0)
    elif cl == 'ar-100kbps':
        nova_classes_treino.append(1)
    elif cl == 'chat-128kbps':
        nova_classes_treino.append(2)
    elif cl == 'down-max':
        nova_classes_treino.append(3)
    elif cl == 'up-max':
        nova_classes_treino.append(4)
    elif cl == 'email-10kbps':
        nova_classes_treino.append(5)
    elif cl == 've-1.5Mbps':
        nova_classes_treino.append(6)
    elif cl == 'vr-5Mbps':
        nova_classes_treino.append(7)


data_np =data.to_numpy()

sfs.fit(data_np, classes)

print(sfs.get_support())

# # print(classes)

# # exit(0)

# print('Teste de feature selection !! ANOVA f (numerico->categorico):\n')

# # define feature selection
# fs = SelectKBest(score_func=f_classif, k=43)
# # fs = SelectKBest(score_func=chi2, k=2)

# # apply feature selection
# # X_selected = fs.fit(data, classes)

# X_selected = fs.fit_transform(data, classes)

# print('Original feature number:', data.shape[1])
# print('ANOVA f reduced features number: ',X_selected)