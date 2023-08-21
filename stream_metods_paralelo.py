#gerara matriz de correlacao das features
#gerar nivel de importancia de cada feature

import pandas as pd
import seaborn as sn
import matplotlib.pyplot as plt

from threading import Thread, Lock

lock = Lock()

# data = pd.read_csv("10_stream_randv2.csv")
data = pd.read_csv("10_stream_randv2.csv")
file_saida = open('saida_10_stream.txt', '+a')
# exit(0)
classes = data['class'].tolist()

classes_int=[]

for cl in classes:
    if cl == 'ae-2Mbps':
        classes_int.append(0)
    elif cl == 'ar-100kbps':
        classes_int.append(1)
    elif cl == 'chat-128kbps':
        classes_int.append(2)
    elif cl == 'down-max':
        classes_int.append(3)
    elif cl == 'up-max':
        classes_int.append(4)
    elif cl == 'email-10kbps':
        classes_int.append(5)
    elif cl == 've-1.5Mbps' or cl == 've-5Mbps':
        classes_int.append(6)
    elif cl == 'vr-5Mbps' or cl == 'vr-1.5Mbps':
        classes_int.append(7)

print(len(classes_int), len(classes))
# exit(0)

classesnp = data['class'].to_numpy()

#remover contador de bloco, qtd de pacotes e a label
##errei o IAT_std :(((

# correlacao baixa com tds < |0.30|: 'IAT_std','tcp_urg_flags','tcp_rst_flags','tcp_windowsize_std','tcp_windowsize_media','tcp_syn_flags','tcp_fin_flags', 'header_tam_std'
#push_flag eh um candidato a sair
#IAT_soma (remover)+-= IAT_media
data = data.drop(columns=['id','cont','pkts','class', 'dport', 'tcp_urg_flags'])#,'IAT_std', , 'tcp_rst_flags','tcp_syn_flags', 'tcp_fin_flags','header_tam_std', 'tcp_push_flags'])

# correlation = data.corr()
# correlation.to_csv('correlacao.csv', sep=',')

# print(correlation)

# sn.heatmap(correlation,
#             annot = False,
#             fmt = '.2f',
#             cmap='YlGnBu')
# plt.title('Correlação entre Features')
# plt.show()


#calcular feature importancia



from sklearn.metrics import accuracy_score, confusion_matrix, precision_score, recall_score,f1_score, ConfusionMatrixDisplay
import time

import numpy as np
np.float = float
from skmultiflow.trees import HoeffdingTreeClassifier
from skmultiflow.meta import AdaptiveRandomForestClassifier

qtd_dados = len(classes)

#blocos
cv = 5

#dados por bloco
dadospb = int(qtd_dados/cv)

print('qtd dados total: ', qtd_dados)

print('dadospb: ', dadospb)

# print(classes[2:5])

# exit(0)

print('comecou!\n')
#criando o crossvalidation
# cv=2


def calcular_cv(i, lock):
    print('IT:', i)

    print('cv?:',cv)
    print('dadospb: ', dadospb)
    

    #alternar qual bloco sera de teste
    htc  = HoeffdingTreeClassifier()
    arfc = AdaptiveRandomForestClassifier()

    y_pred_htc = []

    y_pred_arfc = []

    for j in range(0, cv):

        ##esse eh o de teste
        if i == j:
            continue
        # print(X_train.iloc[i*dadospb:i*dadospb+dadospb-1])
        
        print('treinando com bloco:', j)
        tempo_treino_htc = 0.0
        tempo_treino_arfc = 0.0
        for k in range(j*dadospb, j*dadospb+dadospb-1):
            
            print('k:',k)
            X_train = np.array([data.loc[k, :].values.flatten().tolist()])
            y_train = np.array([classes_int[k]])

            tinicio_htc = time.monotonic()
            htc.partial_fit(X_train, y_train,classes=np.array([0,1,2,3,4,5,6,7]))
            tempo_treino_htc += time.monotonic()-tinicio_htc

            tinicio_arfc = time.monotonic()
            arfc.partial_fit(X_train, y_train,classes=np.array([0,1,2,3,4,5,6,7]))
            tempo_treino_arfc += time.monotonic()-tinicio_arfc

        #treinar rf
        # htc.fit(X_train_np, y_train)#, classes=np.array([0,1,2,3,4,5,6,7]))

        # # htc.partial_fit(X_train, y_train) 

        # Train Decision Tree Classifer
        # arfc.fit(X_train_np, y_train, classes=np.array([0,1,2,3,4,5,6,7]))

        # arfc.partial_fit(X_train, y_train)

    # print(i*dadospb)
    tempo_teste_htc = 0.0
    tempo_teste_arfc = 0.0
    print('Avaliando os modelos')
    for x in range(i*dadospb, i*dadospb+dadospb-1):
        X_test = np.array([data.loc[x, :].values.flatten().tolist()])

        y_test = np.array([classes_int[x]])
        
        tinicio_htc = time.monotonic()
        y_p = htc.predict(X_test)
        tempo_teste_htc+=time.monotonic()-tinicio_htc

        y_pred_htc.append(y_p)
        

        #Predict the response for test dataset
        tinicio_arfc = time.monotonic()
        y_p= arfc.predict(X_test)
        tempo_teste_arfc+=time.monotonic()-tinicio_arfc

        y_pred_arfc.append(y_p)
        # print(X_test)
        # print(y_p,'x',y_test)

        # exit(0)

    # X_test = np.array([data.iloc[i*dadospb:i*dadospb+dadospb-1].values.flatten().tolist()])
    y_test = classes_int[i*dadospb:i*dadospb+dadospb-1]

    print('i:',i,' Esperando lock')
    lock.acquire()

    print('i:',i,' conseguiu lock')
    
    print("\nHoeffding tree - it:", i)
    file_saida.write('Hoeffding tree - it:' + str(i)+'\n')

    #metricas
    print('Tempo total treino: ', tempo_treino_htc, ' | Tempo total teste: ', tempo_teste_htc)

    file_saida.write('Tempo total treino: ' + str(tempo_treino_htc) + ' | Tempo total teste: ' + str(tempo_teste_htc)+'\n')

    accuracy = accuracy_score(y_test, y_pred_htc)
    ps = precision_score(y_test, y_pred_htc,average='macro')
    rs = recall_score(y_test, y_pred_htc,average='macro')
    f1s = f1_score(y_test, y_pred_htc,average='macro')

    file_saida.write('accuracy: '+ str(accuracy)+'\n')
    file_saida.write('ps: '+ str(ps)+'\n')
    file_saida.write('rs: '+ str(rs)+'\n')
    file_saida.write('f1s: '+ str(f1s)+'\n')

    print('Precision: %.3f' % ps)
    print('Recall: %.3f' % rs)
    print('F1 Score: %.3f' % f1s)

   
    print('\nAdaptive Random Forest - it:',i)
    file_saida.write('Adaptive Random Forest - it:' + str(i)+'\n')

    #metricas
    print('Tempo total treino: ', tempo_treino_arfc, ' | Tempo total teste: ', tempo_teste_arfc)

    file_saida.write('Tempo total treino: ' + str(tempo_treino_arfc) + ' | Tempo total teste: ' + str(tempo_teste_arfc)+'\n')

    accuracy = accuracy_score(y_test, y_pred_arfc)
    ps = precision_score(y_test, y_pred_arfc,average='macro')
    rs = recall_score(y_test, y_pred_arfc,average='macro')
    f1s = f1_score(y_test, y_pred_arfc,average='macro')

    file_saida.write('accuracy: '+ str(accuracy)+'\n')
    file_saida.write('ps: '+ str(ps)+'\n')
    file_saida.write('rs: '+ str(rs)+'\n')
    file_saida.write('f1s: '+ str(f1s)+'\n\n')

    print('Precision: %.3f' % ps)
    print('Recall: %.3f' % rs)
    print('F1 Score: %.3f' % f1s)

    lock.release()
    print('i:',i,' liberou lock')

threads_ativas = []
for i in range(0, cv):
    # print(i*dadospb, '->',i*dadospb+dadospb-1)
    t1 = Thread(target=calcular_cv, args=(i, lock))
    threads_ativas.append(t1)
    t1.start()
    
    # calcular_cv(i)


for i in threads_ativas:
    i.join()

print('fim')
exit(0)


cm = confusion_matrix(y_test, y_pred, labels=model.classes_)
disp = ConfusionMatrixDisplay(confusion_matrix=cm,
                               display_labels=model.classes_)
disp.plot()

plt.show()
