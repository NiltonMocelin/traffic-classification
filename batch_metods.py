#gerara matriz de correlacao das features
#gerar nivel de importancia de cada feature

import pandas as pd
import seaborn as sn
import matplotlib.pyplot as plt

data = pd.read_csv("30_pkts_batch.csv")
file_saida = open('saida_30_batch.txt', '+a')

data2 = data

#remover contador de bloco, qtd de pacotes e a label
##errei o IAT_std :(((

# correlacao baixa com tds < |0.30|: 'IAT_std','tcp_urg_flags','tcp_rst_flags','tcp_windowsize_std','tcp_windowsize_media','tcp_syn_flags','tcp_fin_flags', 'header_tam_std'
#push_flag eh um candidato a sair
#IAT_soma (remover)+-= IAT_media
data = data.drop(columns=['cont','pkts','class', 'tcp_urg_flags','dport'])#,'IAT_std', , 'tcp_rst_flags','tcp_syn_flags', 'tcp_fin_flags','header_tam_std', 'tcp_push_flags'])


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
classes = data2['class'].tolist()

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn import svm

from sklearn.metrics import accuracy_score, confusion_matrix, precision_score, recall_score,f1_score, ConfusionMatrixDisplay
import time

X_train, X_test, y_train, y_test = train_test_split(data, classes,test_size=0.2, random_state=42)# Treinando modelo

qtd_dados = len(classes)

#blocos
cv = 5

#dados por bloco
dadospb = int(qtd_dados/cv)

print('qtd dados total: ', qtd_dados)

print('dadospb: ', dadospb)

# print(classes[2:5])

# exit(0)

#criando o crossvalidation
for i in range(0, cv):
    # print(i*dadospb, '->',i*dadospb+dadospb-1)

    
    #alternar qual bloco sera de teste
    model  = RandomForestClassifier()
    clf = DecisionTreeClassifier()
    svmc = svm.SVC()

    tempo_treino_svm = 0.0
    tempo_treino_rf = 0.0
    tempo_treino_dt = 0.0

    for j in range(0, cv):

        ##esse eh o de teste
        if i == j:
            continue
        # print(X_train.iloc[i*dadospb:i*dadospb+dadospb-1])
        
        # print('a: ', j*dadospb, '->', j*dadospb+dadospb-1)
        X_train = data.iloc[j*dadospb:j*dadospb+dadospb-1]
        y_train = classes[j*dadospb:j*dadospb+dadospb-1]

        # print('b')
        #treinar rf
        #model =
        tinicio_rf = time.monotonic()
        model.fit(X_train, y_train)
        tempo_treino_rf += time.monotonic()-tinicio_rf

        # Train Decision Tree Classifer
        #clf =
        tinicio_dt = time.monotonic()
        clf.fit(X_train, y_train)
        tempo_treino_dt += time.monotonic()-tinicio_dt

        #Treinar svm
        #svmc =
        tinicio_svm = time.monotonic()
        svmc.fit(X_train, y_train)
        tempo_treino_svm += time.monotonic()-tinicio_svm

    X_test = data.iloc[i*dadospb:i*dadospb+dadospb-1]
    y_test = classes[i*dadospb:i*dadospb+dadospb-1]

    tempo_teste_svm = 0.0
    tempo_teste_rf = 0.0
    tempo_teste_dt = 0.0

    print('bloco teste = ',i)
###################################
    print("\nRandom Forest - it:", i)

    file_saida.write('rf - it:' + str(i)+'\n')

    print('Tempo total treino: ', tempo_treino_rf, ' | Tempo total teste: ', tempo_teste_rf)

    file_saida.write('Tempo total treino: ' + str(tempo_treino_rf) + ' | Tempo total teste: ' + str(tempo_teste_rf)+'\n')


    tinicio_rf = time.monotonic()
    y_pred = model.predict(X_test)
    tempo_teste_rf += time.monotonic() - tinicio_rf

    #metricas
    accuracy = accuracy_score(y_test, y_pred)
    ps = precision_score(y_test, y_pred,average='macro')
    rs = recall_score(y_test, y_pred,average='macro')
    f1s = f1_score(y_test, y_pred,average='macro')
    print('Precision: %.3f' % ps)
    print('Recall: %.3f' % rs)
    print('F1 Score: %.3f' % f1s)

    file_saida.write('accuracy: '+ str(accuracy)+'\n')
    file_saida.write('ps: '+ str(ps)+'\n')
    file_saida.write('rs: '+ str(rs)+'\n')
    file_saida.write('f1s: '+ str(f1s)+'\n')

    cm = confusion_matrix(y_test, y_pred, labels=model.classes_)
    disp = ConfusionMatrixDisplay(confusion_matrix=cm,
                                  display_labels=model.classes_)   

    disp.plot()
    plt.title('matrix rf')
    # plt.show()
    plt.savefig('imgs_matrix/30rf_it'+str(i)+'.png')


###################################
    print('\nDecision Tree - it:',i)
    file_saida.write('dt - it:' + str(i)+'\n')
    print('Tempo total treino: ', tempo_treino_dt, ' | Tempo total teste: ', tempo_teste_dt)

    file_saida.write('Tempo total treino: ' + str(tempo_treino_dt) + ' | Tempo total teste: ' + str(tempo_teste_dt)+'\n')

    #Predict the response for test dataset
    tinicio_dt = time.monotonic()
    y_pred = clf.predict(X_test)

    tempo_teste_dt += time.monotonic() - tinicio_dt


    #metricas
    accuracy = accuracy_score(y_test, y_pred)
    ps = precision_score(y_test, y_pred,average='macro')
    rs = recall_score(y_test, y_pred,average='macro')
    f1s = f1_score(y_test, y_pred,average='macro')
    print('Precision: %.3f' % ps)
    print('Recall: %.3f' % rs)
    print('F1 Score: %.3f' % f1s)

    file_saida.write('accuracy: '+ str(accuracy)+'\n')
    file_saida.write('ps: '+ str(ps)+'\n')
    file_saida.write('rs: '+ str(rs)+'\n')
    file_saida.write('f1s: '+ str(f1s)+'\n')

    cm = confusion_matrix(y_test, y_pred, labels=clf.classes_)
    disp = ConfusionMatrixDisplay(confusion_matrix=cm,
                                  display_labels=clf.classes_)
    
    disp.plot()
    plt.title('matrix dt')
    # plt.show()
    plt.savefig('imgs_matrix/30dt_it'+str(i)+'.png')

#####################################
    print('\nSVM - it:',i)

    file_saida.write('svm - it:' + str(i)+'\n')

    print('Tempo total treino: ', tempo_treino_svm, ' | Tempo total teste: ', tempo_teste_svm)

    file_saida.write('Tempo total treino: ' + str(tempo_treino_svm) + ' | Tempo total teste: ' + str(tempo_teste_svm)+'\n')


    tinicio_svm = time.monotonic()
    y_pred = svmc.predict(X_test)

    tempo_teste_svm += time.monotonic() - tinicio_svm

    #metricas
    accuracy = accuracy_score(y_test, y_pred)
    ps = precision_score(y_test, y_pred,average='macro')
    rs = recall_score(y_test, y_pred,average='macro')
    f1s = f1_score(y_test, y_pred,average='macro')
    print('Precision: %.3f' % ps)
    print('Recall: %.3f' % rs)
    print('F1 Score: %.3f' % f1s)

    file_saida.write('accuracy: '+ str(accuracy)+'\n')
    file_saida.write('ps: '+ str(ps)+'\n')
    file_saida.write('rs: '+ str(rs)+'\n')
    file_saida.write('f1s: '+ str(f1s)+'\n\n')


    cm = confusion_matrix(y_test, y_pred, labels=svmc.classes_)
    disp = ConfusionMatrixDisplay(confusion_matrix=cm,
                                  display_labels=svmc.classes_)
    
    disp.plot()
    plt.title('matrix svmc')
    # plt.show()
    plt.savefig('imgs_matrix/30svm_it'+str(i)+'.png')

exit(0)
