#gerara matriz de correlacao das features
#gerar nivel de importancia de cada feature

import pandas as pd
import seaborn as sn
import matplotlib.pyplot as plt

data = pd.read_csv("base-agrupada.csv")

minimo_pacotes = 30

# Reomver multiplas linhas
# df1 = df.drop([df.index[1], df.index[2]])
#print("Number of rows ", len(df.index))

tamanho = len(data.index)

linhas_remover_global = []

linhas_remover_aux = []

qtd_anterior = -1

for i in range(0,tamanho):
    qtd = int(data.iloc[i]['pkts'])

    

    if qtd == minimo_pacotes:
        linhas_remover_aux.clear()
        continue
    elif qtd == 1:
        linhas_remover_global.extend(linhas_remover_aux)
        linhas_remover_aux.clear()
    
    linhas_remover_aux.append(data.index[i])    

data = data.drop(linhas_remover_global)

file_name = 'novo.csv'

data.to_csv(file_name, sep=',')