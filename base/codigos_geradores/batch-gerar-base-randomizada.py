#concatena csvs, com apenas um descritor
#entrada:csvs argupados
#saida: csv randomizado


import os
import random

nome_arquivo = 'base-total-randomizada.csv'

dir_list = os.listdir()

contador_total= 0

file_saida = open(nome_arquivo, 'a+')

arquivo = []

for x in dir_list:

#ler todas as linhas de cada csv e armazenar em uma lista - remover a primeira linha dpois
    
    if x.endswith(".csv"):

        file = open(x,'r')

        primeira_linha = 0
        for l in file:
            #nao inserir a primeira linha dos arquivos
            if primeira_linha == 0:
                primeira_linha=1
                continue

            contador_total+=1
            arquivo.append(l)

print(len(arquivo))
while( contador_total > 0):
    numero_gerado = random.randint(0, contador_total-1)
    print(numero_gerado)
    linha = arquivo.pop(numero_gerado)

    file_saida.write(linha)
    contador_total-=1


file_saida.close()
print("Arquivo escrito: {}".format(nome_arquivo))
