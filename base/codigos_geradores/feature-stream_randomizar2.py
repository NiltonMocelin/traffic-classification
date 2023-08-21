#concatena csvs, com apenas um descritor
#entrada:csvs argupados
#saida: csv randomizado


import os
import random

def swapPositions(list, pos1, pos2): 
      
    list[pos1], list[pos2] = list[pos2], list[pos1] 
    return list

nome_arquivo = 'saidao_teste.csv'

dir_list = os.listdir()

contador_total= 0

#mudar para cada base
tam_bloco= 30

file_saida = open(nome_arquivo, 'a+')

file_entrada = open('base-agrupada.csv', 'r')

blocos = []

# for x in dir_list:

# #ler todas as linhas de cada csv e armazenar em uma lista - remover a primeira linha dpois
    
#     if x.endswith(".csv"):

#         file = open(x,'r')

#         primeira_linha = 0
#         for l in file:
#             #nao inserir a primeira linha dos arquivos
#             if primeira_linha == 0:
#                 primeira_linha=1
#                 continue

#             contador_total+=1
#             arquivo.append(l)


arquivo = []
cabecalho = []
primeira_linha = 0

for l in file_entrada:
    if primeira_linha ==0:
        cabecalho.append(l.strip())
        primeira_linha+=1
        continue
    arquivo.append(l.strip())



#misturar blocos

#pegar entre 1 e 15 fluxos e misturar
#repetir enquanto existirem fluxos


#ler os blocos
print(len(arquivo))

tamanho = len(arquivo)
qtd_blocos = int(tamanho/tam_bloco)
aux_qtd_blocos = qtd_blocos
while( aux_qtd_blocos > 0):

    aux_bloco = []
    
    for i in range(0, tam_bloco):
        aux_bloco.append(arquivo.pop())

    blocos.append(aux_bloco)
    aux_qtd_blocos-=1

# print(blocos)


# misturar os blocos

for i in range(0, qtd_blocos):

    #entao esse bloco vai trocar com outro
    if (random.random()>0.5):

        outro_bloco = random.randint(0, qtd_blocos-1)

        #troca
        bloco_aux = blocos[i]
        # print(bloco_aux, '<->', blocos[outro_bloco])

        blocos[i] = blocos[outro_bloco]
        blocos[outro_bloco] = bloco_aux

        # print(blocos[i], '<->', blocos[outro_bloco])
        # exit(0)

#blocos misturados

print('blocos misturadoes prontos')
print('Escrevendo cabecalho')

file_saida.write(cabecalho.pop() + '\n')

#retirar entre 1 e 15 blocos e sortear 
while(qtd_blocos > 0):
    
    qtd_fluxos_ativos = random.randint(1, 20)
    

    if qtd_fluxos_ativos > qtd_blocos:
        qtd_fluxos_ativos = qtd_blocos

    # print('fluxos ativos: ', qtd_fluxos_ativos, 'qtdBlocos: ', qtd_blocos)

    #como estao misturados, pode ser um a um mesmo
    #retirar os qtd_fluxos_ativos do arquivo
    fluxos_ativos= []

    for i in range(0, qtd_fluxos_ativos):
        fluxos_ativos.append(blocos.pop())
        qtd_blocos-=1

    #sortear os pacotes dos blocos para escrever no arquivo
    while(len(fluxos_ativos) > 0): 

        fluxo_sorteado = random.randint(0, len(fluxos_ativos)-1)

        # print('escrevendo pacote do fluxo: ', fluxo_sorteado)
        file_saida.write(fluxos_ativos[fluxo_sorteado].pop()+'\n')

        if( len(fluxos_ativos[fluxo_sorteado]) == 0):
            fluxos_ativos.pop(fluxo_sorteado)

print("Arquivo escrito: {}".format(nome_arquivo))
