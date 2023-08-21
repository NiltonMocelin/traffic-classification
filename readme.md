# Classificação de tráfego de rede para descoberta de QoS em redes SDN.

- No momento ainda não foi implementado em SDN.

- Classificar tráfego de fluxos de rede em classes de serviço.

- Classes: audio tempo-real, video tempo-real, audio estático, video estático, dados-upload, dados-download, chats, e-mail.

- Cada classe de serviço representa diversas aplicações, que possuem requisitos de QoS diferentes. A princípio, algumas dessas
aplicações foram identificadas e a maior largura de banda observada foi anotada para compôr a label.

- Atualmente, o alvo é apenas identificar e reservar largura de banda.

- O objetivo é identificar modelos de aprendizado para implementar no framework FLOWPRI-SDN e automatizar o processo de 
descoberta de serviço (classificação de tráfego).

- OBS: o método de streaming implementado com paralelização não está sendo executado com eficiência.

# ML models avaliados:

* Dados do tipo Batch:

- Decision Tree

- Random Forest

- SVM

* Dados do tipo Streaming:

- Hoeffding Tree

- Adaptive Random Forest

# Base de dados utilizada

* Artigo que fala sobre os tipos de aplicações e como a base foi gerada: [artigo](https://arxiv.org/pdf/2004.13006.pdf)

* link da base para download [base-link](https://www.unb.ca/cic/datasets/vpn.html)

* [download](http://205.174.165.80/CICDataset/ISCX-VPN-NonVPN-2016/Dataset/)

# Principais Dependências:

- Python 3.8 para utilizar corretamente a biblioteca scikit-multiflow.

- Obs se atente a qual versão do Python você está instalando as bibliotecas!

- Wheel é dependência de numpy (as vezes dá problema de instalação do numpy por falta do wheel):

`pip install -U wheel`

- Numpy:

`pip install -U numpy`

- Scikit-multiflow

`pip install -U scikit-multiflow`

- Scapy

`pip install scapy`

- pandas

`pip install pandas`

- matplotlib

`pip install matplotlib`

- sklearn

`pip install -U scikit-learn`

- seaborn

`pip install seaborn`

- No caso de erros, consultar os arquivo python38-packages.txt e python311-packages.txt, 
que contém os pacotes instalados no momento dos testes. 

# Erros e correções relacionados a biblioteca scikit-multiflow:

* Não localiza a biblioteca:

- Verifique você está instalando as dependências na versão Python 3.8 (pip correto).

- Verifique se está executando o código com python 3.8.

- Instale python wheel: pip install -U wheel 

* Numpy: 

- A biblioteca scikit-multiflow depende de uma versão antiga do numpy que nem está mais disponível.

- Isso pode ser burlado definindo a propriedade legada de forma manual, np.float não existe mais.

- Antes de importar a biblioteca scikit-multiflow, defina np.float = float:

```
import numpy as np
np.float = float
from skmultiflow.trees import HoeffdingTreeClassifier
from skmultiflow.meta import AdaptiveRandomForestClassifier
```

* Installação de dependência:

- As vezes a ordem de instalação das dependências pode ocasionar erros.

- Tente instalar primeiro o wheel, depois numpy.

* Erro no arquivo base_neighbors.py: 

- É preciso ir na pasta onde o arquivo está localizado e alterá-lo.

- Geralmente fica instalado em /lib/python3.8/site-packages/skmultiflow/lazy/base_neighbors.py:

- Altere a função valid_metrics(), adicionando () depois de KDTree.valid_metrics:

```
   @staticmethod
    def valid_metrics():
        """ Get valid distance metrics for the KDTree. """
        return KDTree.valid_metrics()
```


# Processamentos realizados na base de dados

- [ok] Extraidos os fluxos de cada arquivo.

- [ok] remover fluxos com poucos pacotes (<30 pkts), dns e outros protocolos.

- [ok] Extrair os subfluxos de cada arquivo pcap de aplicação/serviço.

- [ok] Filtrar os subflows válidos = tempo entre chegadas de pacotes < 10s

- [ok] Filtrar subflows < 10pkts/30pkts

- [ok] Montar tabela sobre a quantidade de subfluxos e de pacotes de cada classe.

- [nao-feito] Extrair os histogramas de largura de banda de cada subfluxo.

- [nao-feito] Analisar os histogramas e definir os limites de largura de banda para as classes = rótulo (foi definido pesquisando os requisitos das aplicações nos seus respectivos sites).

- [ok] Extrair as features para os blocos de pacotes dos subfluxos para batch e streaming, aplicando o rótulo

- [ok] Normalizar os valores das features.

- [ok] Analisar as features com matriz de correlação e valor de importancia.

- [ok] Balancear as bases de dados com quantidades iguais de dados.

- [ok] Montar tabela sobre a quantidade de entrada de dados de cada classe

- [ok] Pronto para teste.

- [ok] Randomizar base streaming

- [ok] Randomizar base batch

- [ok] Executar código batch e obter resultados

- [ok] Executar código Streaming e obter resultados

* Obs: como contar arquivos usando terminal: ls udp* | wc -l
