import pandas as pd
from pybbn.graph.factory import Factory
import networkx as nx
import matplotlib.pyplot as plt

df = pd.read_csv('C:/Users/570835/PycharmProjects/CyberSaint/ba-risk-model/bah/model/scenario_module/caseFile.csv')
df.columns = ['orgSize', 'action', 'actor', 'region', 'industry', 'attribute', 'incident']
df2 = df.replace(to_replace='mining', value='miningandutilities')
df2 = df2.replace(to_replace='educational', value='education')
df2 = df2.replace(to_replace='public', value='publicadministration')
df2.to_csv('C:/Users/570835/PycharmProjects/CyberSaint/ba-risk-model/bah/model/scenario_module/caseFileLoaded.csv',
           index=None)

structure = {
    'incident': [],
    'action': ['incident', 'actor'],
    'actor': ['incident'],
    'orgSize': ['incident'],
    'region': ['incident'],
    'industry': ['incident'],
    'attribute': ['incident', 'actor']
}
#
# structure = {
#     'incident': [],
#     'action': ['incident', 'actor'],
#     'actor': ['incident'],
#     'orgSize': ['incident'],
#     'region': ['incident'],
#     'industry': ['incident'],
#     'attribute': ['incident']
# }

simple_structure = {
    'incident': [],
    'action': ['incident'],
    'actor': ['incident'],
    'orgSize': ['incident'],
    'region': ['incident'],
    'industry': ['incident'],
    'attribute': ['incident']
}

bbn = Factory.from_data(structure, df2)
bbn.to_json(bbn, 'C:/Users/570835/PycharmProjects/CyberSaint/ba-risk-model/bah/model/scenario_module/scenario_bbn.json')

if False:
    n, d = bbn.to_nx_graph()
    nx.draw_circular(n, font_size=14, font_weight='bold', arrowsize=20, node_size=500, with_labels=True, labels=d, node_color='b', alpha=0.5)
    plt.show()
