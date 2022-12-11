import numpy as np
from tqdm import tqdm
import pandas as pd
from verispy import VERIS

data_dir = 'C:/Users/570835/PycharmProjects/VCDB/data/json/validated/'
v = VERIS(json_dir=data_dir)

# uncomment to load fresh from source, o/w load from stored pickle
veris_df = v.json_to_df(verbose=False)
#veris_df = veris_df[(veris_df['plus.dbir_year'] >= 2017) & (veris_df['plus.dbir_year'] <= 2031)]
#veris_df = veris_df[veris_df['attribute.confidentiality.data_disclosure.Yes'] == True]
veris_df.to_pickle("C:/Users/570835/PycharmProjects/VCDB/data/vcdb.pkl")

veris_df = pd.read_pickle("C:/Users/570835/PycharmProjects/VCDB/data/vcdb.pkl")
v_mat, keep_cols = v.df_to_matrix(veris_df, bools_only=True)

actions = ['Error', 'Misuse', 'Hacking', 'Malware', 'Social']
sub_df = pd.DataFrame(v_mat, columns=keep_cols)
inc_df = pd.DataFrame()
keys = ['action.Error', 'action.Misuse', 'action.Hacking', 'action.Malware', 'action.Social', 'actor.External',
        'actor.Internal', 'actor.Partner',
        'attribute.Availability', 'attribute.Confidentiality', 'attribute.Integrity',
        'victim.industry', 'victim.orgsize.Large', 'victim.orgsize.Small', 'victim.region']

# uncomment to freshly build df, o/w load from stored pickle
region_dict = {'21': 'na', '34': 'apac', '35': 'apac', '143': 'apac', '30': 'apac', '9': 'apac', '2': 'emea',
               '150': 'emea', '145': 'emea', '5': 'lac', '13': 'lac', '29': 'lac', '39': 'emea', '0': 'global',
               '002': 'emea', '154': 'emea', '155': 'emea', '151': 'emea', '53': 'apac'}

df_list = []
for r in tqdm(range(0, veris_df.shape[0])):
    rcd = veris_df.iloc[r]
    isect = list(set(rcd.keys()) & set(keys))
    if isect is not None:
        for i in isect:
            if rcd[i] == True:
                break
        row = rcd[isect]
        region = '0'
        try:
            if not 'victim.region' in rcd[rcd.isna()]:
                region = str(int(row['victim.region'][0][3:]))
                if region not in region_dict.keys():
                    if len(row['victim.region']) > 1:
                        region = str(int(row['victim.region'][1][3:]))
                    if region not in region_dict.keys():
                        region = str(int(row['victim.region'][0][0:3]))
        except:
            print("Error-------")
            db = 1
        rcd['victim.region'] = region_dict[region]

        df_list.append(rcd[isect])

df = pd.DataFrame(df_list, columns=rcd[isect].index)

df = v._victim_postproc_subset(df)
df = df.drop(['victim.industry'], axis=1)

df.to_pickle("C:/Users/570835/PycharmProjects/CyberSaint/ba-risk-model/bah/model/scenario_module/df.pkl")

df = pd.read_pickle("C:/Users/570835/PycharmProjects/CyberSaint/ba-risk-model/bah/model/scenario_module/df.pkl")
nodes = {'victim.orgsize': {'large', 'small', 'unknown'}, 'action': {'error', 'hacking', 'malware', 'misuse', 'social'},
         'actor': {'external', 'internal', 'partner'}, 'victim.region': {'apac', 'emea', 'lac', 'na'},
         'victim.industry.name': {'accommodation', 'agriculture', 'administrative', 'construction', 'educational', 'entertainment',
                                  'finance', 'healthcare', 'information', 'management', 'manufacturing', 'mining', 'otherservices',
                                  'professional', 'public', 'public', 'realestate', 'retail', 'trade', 'transportation', 'utilities'},
         'attribute': {'confidentiality', 'integrity', 'availability'}}

cols = ['victim.orgsize', 'action', 'actor', 'victim.region', 'victim.industry.name', 'attribute', 'incident']
dfx = pd.DataFrame(index=range(df.shape[0]), columns=cols)

for r in tqdm(range(0, df.shape[0])):
    for c in df.columns:
        if c.lower() == 'victim.industry.name':
            dfx.iloc[r]['victim.industry.name'] = df.iloc[r][c].lower().replace(' ', '')
        elif c.lower() == 'victim.region':
            dfx.iloc[r]['victim.region'] = df.iloc[r][c].lower().replace(' ', '')
        elif df.iloc[r][c] == True:
            for n in nodes:
                toInsert = 'nan'
                if n in c.lower():
                    for k in nodes[n]:
                        if k.strip().replace(' ', '') in c.lower():
                            toInsert = k
                            break
                    break

            if n == 'attribute':
                if type(dfx.iloc[r][n]) == list:
                    dfx.iloc[r][n] = dfx.iloc[r][n] + toInsert[0]
                else:
                    dfx.iloc[r][n] = toInsert[0]
            else:
                dfx.iloc[r][n] = toInsert
    dfx.iloc[r]['incident'] = "T"

add = []

for sz in nodes['victim.orgsize']:
    for a in nodes['action']:
        for tor in nodes['actor']:
            for reg in nodes['victim.region']:
                for ind in nodes['victim.industry.name']:
                    for att in nodes['attribute']:
                        add.append([sz, a, tor, reg, ind, att[0], 'F'])
len1 = len(add)
delta = dfx.shape[0] - len1
falseFrame = pd.DataFrame(add, columns=cols)
if delta > 0:
    df2 = dfx.append(falseFrame)
    df3 = df2.append(falseFrame.sample(n=delta))
else:
    delta = dfx.shape[0]
    df3 = dfx.append(falseFrame.sample(n=delta))

df3.to_csv('C:/Users/570835/PycharmProjects/CyberSaint/ba-risk-model/bah/model/scenario_module/caseFile.csv',
           index=None)
