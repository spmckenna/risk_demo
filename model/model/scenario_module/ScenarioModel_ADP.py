import pandas as pd
from pybbn.graph.dag import Bbn
from pybbn.graph.jointree import EvidenceBuilder
from pybbn.pptc.inferencecontroller import InferenceController


class Scenario:

    def __init__(self, uuid=None, attackGeography=None, attackAction=None, attackThreatType=None,
                 attackLossType=None, orgSize=None, attackIndustry=None, attackTarget=None,
                 aprioriProbability=0.5):
        self.uuid = uuid
        self.aprioriProbability = aprioriProbability
        self.posteriorProbability = aprioriProbability
        self.attackGeography = attackGeography
        self.attackAction = attackAction
        self.attackLossType = attackLossType
        if attackIndustry is not None and 'mining' in attackIndustry:
            attackIndustry = 'miningandutilities'  # TODO here in case the UI doesn't update
        self.attackIndustry = attackIndustry
        self.orgSize = orgSize
        self.attackThreatType = attackThreatType
        self.attackTarget = attackTarget

    def determine_scenario_probability(self, verbose=False):
        """
        Function that returns probability of attack using DBIR data in a BBN
        :param verbose: Boolean to print result to terminal
        """

        bbn = Bbn.from_json(
            'C:/Users/570835/PycharmProjects/CyberSaint/ba-risk-model/bah/model/scenario_module/scenario_bbn.json')

        # convert the BBN to a join tree
        join_tree = InferenceController.apply(bbn)

        # insert evidence
        if (self.attackGeography is not None) and (self.attackGeography != "global"):
            ev1 = EvidenceBuilder() \
                .with_node(join_tree.get_bbn_node_by_name('region')) \
                .with_evidence(self.attackGeography, 1.0) \
                .build()
            join_tree.set_observation(ev1)

        if self.attackIndustry is not None:
            ev2 = EvidenceBuilder() \
                .with_node(join_tree.get_bbn_node_by_name('industry')) \
                .with_evidence(self.attackIndustry, 1.0) \
                .build()
            join_tree.set_observation(ev2)

        if self.attackThreatType is not None:
            ev3 = EvidenceBuilder() \
                .with_node(join_tree.get_bbn_node_by_name('actor')) \
                .with_evidence(self.attackThreatType, 1.0) \
                .build()
            join_tree.set_observation(ev3)

        if self.attackLossType is not None:
            ev4 = EvidenceBuilder() \
                .with_node(join_tree.get_bbn_node_by_name('attribute')) \
                .with_evidence(self.attackLossType, 1.0) \
                .build()
            join_tree.set_observation(ev4)

        if self.attackAction is not None:
            ev5 = EvidenceBuilder() \
                .with_node(join_tree.get_bbn_node_by_name('action')) \
                .with_evidence(self.attackAction, 1.0) \
                .build()
            join_tree.set_observation(ev5)

        if (self.orgSize is not None) and (self.orgSize != "unknown"):
            ev6 = EvidenceBuilder() \
                .with_node(join_tree.get_bbn_node_by_name('orgSize')) \
                .with_evidence(self.orgSize, 1.0) \
                .build()
            join_tree.set_observation(ev6)

        # ev7 = EvidenceBuilder() \
        #     .with_node(join_tree.get_bbn_node_by_name('incident')) \
        #     .with_evidence('T', 1.0) \
        #     .build()
        # join_tree.set_observation(ev7)

        # print all the marginal probabilities
        potentialOut = 0
        for node in join_tree.get_bbn_nodes():
            potential = join_tree.get_bbn_potential(node)
            if verbose:
                print(potential)
            if node.variable.name == 'incident':
                if potential.entries[0].entries.values() == 'T':
                    potentialOut = potential.entries[0].value
                else:
                    potentialOut = potential.entries[1].value

        self.posteriorProbability = potentialOut


if __name__ == '__main__':

    # Code for ADP
    df = pd.DataFrame(index=range(3*5*3), columns=['action', 'actor', 'attribute', 'prob'])
    if True:
        r = 0
        for loss in ['c', 'i', 'a']:
            for ta in ['external', 'internal', 'partner']:
                if ta in ['internal']:
                    actionList = ['error', 'misuse']
                else:
                    actionList = ['hacking', 'malware', 'social']
                for aa in actionList:
                    scenario = Scenario(attackLossType=loss, orgSize='large', attackAction=aa, attackGeography='na',
                                        attackIndustry='professional', attackThreatType=ta, aprioriProbability=0.5)
                    scenario.determine_scenario_probability(verbose=False)
                    df.iloc[r]['action'] = aa
                    df.iloc[r]['actor'] = ta
                    df.iloc[r]['attribute'] = loss
                    df.iloc[r]['prob'] = round(scenario.posteriorProbability * 100., 1)
                    print(loss + ',' + aa + ',' + ta + ',' + str(round(scenario.posteriorProbability * 100., 1)))
                    r = r + 1

    df.to_csv('C:\\McKenna\\Booz Allen\\Commercial Cyber\\Engagements\\ADP\\Feb2022\\dbir_scenario_ordering2.csv',
              index=None)
