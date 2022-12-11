from pybbn.graph.dag import Bbn
from pybbn.graph.jointree import EvidenceBuilder
from pybbn.pptc.inferencecontroller import InferenceController
import os


class Scenario:

    def __init__(self, bbn_file, uuid=None, attackGeography=None, attackAction=None, attackThreatType=None,
                 attackLossType=None, orgSize=None, attackIndustry=None, attackTarget=None,
                 aprioriProbability=0.5):
        self.bbn_file = bbn_file
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

        bbn = Bbn.from_json(self.bbn_file)

        # convert the BBN to a join tree
        join_tree0 = InferenceController.apply(bbn)

        # update incident CPT
        node = [n for n in bbn.nodes if bbn.nodes[n].variable.name == 'attack'][0]
        bbn.nodes[node].variable.probs = [self.aprioriProbability, 1. - self.aprioriProbability]
        join_tree = InferenceController.reapply(join_tree0, {node: [self.aprioriProbability, 1. - self.aprioriProbability]})

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
        #     .with_evidence('T', 1) \
        #     .build()
        # join_tree.set_observation(ev7)

        # print all the marginal probabilities
        potentialOut = 0
        for node in join_tree.get_bbn_nodes():
            potential = join_tree.get_bbn_potential(node)
            if verbose:
                print(potential)
            if node.variable.name == 'attack':
                potentialOut = potential.entries[0].value

        self.posteriorProbability = potentialOut


if __name__ == '__main__':
    bbn_file = os.path.join(os.path.dirname(__file__), './scenario_bbn2.json')
    # scenario = Scenario(attackLossType='c', orgSize='small', attackAction='hacking', attackGeography='apac',
    #                    attackThreatType='external', aprioriProbability=0.5, bbn_file=bbn_file)
    # scenario = Scenario(attackAction='hacking', attackGeography='na', attackIndustry='professional', aprioriProbability=0.5, bbn_file=bbn_file)
    scenario = Scenario(attackLossType='a', orgSize='small', attackAction='social', attackGeography='na',
                        attackIndustry='professional', aprioriProbability=0.5, bbn_file=bbn_file)
    scenario = Scenario(attackThreatType='internal', attackAction='misuse', aprioriProbability=0.5, bbn_file=bbn_file)
    #scenario = Scenario(attackGeography='na', attackIndustry='healthcare', orgSize='small',
    #                    attackThreatType='external', attackAction='hacking',
    #                    attackLossType='i', bbn_file=bbn_file)
    scenario = Scenario(bbn_file=bbn_file, attackAction='error', attackThreatType='internal', attackIndustry='retail')
    scenario = Scenario(attackAction='misuse', attackThreatType='internal', attackTarget='enterprise',
                        attackLossType='a', attackIndustry='healthcare', attackGeography='na', orgSize="unknown",
                        bbn_file=bbn_file, aprioriProbability=0.05)
    #scenario = Scenario(bbn_file=bbn_file, attackThreatType='external', attackAction='malware', attackIndustry='retail', aprioriProbability=0.05)
    scenario.determine_scenario_probability(verbose=True)

    print("true  " + str(round(100. * scenario.posteriorProbability, 1)))
    print("false " + str(round((1 - scenario.posteriorProbability) * 100., 1)))
