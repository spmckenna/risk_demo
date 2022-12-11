from scipy import interpolate
from scipy.stats import poisson

import platform
import os
from model.model.VistaOutput import VistaOutput, ValueVar
from model.model.config import INPUTS
from model.model.entity_module.Entity import Organization
from model.model.threat_module.ThreatActor import ThreatActor
from model.model.scenario_module import ScenarioModel
from model.model.environment_module.network_traversal import *
from model.model.helpers.helper_functions import get_confidence_interval, flatten_list, compute_metric
from collections import OrderedDict
from pert import PERT
import numpy as np
from scipy.stats import uniform, norm
import logging
import pandas as pd


def generate_pert_random_variables(modeValue=0.5, gamma=2.0, nIterations=1000):
    """
    The Beta-PERT methodology was developed in the context of Program Evaluation and Review Technique (PERT). It is 
    based on a pessimistic estimate (minimum value), a most likely estimate (mode), and an optimistic estimate 
    (maximum value), typically derived through expert elicitation. 
    
    :param modeValue: the mode
    :param gamma: the spread parameter
    :param nIterations: number of values to generate
    :return: nIterations samples from the specified PERT distribution
    """
    maxValue = 1
    return PERT(0, modeValue, maxValue, gamma).rvs(size=nIterations)


def generate_gaussian_random_variables(mean=0.0, stdDev=1.0, nIterations=1000):
    """
    :param mean: mean
    :param stdDev: standard deviation
    :param nIterations: number of values to generate
    :return: nIterations samples from the normal distribution
    """
    return norm.rvs(loc=mean, scale=stdDev, size=nIterations)


def generate_uniform_random_variables(nIterations=1000):
    """
    Generate random variables from the uniform distribution from 0 to 1
    :param nIterations: number of values to generate
    :return: nIterations samples from the unit uniform distribution
    """
    return uniform.rvs(loc=0, scale=1, size=nIterations)


def determine_initial_access(tac, proti, protr, vuln, iaRV, coeffs):  # TODO these could be done "once" outside loop
    """
    :param tac: threat actor capacity
    :param proti: CSF Protect Function metric, inherent
    :param protr: CSF Protect Function metric, residual
    :param vuln: vulnerability metric
    :param iaRV: Initial Access random variable
    :param coeffs: Threat Actor Capability versus Control Effectiveness fit coefficients
    :return: A pair of booleans (inherent, residual), with True for success, False for fail
    """
    inherent_vuln = vuln * (1 - proti)
    residual_vuln = vuln * (1 - protr)
    p00 = coeffs[0]
    p10 = coeffs[1]
    p01 = coeffs[2]
    p20 = coeffs[3]
    p11 = coeffs[4]
    p02 = coeffs[5]
    p30 = coeffs[6]
    p21 = coeffs[7]
    p12 = coeffs[8]
    p03 = coeffs[9]
    x = 1 - inherent_vuln
    y = tac
    prob = p00 + p10 * x + p01 * y + p20 * x ** 2 + p11 * x * y + p02 * y ** 2 + \
           p30 * x ** 3 + p21 * x ** 2 * y + p12 * x * y ** 2 + p03 * y ** 3
    if prob < 0:
        prob = 0.
    elif prob > 1:
        prob = 1.

    if iaRV <= prob:
        inherent_result = True
    else:
        inherent_result = False

    x = 1 - residual_vuln
    prob = p00 + p10 * x + p01 * y + p20 * x ** 2 + p11 * x * y + p02 * y ** 2 + \
           p30 * x ** 3 + p21 * x ** 2 * y + p12 * x * y ** 2 + p03 * y ** 3
    if prob < 0:
        prob = 0.
    elif prob > 1:
        prob = 1.
    if iaRV <= prob:
        residual_result = True
    else:
        residual_result = False

    return inherent_result, residual_result


def determine_execution(tac, proti, protr, exploitability, execRV, coeffs):
    """
    :param tac: threat actor capacity
    :param proti: CSF Protect Function metric, inherent
    :param protr: CSF Protect Function metric, residual
    :param exploitability: exploitability metric
    :param execRV: Initial Access random variable
    :param coeffs: Threat Actor Capability versus Control Effectiveness fit coefficients
    :return: A pair of booleans (inherent, residual), with True for success, False for fail
    """
    inherent_expl = exploitability * (1 - proti)
    residual_expl = exploitability * (1 - protr)

    p00 = coeffs[0]
    p10 = coeffs[1]
    p01 = coeffs[2]
    p20 = coeffs[3]
    p11 = coeffs[4]
    p02 = coeffs[5]
    p30 = coeffs[6]
    p21 = coeffs[7]
    p12 = coeffs[8]
    p03 = coeffs[9]
    x = 1 - inherent_expl
    y = tac
    prob = p00 + p10 * x + p01 * y + p20 * x ** 2 + p11 * x * y + p02 * y ** 2 + \
           p30 * x ** 3 + p21 * x ** 2 * y + p12 * x * y ** 2 + p03 * y ** 3
    if prob < 0:
        prob = 0.
    elif prob > 1:
        prob = 1.
    if execRV <= prob:
        inherent_result = True
    else:
        inherent_result = False

    x = 1 - residual_expl
    prob = p00 + p10 * x + p01 * y + p20 * x ** 2 + p11 * x * y + p02 * y ** 2 + \
           p30 * x ** 3 + p21 * x ** 2 * y + p12 * x * y ** 2 + p03 * y ** 3
    if prob < 0:
        prob = 0.
    elif prob > 1:
        prob = 1.
    if execRV <= prob:
        residual_result = True
    else:
        residual_result = False

    return inherent_result, residual_result


def determine_movement():
    # TBD
    return 0


def determine_impact(rri, rrr, entity):
    """
    I = (1 - RR) * VAL
    :param rri: CSF Respond & Recover Function metric, inherent
    :param rrr:  CSF Respond & Recover Function metric, residual
    :param entity: entity object
    :return: A pair of impact values (inherent, residual)
    """
    inherentImpact = entity.value['self'] * (1 - rri)
    residualImpact = entity.value['self'] * (1 - rrr)
    return inherentImpact, residualImpact


def compute_impact_values(vistaInput, impactCalcMode='mean'):
    """
    Compute impact values
    :param vistaInput: input object containing input impact values
    :param impactCalcMode: either 'mean' or 'max'
    :return: total impact (using either mean or max approach), direct impact, and indirect impact
    """
    directImpactValues = list(vistaInput.impact.directImpact.__dict__.values())
    indirectImpactValues = list(vistaInput.impact.indirectImpact.__dict__.values())
    directImpactValue = np.mean(directImpactValues)
    indirectImpactValue = np.mean(indirectImpactValues)
    if impactCalcMode == 'mean':
        impact = np.mean((directImpactValue, indirectImpactValue))
    else:
        impact = np.max(directImpactValues + indirectImpactValues)
    return impact, directImpactValue, indirectImpactValue


def compute_quant_impact(vistaInput, nIterations):
    """
    Compute quant impact
    :param vistaInput: input object containing input impact values
    :param nIterations number of values to return
    :return: quant impact
    """
    scale = vistaInput.quantImpact.maxImpact
    impact = PERT(vistaInput.quantImpact.minImpact/scale, vistaInput.quantImpact.avgImpact/scale,
                  vistaInput.quantImpact.maxImpact/scale).rvs(size=nIterations)
    return impact[0], scale


def update_attack_probability_given_rate(poissonRate, timeWindow, attackMotivator):
    """
    Compute the posterior probability of attack using a prior attack rate estimate and new information -- in this case,
        the Attack Motivator metric, using the log-odds-ratio method
    :param poissonRate: rate of attack as counts per [unit of time]
    :param timeWindow: window of time we are concerned with (number of units of time)
    :param attackMotivator: Attack Motivator metric
    :return: posterior probability and prior probability
    """
    priorAttackProbability = np.min((0.99, 1. - poisson.cdf(1, poissonRate)))  # 1 or more attacks, aka ALO
    condProbTable = np.array([max(0.01, 0.1 * priorAttackProbability),  # these values are SPM-best-guesses
                              max(0.01, 0.5 * priorAttackProbability),
                              priorAttackProbability,
                              min(1.5 * priorAttackProbability, 0.99),
                              min(2 * priorAttackProbability, 0.99)], dtype=np.double)
    baselineLogOdds = np.log(priorAttackProbability / (1 - priorAttackProbability))
    logOddsChangeAttackProbability = np.log(np.divide(condProbTable, (1 - condProbTable))) - baselineLogOdds
    x = logOddsChangeAttackProbability + baselineLogOdds
    attackProbabilityTable = np.divide(1, (1 + np.divide(1, np.exp(x))))
    func = interpolate.interp1d(np.arange(5) / 4., attackProbabilityTable, kind='linear')
    attackProbability = func(attackMotivator)
    attackProbability = 1 - (1 - attackProbability) ** timeWindow
    priorAttackProbability = 1 - (1 - priorAttackProbability) ** timeWindow
    return attackProbability, priorAttackProbability


def update_attack_probability_given_probability(priorAttackProbability, timeWindow, attackMotivator):
    """
    Compute the posterior probability of attack using a prior probability estimate and new information -- in this case,
    the Attack Motivator metric, using the log-odds-ratio method
    :param priorAttackProbability: prior probability estimate (over [unit of time])
    :param timeWindow: window of time we are concerned with (number of units of time)
    :param attackMotivator: Attack Motivator metric
    :return: posterior probability and prior probability
    """
    condProbTable = np.array([max(0.01, 0.1 * priorAttackProbability),  # these values are SPM-best-guesses
                              max(0.01, 0.5 * priorAttackProbability),
                              priorAttackProbability,
                              min(1.5 * priorAttackProbability, 0.99),
                              min(2 * priorAttackProbability, 0.99)], dtype=np.double)
    baselineLogOdds = np.log(priorAttackProbability / (1 - priorAttackProbability))
    logOddsChangeAttackProbability = np.log(np.divide(condProbTable, (1 - condProbTable))) - baselineLogOdds
    x = logOddsChangeAttackProbability + baselineLogOdds
    attackProbabilityTable = np.divide(1, (1 + np.divide(1, np.exp(x))))
    func = interpolate.interp1d(np.arange(5) / 4., attackProbabilityTable, kind='linear')
    attackProbability = func(attackMotivator)
    attackProbability = 1 - (1 - attackProbability) ** timeWindow
    priorAttackProbability = 1 - (1 - priorAttackProbability) ** timeWindow
    return attackProbability, priorAttackProbability


def update_metric(x, z, baselineStdDev=0.2, measStdDev=0.1):
    """
    Function to update the estimate of a metric using a "measurement" of the metric, based on Kalman Filter
    :param x: initial estimate of the metric
    :param z: measurement of the metric
    :param baselineStdDev: std dev of the initial estimate of the metric
    :param measStdDev: std dev of the measurement of the metric
    :return: updated estimate of the metric
    """
    x10 = x  # initial estimate
    p10 = baselineStdDev * baselineStdDev  # uncertainty of initial estimate
    k = p10 / (p10 + measStdDev * measStdDev)  # Kalman gain
    x11 = x10 + k * (z - x10)  # updated estimate
    p11 = (1 - k) * p10  # updated uncertainty
    return x11, p11


def runVista(vistaInput, graph, prog_bar=None, sweep=False):
    """
    Main routine to run the Booz Allen Cyber Risk Engine
    :param vistaInput: input object
    :param graph: network model as a graph
    :param sweep: flag to indicate if we're doing a parameter sweep
    :return: outputs
    """
    # used for testing, etc.
    if platform.uname()[1] == 'xBAHG3479J3' and not sweep:
        random_seed = 101798
        logger = logging.getLogger('Main')
        logger.setLevel(level=logging.DEBUG)
    else:
        logger = logging.getLogger('Main')
        logger.setLevel(level=logging.INFO)
        rng = np.random.default_rng()
        random_seed = int(rng.random() * 100000)

    np.random.seed(random_seed)

    numberOfMonteCarloRuns = INPUTS['numberOfMonteCarloRuns']
    impactCalcMode = INPUTS['impactCalcMode']
    coeffs = INPUTS['tac_v_ctrl_coeffs']

    # Compute quant impact
    impactValue, impactScale = compute_quant_impact(vistaInput, 1)

    # Define the "atomic" entity
    enterprise = Organization('enterprise', label='Enterprise')
    enterprise.assign_value(impactValue * impactScale, 'self')

    # Create list of all entities
    allEntitiesList = [enterprise]

    # Set up threat actor
    threat_actor = ThreatActor(uuid="0000", label='nominal')
    if vistaInput.scenario.attackAction == 'error':  # current approach to error case
        vistaInput.threatActorInput.determination = 0
        vistaInput.threatActorInput.determinationWeight = 0
    threat_actor.attemptLimit = max(1, int(vistaInput.threatActorInput.determination * 10))

    threat_actor.properties['capability'] = np.sum((
        vistaInput.threatActorInput.determination * vistaInput.threatActorInput.determinationWeight,
        vistaInput.threatActorInput.resources * vistaInput.threatActorInput.resourcesWeight,
        vistaInput.threatActorInput.sophistication * vistaInput.threatActorInput.sophisticationWeight)) / (
                                                  vistaInput.threatActorInput.determinationWeight +
                                                  vistaInput.threatActorInput.resourcesWeight +
                                                  vistaInput.threatActorInput.sophisticationWeight)

    # Assign control values to each entity
    for a in allEntitiesList:
        a.controls['csf']['identify']['value'] = vistaInput.csf.identify.value
        a.controls['csf']['protect']['value'] = vistaInput.csf.protect.value
        a.controls['csf']['detect']['value'] = vistaInput.csf.detect.value
        a.controls['csf']['respond']['value'] = vistaInput.csf.respond.value
        a.controls['csf']['recover']['value'] = vistaInput.csf.recover.value
        a.allocate_data_space(numberOfMonteCarloRuns)

    # Use this metadata to set prior probability of attack
    attackAction = vistaInput.scenario.attackAction
    attackTarget = vistaInput.scenario.attackTarget  # also, threat actor objective here
    attackIndustry = vistaInput.scenario.attackIndustry
    attackGeography = vistaInput.scenario.attackGeography
    attackLossType = vistaInput.scenario.attackLossType
    attackThreatType = vistaInput.scenario.attackThreatType
    orgSize = vistaInput.scenario.orgSize

    bbn_file = os.path.join(os.path.dirname(__file__), INPUTS['bbn_file'])

    scenario = ScenarioModel.Scenario(attackAction=attackAction, attackThreatType=attackThreatType,
                                      attackGeography=attackGeography, attackLossType=attackLossType,
                                      attackIndustry=attackIndustry, orgSize=orgSize)
    scenario.determine_scenario_probability_scale_factor(bbn_file=bbn_file, verbose=False)

    # TODO make these entries optional, if that is deemed a good idea, then update them as below if there is info to
    # use for the update, o/w use baseline
    # Compute Attack Motivator metric
    attackMotivator0 = 0.5  # baseline value of 0.5
    attackMotivator_ = np.mean([vistaInput.attackMotivators.reward,  # TODO weights?
                                vistaInput.attackMotivators.appeal,
                                vistaInput.attackMotivators.targeting,
                                vistaInput.attackMotivators.perceivedDefenses])
    attackMotivator, _ = update_metric(attackMotivator0, attackMotivator_)

    probability_scale_factor0 = scenario.probability_scale_factor

    probability_scale_factor = scenario.probability_scale_factor * attackMotivator

    """
    Bayes to incorporate log data (a la ARM) (not in VISTA, but noted here for future)
    attackProbabilityBayes = probLogDataGivenAttack * probAttack / probLogData
    """

    # Compute Threat Level; only used as a reporting metric
    # MODEL: power = ~rate * force;  P = F * V
    threatLevel = compute_metric(probability_scale_factor, threat_actor.properties['capability'], method="harmonic")

    # Pre-allocate space
    attackDict = OrderedDict((k, {}) for k in range(numberOfMonteCarloRuns))
    riskI = np.zeros((numberOfMonteCarloRuns,))
    riskR = np.zeros((numberOfMonteCarloRuns,))
    impactI = np.zeros((numberOfMonteCarloRuns,))
    impactR = np.zeros((numberOfMonteCarloRuns,))
    accessI = np.zeros((numberOfMonteCarloRuns,))
    accessR = np.zeros((numberOfMonteCarloRuns,))

    # TODO using this idea, but not sold on it
    # Using baseline Attack Surface metric, update it with attack surface values from inputs
    attackSurface0 = 0.5  # baseline value of 0.5
    attackSurface_ = np.mean([vistaInput.attackSurface.awareness, vistaInput.attackSurface.opportunity])
    attackSurface, _ = update_metric(attackSurface0, attackSurface_)

    # Using baseline Exploitability metric, update it with exploitability value from inputs
    exploitability0 = 0.5  # baseline value of 0.5
    exploitability_ = vistaInput.exploitability.easeOfExploit
    exploitability, _ = update_metric(exploitability0, exploitability_)

    # Compute Vulnerability metrics
    vulnerability = compute_metric(exploitability, attackSurface, method='geometric')  # MODEL: flux = porosity * area * gradient(=1)

    # Get random variable samples ahead of the MCS
    exploitabilityRV = generate_pert_random_variables(modeValue=exploitability,
                                                      nIterations=numberOfMonteCarloRuns)
    attackSurfaceRV = generate_pert_random_variables(modeValue=attackSurface,
                                                     nIterations=numberOfMonteCarloRuns)
    vulnerabilityRV = compute_metric(exploitabilityRV, attackSurfaceRV, method='geometric')

    initial_accessRV = generate_uniform_random_variables(nIterations=numberOfMonteCarloRuns)
    execution_accessRV = generate_uniform_random_variables(nIterations=numberOfMonteCarloRuns)

    detectRVInherent = np.zeros([numberOfMonteCarloRuns])
    detectRVResidual = generate_pert_random_variables(modeValue=vistaInput.csf.detect.value,
                                                      gamma=0.1 + 100 * vistaInput.csf.identify.value,
                                                      nIterations=numberOfMonteCarloRuns)

    protectRVInherent = np.zeros([numberOfMonteCarloRuns])
    protectRVResidual = generate_pert_random_variables(modeValue=vistaInput.csf.protect.value,
                                                       gamma=0.1 + 100 * vistaInput.csf.identify.value,
                                                       nIterations=numberOfMonteCarloRuns)

    # Compute combined Protect and Detect metric
    protectDetectRVInherent = np.zeros([numberOfMonteCarloRuns])
    protectDetectRVResidual = np.divide(np.add(detectRVResidual, protectRVResidual), 2)

    respondRVInherent = np.zeros([numberOfMonteCarloRuns])
    respondRVResidual = generate_pert_random_variables(modeValue=vistaInput.csf.respond.value,
                                                       gamma=0.1 + 100 * vistaInput.csf.identify.value,
                                                       nIterations=numberOfMonteCarloRuns)

    recoverRVInherent = np.zeros([numberOfMonteCarloRuns])
    recoverRVResidual = generate_pert_random_variables(modeValue=vistaInput.csf.recover.value,
                                                       gamma=0.1 + 100 * vistaInput.csf.identify.value,
                                                       nIterations=numberOfMonteCarloRuns)

    # Compute combined Respond and Recover metric
    respondRecoverRVInherent = np.zeros([numberOfMonteCarloRuns])
    respondRecoverRVResidual = np.divide(np.add(respondRVResidual, recoverRVResidual), 2)

    """
    ******************************************
    MC loop begins for inherent and residual *
    ******************************************
    Each iteration is a single attack
    A single attack may have multiple attempts, though, based on the TA attemptLimit
    """

    for iteration in range(0, numberOfMonteCarloRuns):
        if prog_bar is not None:
            prog_bar.progress(iteration/(numberOfMonteCarloRuns-1))
        tryCountI, tryCountR = 1, 1
        origin = 'internet'
        destination = 'enterprise'  # attack target
        entryNode = 'enterprise'  # first node to gain entry

        initialAccess = True

        currentNode = None
        failedNodeList = []
        doResidual = True

        logger.debug(' -----------------')
        logger.debug(' Iteration: ' + str(iteration))

        attackDict[iteration]['iteration'] = iteration
        attackDict[iteration]['attack_type'] = 'nominal'
        attackDict[iteration]['probability_scale_factor'] = probability_scale_factor
        attackDict[iteration]['origin'] = origin
        attackDict[iteration]['destination'] = destination
        attackDict[iteration]['entryPoint'] = entryNode
        attackDict[iteration]['sequenceI'] = [origin]
        attackDict[iteration]['sequenceR'] = [origin]

        attackDictElement = attackDict[iteration]
        done = False

        while not done:

            while tryCountI <= threat_actor.attemptLimit:  # tryCountI should always be < tryCountR

                if initialAccess:
                    from_node = attackDictElement['origin']
                    objective_node = attackDictElement['entryPoint']
                    logger_from_string = attackDictElement['origin']
                else:
                    from_node = currentNode
                    objective_node = attackDictElement['destination']
                    logger_from_string = currentNode

                nextNode = from_node_to_node(from_node=from_node,
                                             objective_node=objective_node,
                                             attack_type=attackDictElement['attack_type'],
                                             graph=graph,
                                             all_assets_list=allEntitiesList,
                                             failed_node_list=failedNodeList)
                if nextNode is not None:
                    logger.debug(' ' + logger_from_string + ' ----> ' + nextNode.uuid)

                if nextNode is None:
                    logger.debug(' End of path reached')
                    tryCountI += 1
                    tryCountR += 1
                    failedNodeList.append(nextNode)
                    if tryCountI > threat_actor.attemptLimit:
                        logger.debug('   End of path reached (I/R), attacker giving up')
                        done = True
                        break
                    else:
                        logger.debug('   End of path reached (I), attacker trying again')
                    if doResidual:
                        if tryCountR > threat_actor.attemptLimit:
                            logger.debug('   End of path reached (R), attacker giving up')
                            doResidual = False
                        elif doResidual:
                            logger.debug('   End of path reached (R), attacker trying again')
                        else:
                            logger.debug('   End of path reached (R), residual attack ends')
                        continue

                # Determine if threat actor gains INITIAL ACCESS to entity

                if (attackAction == 'error') or (attackAction == 'misuse'):
                    inherentAccess = True  # these are for insider, who has initial access
                    residualAccessIA = True
                else:
                    inherentAccess, residualAccessIA = determine_initial_access(threat_actor.properties['capability'],
                                                                                protectDetectRVInherent[iteration],
                                                                                protectDetectRVResidual[iteration],
                                                                                vulnerabilityRV[iteration],
                                                                                initial_accessRV[iteration], coeffs)

                if nextNode is not None:

                    if inherentAccess is False:  # residualAccess should also be False
                        tryCountI += 1
                        tryCountR += 1
                        failedNodeList.append(nextNode)
                        if tryCountI > threat_actor.attemptLimit:
                            logger.debug('   Failed (I/R), attacker giving up - too many tries')
                            done = True
                            break
                        else:
                            logger.debug('   Failed (I), trying again')
                        if tryCountR > threat_actor.attemptLimit and doResidual:
                            logger.debug('   Failed (R), residual attack ends - too many tries')
                            doResidual = False
                        elif doResidual:  # both False
                            logger.debug('   Failed (R), but trying again since inherent also failed')

                    else:
                        logger.debug('   Next hop enabled (I) ...')
                        initialAccess = False
                        currentNode = nextNode.uuid

                        if residualAccessIA is False and doResidual:
                            logger.debug(
                                '   Failed (R), residual attack ends since inherent succeeded')
                            doResidual = False
                        elif residualAccessIA is True and doResidual:
                            logger.debug('       Next hop enabled (R) ...')
                            currentNode = nextNode.uuid

                    if currentNode == attackDictElement['destination']:
                        done = True
                        initialAccess = False
                        logger.debug(
                            '       Reached target (I)                                             XXX')
                        if residualAccessIA is True:
                            logger.debug(
                                '       Reached target (R)                                             ^^^')
                        break

            if tryCountI > threat_actor.attemptLimit:
                done = True

            if nextNode is not None:
                inherentExecution, residualExecution = determine_execution(threat_actor.properties['capability'],
                                                                           protectDetectRVInherent[iteration],
                                                                           protectDetectRVResidual[iteration],
                                                                           exploitabilityRV[iteration],
                                                                           execution_accessRV[iteration], coeffs)

                logger.debug(' Execution success?. (I): ' + str(inherentExecution))
                logger.debug(' Execution success? (R): ' + str(residualExecution))
                inherentImpact = 0.
                residualImpact = 0.
                inherentAccess = 0.
                residualAccess = 0.
                if residualExecution and residualAccessIA:
                    residualAccess = 1.
                    inherentAccess = 1.
                    inherentImpact, residualImpact = determine_impact(respondRecoverRVInherent[iteration],
                                                                      respondRecoverRVResidual[iteration], nextNode)
                    logger.debug(' Inherent Impact: ' + str(round(inherentImpact, 2)))
                    logger.debug(' Residual Impact: ' + str(round(residualImpact, 2)))
                elif inherentExecution:
                    inherentAccess = 1.
                    inherentImpact, residualImpact = determine_impact(respondRecoverRVInherent[iteration],
                                                                      respondRecoverRVResidual[iteration], nextNode)
                    logger.debug(' Inherent Impact: ' + str(round(residualImpact, 2)))
                    residualImpact = 0.
                riskR[iteration] = probability_scale_factor * residualImpact
                riskI[iteration] = probability_scale_factor * inherentImpact
                impactR[iteration] = residualImpact
                impactI[iteration] = inherentImpact
                accessR[iteration] = residualAccess
                accessI[iteration] = inherentAccess
                nextNode.impactR[iteration] = residualImpact
                nextNode.impactI[iteration] = inherentImpact
                nextNode.accessR[iteration] = residualAccess
                nextNode.accessI[iteration] = inherentAccess
            else:
                riskR[iteration] = 0.
                riskI[iteration] = 0.
                impactR[iteration] = 0.
                impactI[iteration] = 0.
                accessR[iteration] = 0.
                accessI[iteration] = 0.

    # Collect MCS results to calculate the outputs we want (for the single enterprise node)
    for a in allEntitiesList:
        a.lhR_vec = probability_scale_factor * a.accessR
        a.lhI_vec = probability_scale_factor * a.accessI
        a.impR_vec = a.impactR/impactScale
        a.impI_vec = a.impactI/impactScale
        a.riskI_vec = np.multiply(a.lhI_vec, a.impI_vec)
        a.riskR_vec = np.multiply(a.lhR_vec, a.impR_vec)

        # Computing confidence intervals
        a.LH_confIntI = get_confidence_interval(a.lhI_vec, alpha=INPUTS['confidenceAlpha'])
        a.LH_confIntR = get_confidence_interval(a.lhR_vec, alpha=INPUTS['confidenceAlpha'])
        a.imp_confIntI = get_confidence_interval(a.impI_vec[a.accessI == 1], alpha=INPUTS['confidenceAlpha'])
        a.imp_confIntR = get_confidence_interval(a.impR_vec[a.accessR == 1], alpha=INPUTS['confidenceAlpha'])
        a.risk_confIntI = get_confidence_interval(a.riskI_vec, alpha=INPUTS['confidenceAlpha'])
        a.risk_confIntR = get_confidence_interval(a.riskR_vec, alpha=INPUTS['confidenceAlpha'])
        if INPUTS['scoring_lambda'] == 0:
            tmpRiskTransformedI_vec = np.log(a.riskI_vec + 1e-10)
            tmpRiskTransformedR_vec = np.log(a.riskR_vec + 1e-10)
        else:
            tmpRiskTransformedI_vec = np.power(a.riskI_vec, INPUTS['scoring_lambda'])
            tmpRiskTransformedR_vec = np.power(a.riskR_vec, INPUTS['scoring_lambda'])

        riskLevelI_vec = INPUTS['scoring_fit'][0] * tmpRiskTransformedI_vec + INPUTS['scoring_fit'][1]
        riskLevelI_vec[riskLevelI_vec < 0] = 0
        riskLevelI_vec[riskLevelI_vec > 5] = 5

        riskLevelR_vec = INPUTS['scoring_fit'][0] * tmpRiskTransformedR_vec + INPUTS['scoring_fit'][1]
        riskLevelR_vec[riskLevelR_vec < 0] = 0
        riskLevelR_vec[riskLevelR_vec > 5] = 5

        a.riskLevel_confIntI = max(min(2.5, get_confidence_interval(riskLevelI_vec[riskLevelI_vec > 0],
                                                                    alpha=INPUTS['confidenceAlpha'])), 0)
        a.riskLevel_confIntR = max(min(2.5, get_confidence_interval(riskLevelR_vec[riskLevelR_vec > 0],
                                                                    alpha=INPUTS['confidenceAlpha'])), 0)
        # Computing variances
        a.LH_varI = float(np.var(a.lhI_vec))
        a.LH_varR = float(np.var(a.lhR_vec))

        a.imp_varI = float(np.var(a.impI_vec))
        a.imp_varR = float(np.var(a.impR_vec))

        a.risk_varI = np.var(a.riskI_vec)
        a.risk_varR = np.var(a.riskR_vec)

        a.riskLevel_varI = np.var(riskLevelI_vec)
        a.riskLevel_varR = np.var(riskLevelR_vec)

        if INPUTS['scoring_lambda'] == 0:
            riskTransformedI = np.log(np.mean(a.riskI_vec) + 1e-10)
            riskTransformedR = np.log(np.mean(a.riskR_vec) + 1e-10)
        else:
            riskTransformedI = np.mean(a.riskI_vec) ** INPUTS['scoring_lambda']
            riskTransformedR = np.mean(a.riskR_vec) ** INPUTS['scoring_lambda']

        a.riskLevelI = max(min(5, INPUTS['scoring_fit'][0] * np.mean(riskTransformedI) + INPUTS['scoring_fit'][1]), 0)
        a.riskLevelR = max(min(5, INPUTS['scoring_fit'][0] * np.mean(riskTransformedR) + INPUTS['scoring_fit'][1]), 0)

        # Computing means
        a.lhI = np.mean(a.lhI_vec)
        a.lhR = np.mean(a.lhR_vec)
        if np.sum(a.accessI) == 0:
            a.impI = 0.
        else:
            a.impI = np.mean(a.impI_vec[a.accessI > 0])
        if np.sum(a.accessR) == 0:
            a.impR = 0.
        else:
            a.impR = np.mean(a.impR_vec[a.accessR > 0])
        a.riskI = np.mean(a.riskI_vec)
        a.riskR = np.mean(a.riskR_vec)

        if a.uuid == 'enterprise':

            # SPM diagnostics
            if not sweep:
                print("lhI = " + str(np.round(a.lhI, 4)))
                print("impI = " + str(np.round(a.impI, 4)))
                print("riskI = " + str(np.round(a.riskI, 4)))
                print("riskI_CI = " + str(np.round(a.risk_confIntI, 4)))
                print("riskLevelI = " + str(np.round(a.riskLevelI, 2)))
                print("riskLevelI_CI = " + str(np.round(a.riskLevel_confIntI, 2)))
                print("--------------------------------")

                print("lhR = " + str(np.round(a.lhR, 4)))
                print("impR = " + str(np.round(a.impR, 4)))
                print("riskR = " + str(np.round(a.riskR, 4)))
                print("riskR_CI = " + str(np.round(a.risk_confIntR, 4)))
                print("riskLevelR = " + str(np.round(a.riskLevelR, 2)))
                print("riskLevelR_CI = " + str(np.round(a.riskLevel_confIntR, 2)))
                print("--------------------------------")

            logger.debug('output: ' + str(VistaOutput(
                overallInherentLikelihood=ValueVar(float(a.lhI), a.LH_varI, a.LH_confIntI),
                overallResidualLikelihood=ValueVar(float(a.lhR), a.LH_varR, a.LH_confIntR),
                overallInherentImpact=ValueVar(float(a.impI)*impactScale, a.imp_varI, a.imp_confIntI),
                overallResidualImpact=ValueVar(float(a.impR)*impactScale, a.imp_varR, a.imp_confIntR),
                overallInherentRiskLevel=ValueVar(a.riskLevelI, float(a.riskLevel_varI), a.riskLevel_confIntI),
                overallResidualRiskLevel=ValueVar(a.riskLevelR, float(a.riskLevel_varR), a.riskLevel_confIntR),
                attackSurface=float(attackSurface),
                exploitability=exploitability,
                vulnerability=vulnerability,
                threatActorCapacity=threat_actor.properties['capability'],
                threatLevel=float(np.mean(threatLevel)),
                priorAttackProbability=float(probability_scale_factor0),
                attackProbability=float(probability_scale_factor),
                attackMotivators=float(attackMotivator),
                directImpact=float(impactValue),
                indirectImpact=float(impactValue))))

            return VistaOutput(
                overallInherentLikelihood=ValueVar(float(a.lhI), a.LH_varI, a.LH_confIntI),
                overallResidualLikelihood=ValueVar(float(a.lhR), a.LH_varR, a.LH_confIntR),
                overallInherentImpact=ValueVar(float(a.impI)*impactScale, a.imp_varI, a.imp_confIntI),
                overallResidualImpact=ValueVar(float(a.impR)*impactScale, a.imp_varR, a.imp_confIntR),
                overallInherentRiskLevel=ValueVar(a.riskLevelI, float(a.riskLevel_varI), a.riskLevel_confIntI),
                overallResidualRiskLevel=ValueVar(a.riskLevelR, float(a.riskLevel_varR), a.riskLevel_confIntR),
                attackSurface=float(attackSurface),
                exploitability=exploitability,
                vulnerability=vulnerability,
                threatActorCapacity=threat_actor.properties['capability'],
                threatLevel=float(np.mean(threatLevel)),
                priorAttackProbability=float(probability_scale_factor0),
                attackProbability=float(probability_scale_factor),
                attackMotivators=float(attackMotivator),
                directImpact=float(impactValue),
                indirectImpact=float(impactValue)
            )


"""
Threat Coverage Code
"""


def run_ttp_coverage_metric(ttpInput):
    controls = ttpInput.controls
    action = ttpInput.action
    fam_scores = {}
    for ctrl in controls:
        fam = ctrl.label.split("-")[0]
        if fam in fam_scores.keys():
            fam_scores[fam].append([ctrl.score] * len(ctrl.ttps))
        else:
            fam_scores[fam] = [[ctrl.score] * len(ctrl.ttps)]

    for fam in fam_scores:
        fam_scores[fam] = np.mean(flatten_list(fam_scores[fam]))

    df = pd.read_csv(os.path.join(os.path.dirname(__file__), 'resources/control_action_ttp_mapping.csv'), dtype='string')
    ttps = []
    for r in df.iterrows():
        if not pd.isna(r[1]['MITRE ATTACK Technique']):
            ttps.append(r[1]['MITRE ATTACK Technique'].split('.')[0])
        else:
            ttps.append("")
    df['TTP'] = ttps

    action_dict = {}
    action_list = ['error', 'misuse', 'hacking', 'malware', 'social']
    for act in action_list:
        act_df = df[df['VERIS Threat Action'].str.contains(act + '.variety')]
        action_dict[act] = list(zip(act_df['NIST 800-53 Control'].tolist(), act_df['TTP'].tolist()))

    sum1 = []
    in_scope_ttps = [x[1] for x in action_dict[action]]
    in_scope_actions_ = df[df['VERIS Threat Action'].str.contains(action + '.variety')]
    in_scope_actions = np.unique(in_scope_actions_['VERIS Threat Action'].tolist())

    mitigated_ttps = []
    mitigated_actions = []
    for ctrl_ttp in action_dict[action]:  # the in-scope controls|ttps
        if ctrl_ttp[0] not in [x.label for x in controls]:  # control not assessed
            pass
        else:
            if action in ['hacking', 'malware', 'social']:
                score = [x.score for x in controls if x.label == ctrl_ttp[0]][0]  # control score
                mitigated_ttps.append(ctrl_ttp[1])  # ttp mitigated by this control
                count1 = 1
            else:
                score = [x.score for x in controls if x.label == ctrl_ttp[0]][0]
                if action == 'error':
                    error = df[df['VERIS Threat Action'].str.contains('error.variety')]
                    mitigated_actions_ = error[error['NIST 800-53 Control'].str.contains(ctrl_ttp[0])][
                        'VERIS Threat Action'].tolist()  # actions mitigated by this control
                else:
                    misuse = df[df['VERIS Threat Action'].str.contains('misuse.variety')]
                    mitigated_actions_ = misuse[misuse['NIST 800-53 Control'].str.contains(ctrl_ttp[0])][
                        'VERIS Threat Action'].tolist()  # action(s) mitigated by this control
                count1 = len(mitigated_actions_)  # number of actions mitigated by this control
                mitigated_actions.append(mitigated_actions_)
            sum1.append([score] * count1)

    if len(sum1) > 0:
        effectiveness = np.mean(flatten_list(sum1))
    else:
        effectiveness = 0
    if action in ['hacking', 'malware', 'social']:
        n = len(np.unique(mitigated_ttps))
        d = len(np.unique(in_scope_ttps))
    else:
        n = len(np.unique(flatten_list(mitigated_actions)))
        d = len(in_scope_actions)

    if d > 0:
        coverage = n / d
    else:
        coverage = 0

    threat_coverage = compute_metric(effectiveness, coverage, method='geometric')
    if len(sum1) > 0:
        ci = get_confidence_interval(flatten_list(sum1), alpha=INPUTS['confidenceAlpha'])  # no need to factor in the
                                                                                           # coverage since that is just a
                                                                                           # constant and does not affect
                                                                                           # the CI math
        tc_var = np.var(flatten_list(sum1))
    else:
        ci = 0
        tc_var = 0

    return {'effectiveness': effectiveness,
            'coverage': coverage,
            'n': n,
            'd': d,
            'threat_coverage': threat_coverage,
            'confidence_interval': ci,
            'var': tc_var}
