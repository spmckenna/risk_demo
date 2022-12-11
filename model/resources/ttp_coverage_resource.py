from flask_restful import Resource
from flask import request
from dataclasses import dataclass
from bah.model.VistaOutput import ValueVar
from bah.model.run_vista import run_ttp_coverage_metric


@dataclass
class MitreAttackControl:
    label: str
    score: float
    ttps: []


@dataclass
class ttpCoverageRequest:
    controls: [MitreAttackControl]
    action: None


@dataclass
class ttpCoverageResponse:
    success: bool
    threatCoverage: ValueVar
    controlEffectiveness: ValueVar
    controlCoverage: ValueVar

    def reprJSON(self):
        return dict(
            threatCoverage=self.threatCoverage.reprJSON(),
            controlEffectiveness=self.controlEffectiveness.reprJSON(),
            controlCoverage=self.controlCoverage.reprJSON()
        )


class TtpCoverageResource(Resource):
    def post(self):
        json_data = request.json
        ttpCoverageInput = self.jsonToInput(json_data)
        ttp_output = run_ttp_coverage_metric(ttpInput=ttpCoverageInput)
        return ttpCoverageResponse(success=True, threatCoverage=ValueVar(value=ttp_output['threat_coverage'],
                                                                         confidenceInterval=ttp_output[
                                                                             'confidence_interval'],
                                                                         variance=ttp_output['var']),
                                   controlEffectiveness=ValueVar(value=ttp_output['effectiveness'],
                                                                 confidenceInterval=ttp_output['confidence_interval'],
                                                                 variance=ttp_output['var']),
                                   controlCoverage=ValueVar(value=ttp_output['coverage'],
                                                            confidenceInterval=0.0,
                                                            variance=0.0)
                                   ).reprJSON()

    def jsonToInput(self, data):
        controls: [MitreAttackControl] = []

        for item in data['controls']:
            controls.append(
                MitreAttackControl(
                    label=item['label'],
                    score=item['score'],
                    ttps=item['ttps']
                )
            )
        if 'action' in data.keys():
            action = data['action']
        else:
            action = 'malware'

        return ttpCoverageRequest(
            controls=controls, action=action
        )
