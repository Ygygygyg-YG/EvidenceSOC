"""One canonical diagnosis contract, also persisted by the product graph."""

from evidencesoc.agents.diagnosis import Diagnosis, FactClaim, StageInstance

__all__ = ["Diagnosis", "FactClaim", "StageInstance", "validate_diagnosis"]


def validate_diagnosis(value, registry: dict) -> Diagnosis:
    diagnosis = Diagnosis.model_validate(value)
    references = list(diagnosis.evidence_ids)
    if diagnosis.origin:
        references.extend(diagnosis.origin.evidence_ids)
    for item in [*diagnosis.claims, *diagnosis.stage_instances]:
        references.extend(item.evidence_ids)
        if not item.evidence_ids:
            raise ValueError("factual diagnosis element lacks an evidence citation")
    if any(reference not in registry for reference in references):
        raise ValueError("diagnosis citation is not in this case trusted registry")
    if diagnosis.verdict in {"attack", "benign"} and not references:
        raise ValueError("answered diagnosis needs an observed evidence citation")
    return diagnosis
