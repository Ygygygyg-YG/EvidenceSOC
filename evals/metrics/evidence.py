"""Reference integrity and explicitly human-reviewed semantic metrics."""
import re

from .classification import diagnosis, ratio


def _registry(row):
    value = row.get("evidence_registry", (row.get("result") or {}).get("evidence_registry", {}))
    if isinstance(value, list):
        return {item.get("evidence_id", item.get("id")): item for item in value if isinstance(item, dict)}
    return value if isinstance(value, dict) else {}


def ordered_citations(output):
    """Canonical order first, then original sealed report assertions in order."""
    nested = output.get("diagnosis")
    references = ordered_citations(nested) if isinstance(nested, dict) else []
    references.extend(output.get("evidence_ids", []))
    origin = output.get("origin")
    if isinstance(origin, dict):
        references.extend(origin.get("evidence_ids", []))
    if "diagnosis" in output:
        references.extend((output.get("classification") or {}).get("evidence_ids", []))
    for item in [*(output.get("stage_instances") or []),
                 *((output.get("attack_steps") or []) if "diagnosis" in output else []),
                 *(output.get("claims") or [])]:
        references.extend(item.get("evidence_ids", []))
    return references


def score_evidence(rows):
    total = valid = report_n = empty_n = reviewed_n = reviewed_slots = 0
    p_lower = p_upper = claims = unsupported = uncertain = ucr_reports = 0
    actual_unique = []
    for row in rows:
        if diagnosis(row) is None:
            continue
        output = ((row.get("result") or {}).get("diagnostic_snapshot")
                  or row.get("diagnosis") or {})
        report_n += 1
        citations = ordered_citations(output)
        registry = _registry(row)
        hash_maps = [output.get("evidence_hashes", {})]
        if isinstance(output.get("diagnosis"), dict):
            hash_maps.append(output["diagnosis"].get("evidence_hashes", {}))
        if any(not isinstance(value, dict) for value in hash_maps):
            raise TypeError("Explicit evidence hashes must be an ID-to-digest mapping")
        validity = {}
        for evidence_id in citations:
            entry = registry.get(evidence_id)
            digest = entry.get("content_sha256", entry.get("sha256")) if isinstance(entry, dict) else None
            validity[evidence_id] = (isinstance(entry, dict) and entry.get("case_id") == row.get("case_id")
                and entry.get("evidence_id", evidence_id) == evidence_id
                and isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest) is not None
                and all(evidence_id not in cited_hashes or cited_hashes[evidence_id] == digest
                        for cited_hashes in hash_maps))
            total += 1
            valid += bool(validity[evidence_id])
        unique = list(dict.fromkeys(citations))
        actual_unique.append(len(unique))
        empty_n += not citations
        review = row.get("human_review") or {}
        if review.get("reviewed") is not True:
            continue
        relevance = review.get("relevance")
        # Review is optional; never infer relevance from an attack label or existence.
        if isinstance(relevance, dict):
            reviewed_n += 1
            reviewed_slots += 5
            for evidence_id in unique[:5]:
                judgment = relevance.get(evidence_id, "uncertain")
                if validity.get(evidence_id) and judgment in {"supported", "relevant"}:
                    p_lower += 1
                    p_upper += 1
                elif validity.get(evidence_id) and judgment in {"uncertain", "undetermined"}:
                    p_upper += 1
        claim_rows = review.get("claims")
        if isinstance(claim_rows, list):
            ucr_reports += 1
            for claim in claim_rows:
                judgment = claim.get("judgment")
                if judgment not in {"supported", "unsupported", "uncertain", "undetermined"}:
                    raise ValueError("Human claim review requires explicit judgment")
                claims += 1
                unsupported += judgment == "unsupported"
                uncertain += judgment in {"uncertain", "undetermined"}
    return {"citation_validity": ratio(valid, total), "valid_citation_count": valid, "citation_count": total,
            "report_count": report_n, "zero_citation_report_count": empty_n,
            "zero_citation_report_rate": ratio(empty_n, report_n), "actual_unique_reference_counts": actual_unique,
            "p_at_5_lower": ratio(p_lower, reviewed_slots), "p_at_5_upper": ratio(p_upper, reviewed_slots),
            "semantic_reviewed_reports": reviewed_n, "semantic_denominator_slots": reviewed_slots,
            "ucr_lower": ratio(unsupported, claims), "ucr_upper": ratio(unsupported + uncertain, claims),
            "reviewed_claim_count": claims, "unsupported_claim_count": unsupported,
            "undetermined_claim_count": uncertain, "ucr_reviewed_reports": ucr_reports,
            "human_review_coverage": ratio(reviewed_n, len(rows)),
            "semantic_scope": "preregistered human-reviewed sample only",
            "missing_reason": "No completed applicable human review" if not reviewed_n else None}
