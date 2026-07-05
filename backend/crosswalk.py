"""Framework crosswalk engine: static, phrase-verified cross-framework control
mapping and honesty-preserving projection logic.

What this module deliberately does NOT do: it never copies a source control's
numeric score onto a target control, and it never invents a weighted
"projected coverage score" out of made-up status-to-number conversions. A
control's score is only meaningful against the exact required_text phrase
list it was computed from (see scanning.py's analyze_control()) -- reusing
that number, or synthesizing a new one from it, for a different framework's
control would imply a precision this system cannot honestly claim. Instead
this module projects only a categorical status (Compliant / Partially
Compliant / Non-Compliant), always labeled as a projection with the source
control cited alongside it, and reports plain counts (mapped/unmapped,
status breakdown) rather than a synthetic aggregate score.

CROSSWALK_CLUSTERS is hand-curated and phrase-verified directly against
scanning.py's FRAMEWORKS required_text lists -- every cluster below shares at
least two meaningful required_text phrases (or an unambiguous single concept
like "DPO designation") across its member controls. Many plausible-looking
cross-framework relationships (children's-data, data-localization, firewall/
tokenization, segregation-of-duties, security-awareness-training,
data-retention, backup/DR) were checked and excluded because the phrase
overlap was weak or absent -- do not add a cluster here without verifying the
same way.
"""

from scanning import FRAMEWORKS

CROSSWALK_CLUSTERS = {
    "encryption_data_security": {
        "label": "Encryption / Data Security",
        "members": [
            ("dpdpa", "DPDPA-9"), ("gdpr", "Art-32"), ("pcidss", "Req-3"),
            ("hipaa", "164.312(e)"), ("nistcsf", "PR.DS-01"),
        ],
    },
    "access_control_identity": {
        "label": "Access Control / Identity & Authorization",
        "members": [
            ("dpdpa", "DPDPA-9"), ("iso27001", "A.9.1"), ("pcidss", "Req-8"),
            ("hipaa", "164.312(a)"), ("nistcsf", "PR.AA-01"),
        ],
    },
    "incident_breach_notification": {
        "label": "Incident Response & Breach Notification",
        "members": [
            ("dpdpa", "DPDPA-10"), ("gdpr", "Art-33"), ("hipaa", "164.308(a)(6)"),
            ("iso27001", "A.16.1"), ("nistcsf", "RS.MA-01"),
        ],
    },
    "data_subject_rights": {
        "label": "Data Subject / Principal Rights",
        "members": [
            ("dpdpa", "DPDPA-6"), ("gdpr", "Art-15"), ("gdpr", "Art-17"),
        ],
    },
    "monitoring_logging": {
        "label": "Monitoring & Logging",
        "members": [
            ("pcidss", "Req-10"), ("hipaa", "164.312(b)"), ("nistcsf", "DE.CM-01"),
        ],
    },
    "vulnerability_patch_management": {
        "label": "Vulnerability & Patch Management",
        "members": [
            ("pcidss", "Req-6"), ("pcidss", "Req-11"), ("nistcsf", "PR.PS-01"),
        ],
    },
    "dpo_designation": {
        "label": "Data Protection Officer Designation",
        "members": [
            ("dpdpa", "DPDPA-8"), ("gdpr", "Art-37"),
        ],
    },
}


def _validate_clusters():
    """Fail loudly at import time if a cluster references a control ID that
    doesn't actually exist in FRAMEWORKS -- catches a typo immediately rather
    than silently producing an empty/wrong projection at request time."""
    for cluster_key, cluster in CROSSWALK_CLUSTERS.items():
        for framework, control_id in cluster["members"]:
            if framework not in FRAMEWORKS:
                raise AssertionError(f"crosswalk.py: unknown framework {framework!r} in cluster {cluster_key!r}")
            ids = {c["id"] for c in FRAMEWORKS[framework]["controls"]}
            if control_id not in ids:
                raise AssertionError(
                    f"crosswalk.py: {framework}.{control_id} in cluster {cluster_key!r} "
                    f"does not exist in FRAMEWORKS[{framework!r}]['controls']"
                )


def _build_lookup():
    """(framework, control_id) -> set of cluster_keys it belongs to. Built
    once at import time; the directed source->target lookup used by
    get_mapped_targets() is derived from this rather than hand-authored, so
    a forward mapping and a reverse mapping can never silently drift apart."""
    control_to_clusters = {}
    for cluster_key, cluster in CROSSWALK_CLUSTERS.items():
        for member in cluster["members"]:
            control_to_clusters.setdefault(member, set()).add(cluster_key)
    return control_to_clusters


_validate_clusters()
_CONTROL_TO_CLUSTERS = _build_lookup()


def get_mapped_targets(source_framework, source_control_id, target_framework):
    """Every control in target_framework that shares a cluster with
    (source_framework, source_control_id). Returns a list of
    (control_id, cluster_key) tuples -- a source control can legitimately
    map to more than one target control (e.g. DPDPA-6 -> [Art-15, Art-17],
    since DPDPA bundles what GDPR splits into two articles)."""
    key = (source_framework, source_control_id)
    clusters = _CONTROL_TO_CLUSTERS.get(key, set())
    out = []
    for cluster_key in clusters:
        for framework, control_id in CROSSWALK_CLUSTERS[cluster_key]["members"]:
            if framework == target_framework:
                out.append((control_id, cluster_key))
    return out


def build_crosswalk(source_framework, source_controls, target_framework):
    """source_controls: list of result dicts as returned by
    analyze_control()/reconstruct_control_dict() for the already-scanned
    source assessment (must include id, name, status, score).

    Returns the projection payload for one target framework: which of its
    controls are reachable via a verified cluster, their projected
    (categorical, never numeric) status with full source citation, which
    controls are NOT reachable (and therefore need a direct scan), and a
    plain status-count breakdown -- no synthetic aggregate score."""
    target_defs = FRAMEWORKS[target_framework]["controls"]

    covered = {}  # target_control_id -> projection dict
    for src in source_controls:
        for target_control_id, cluster_key in get_mapped_targets(
            source_framework, src["id"], target_framework
        ):
            candidate = {
                "target_control_id": target_control_id,
                "projected_status": src["status"],
                "cluster": CROSSWALK_CLUSTERS[cluster_key]["label"],
                "source_control_id": src["id"],
                "source_control_name": src["name"],
                "source_score": src["score"],
                "source_status": src["status"],
            }
            existing = covered.get(target_control_id)
            if existing is None:
                covered[target_control_id] = {**candidate, "other_sources": []}
            elif src["score"] > existing["source_score"]:
                # Only possible if a future cluster addition creates a target
                # control reachable from more than one source control (no
                # such case exists in the 7 clusters above today). Keep the
                # higher-scoring projection as primary, don't discard the rest.
                covered[target_control_id] = {
                    **candidate,
                    "other_sources": existing["other_sources"] + [{
                        "source_control_id": existing["source_control_id"],
                        "source_score": existing["source_score"],
                        "source_status": existing["source_status"],
                    }],
                }
            else:
                existing["other_sources"].append({
                    "source_control_id": src["id"],
                    "source_score": src["score"],
                    "source_status": src["status"],
                })

    mapped_controls = []
    unmapped_controls = []
    status_breakdown = {"compliant": 0, "partially_compliant": 0, "non_compliant": 0}
    status_key = {
        "Compliant": "compliant",
        "Partially Compliant": "partially_compliant",
        "Non-Compliant": "non_compliant",
    }

    for tdef in target_defs:
        if tdef["id"] in covered:
            proj = covered[tdef["id"]]
            proj["target_control_name"] = tdef["name"]
            mapped_controls.append(proj)
            status_breakdown[status_key.get(proj["projected_status"], "non_compliant")] += 1
        else:
            unmapped_controls.append({
                "target_control_id": tdef["id"],
                "target_control_name": tdef["name"],
                "reason": "not covered by this projection - requires a direct scan against this framework",
            })

    return {
        "target_framework": target_framework,
        "target_framework_name": FRAMEWORKS[target_framework]["name"],
        "mapped_count": len(mapped_controls),
        "total_target_controls": len(target_defs),
        "status_breakdown": status_breakdown,
        "mapped_controls": mapped_controls,
        "unmapped_controls": unmapped_controls,
    }
