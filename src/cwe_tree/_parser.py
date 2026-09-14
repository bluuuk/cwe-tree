"""Parse the official CWE View-1000 CSV export into node records and edges.

The CWE CSV export packs structured sub-fields into a `::KEY:value:KEY:value::`
mini-format (e.g. Potential Mitigations, Common Consequences). `parse_entries`
parses that generically into a list of dicts; `parse_values` handles columns
that are just a flat `::value::value::` list with no keys.
"""

import re
from collections import defaultdict
from typing import Any, Dict, List, Optional

# Every key used across the CWE CSV's `::KEY:value::` sub-fields, longest first
# so multi-word keys aren't shadowed by a shorter key that happens to prefix them.
_KEYS = sorted(
    [
        "TAXONOMY NAME", "LANGUAGE PREVALENCE", "TECHNOLOGY PREVALENCE",
        "OPERATING SYSTEM PREVALENCE", "OPERATING SYSTEM CLASS", "ARCHITECTURE PREVALENCE",
        "ARCHITECTURE CLASS", "ARCHITECTURE NAME", "OPERATING SYSTEM NAME",
        "LANGUAGE CLASS", "LANGUAGE NAME", "TECHNOLOGY CLASS", "TECHNOLOGY NAME",
        "MAPPING FIT", "ENTRY NAME", "ENTRY ID", "CHAIN ID", "CWE ID", "VIEW ID",
        "DESCRIPTION", "REFERENCE", "LINK", "PHASE", "IMPACT", "SCOPE", "NOTE",
        "NATURE", "ORDINAL", "ORDINALITY", "EFFECTIVENESS", "METHOD", "STRATEGY",
        "TYPE", "TERM", "LIKELIHOOD",
    ],
    key=len,
    reverse=True,
)
_KEY_RE = re.compile(r":(" + "|".join(re.escape(k) for k in _KEYS) + r"):")


def normalize(cwe_id: str) -> str:
    """Return a CWE id in canonical `CWE-<n>` form."""
    return cwe_id if cwe_id.startswith("CWE-") else f"CWE-{cwe_id}"


def unwrap(text: str) -> str:
    """Strip the leading/trailing `::` wrapper from a free-text field."""
    return (text or "").strip().removeprefix("::").removesuffix("::")


def parse_entries(text: str) -> List[Dict[str, Any]]:
    """Parse a `::KEY:val:KEY:val::KEY:val::` field into a list of dicts.

    Repeated keys within one entry collapse into a list of values.
    """
    entries: List[Dict[str, Any]] = []
    for chunk in (c for c in (text or "").split("::") if c.strip()):
        wrapped = ":" + chunk + ":"
        matches = list(_KEY_RE.finditer(wrapped))
        if not matches:
            continue
        entry: Dict[str, Any] = {}
        for i, match in enumerate(matches):
            key = match.group(1).lower().replace(" ", "_")
            value_end = matches[i + 1].start() if i + 1 < len(matches) else len(wrapped) - 1
            value = wrapped[match.end():value_end]
            if key in entry:
                existing = entry[key]
                entry[key] = existing + [value] if isinstance(existing, list) else [existing, value]
            else:
                entry[key] = value
        entries.append(entry)
    return entries


def parse_values(text: str) -> List[str]:
    """Parse a flat `::value::value::` field (no keys) into a list of strings."""
    return [c.strip() for c in (text or "").split("::") if c.strip()]


def parse_node(row: Dict[str, str]) -> Dict[str, Any]:
    """Parse one raw CWE CSV row into a node record with native Python values.

    The `layer` field is filled in separately by `compute_layers` once the full
    graph is known.
    """
    related = parse_entries(row["Related Weaknesses"])
    for rel in related:
        if "cwe_id" in rel:
            rel["cwe_id"] = normalize(rel["cwe_id"])

    return {
        "id": normalize(row["CWE-ID"]),
        "name": row["Name"],
        "abstract": row["Weakness Abstraction"],
        "status": row["Status"],
        "description": row["Description"],
        "extended_description": row["Extended Description"],
        "background_details": unwrap(row["Background Details"]),
        "alternate_terms": parse_entries(row["Alternate Terms"]),
        "weakness_ordinalities": parse_entries(row["Weakness Ordinalities"]),
        "applicable_platforms": parse_entries(row["Applicable Platforms"]),
        "modes_of_introduction": parse_entries(row["Modes Of Introduction"]),
        "common_consequences": parse_entries(row["Common Consequences"]),
        "detection_methods": parse_entries(row["Detection Methods"]),
        "potential_mitigations": parse_entries(row["Potential Mitigations"]),
        "observed_examples": parse_entries(row["Observed Examples"]),
        "functional_areas": parse_values(row["Functional Areas"]),
        "affected_resources": parse_values(row["Affected Resources"]),
        "taxonomy_mappings": parse_entries(row["Taxonomy Mappings"]),
        "related_attack_patterns": [f"CAPEC-{v}" for v in parse_values(row["Related Attack Patterns"])],
        "notes": parse_entries(row["Notes"]),
        "related_weaknesses": related,
    }


def find_parent(related_weaknesses: List[Dict[str, Any]]) -> Optional[str]:
    """Return the node's ChildOf parent within CWE view 1000, if any.

    View 1000 is a strict tree, so there is at most one such parent.
    """
    for rel in related_weaknesses:
        if rel.get("nature") == "ChildOf" and rel.get("view_id") == "1000":
            return rel["cwe_id"]
    return None


def compute_layers(node_ids: List[str], parent_of: Dict[str, str]) -> Dict[str, Dict[str, int]]:
    """Map each node to `{root_id: depth}`, its depth within its root tree."""
    children: Dict[str, List[str]] = defaultdict(list)
    for child, parent in parent_of.items():
        children[parent].append(child)

    layers: Dict[str, Dict[str, int]] = {}
    roots = [nid for nid in node_ids if nid not in parent_of]
    for root in roots:
        stack = [(root, 0)]
        while stack:
            nid, depth = stack.pop()
            layers[nid] = {root: depth}
            for child in children[nid]:
                stack.append((child, depth + 1))
    return layers
