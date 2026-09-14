"""Tests for the CweForest API, using CWE-27 (Path Traversal) as the fixture node.

CWE-27 is a good test case because it's a leaf node (no children) with a single
parent, sitting several layers deep in the CWE-664 root tree:
CWE-664 -> CWE-706 -> CWE-22 -> CWE-23 -> CWE-27
"""

from cwe_tree import query


def test_get_cwe_by_full_id():
    node = query.get_cwe("CWE-27")
    assert node is not None
    assert node.cwe_id == "CWE-27"


def test_get_cwe_by_bare_number():
    node = query.get_cwe("27")
    assert node is not None
    assert node.cwe_id == "CWE-27"


def test_get_cwe_unknown_returns_none():
    assert query.get_cwe("CWE-9999999") is None


def test_node_metadata_fields():
    node = query.get_cwe("CWE-27")
    assert node.name == "Path Traversal: 'dir/../../filename'"
    assert node.abstract == "Variant"
    assert node.layer == {"CWE-664": 4}
    assert "restricted directory" in node.description
    assert node.extended_description != ""


def test_get_parents():
    parents = {p.cwe_id for p in query.get_parents("CWE-27")}
    assert parents == {"CWE-23"}


def test_get_children_is_empty():
    assert query.get_children("CWE-27") == set()


def test_ancestors_chain():
    node = query.get_cwe("CWE-27")
    ancestor_ids = {a.cwe_id for a in query.ancestors(node)}
    assert ancestor_ids == {"CWE-23", "CWE-22", "CWE-706", "CWE-664"}


def test_descendants_is_empty():
    node = query.get_cwe("CWE-27")
    assert list(query.descendants(node)) == []


def test_is_ancestor():
    assert query.is_ancestor("CWE-664", "CWE-27") is True
    assert query.is_ancestor("CWE-23", "CWE-27") is True
    assert query.is_ancestor("CWE-79", "CWE-27") is False


def test_is_descendant():
    assert query.is_descendant("CWE-27", "CWE-664") is True
    assert query.is_descendant("CWE-27", "CWE-23") is True
    assert query.is_descendant("CWE-27", "CWE-79") is False


def test_get_metadata():
    metadata = query.get_metadata("CWE-27")
    assert metadata is not None
    assert metadata["id"] == "CWE-27"
    assert metadata["parents"] == ["CWE-23"]
    assert metadata["children"] == []


def test_status():
    assert query.get_cwe("CWE-27").status == "Draft"


def test_weakness_ordinalities():
    ordinalities = {o["ordinality"] for o in query.get_cwe("CWE-27").weakness_ordinalities}
    assert ordinalities == {"Primary", "Resultant"}


def test_applicable_platforms():
    platforms = query.get_cwe("CWE-27").applicable_platforms
    assert {"language_class": "Not Language-Specific", "language_prevalence": "Undetermined"} in platforms


def test_modes_of_introduction():
    phases = {m["phase"] for m in query.get_cwe("CWE-27").modes_of_introduction}
    assert "Implementation" in phases


def test_common_consequences():
    consequences = query.get_cwe("CWE-27").common_consequences
    assert any("Confidentiality" in c.get("scope", []) for c in consequences)
    assert any("Integrity" in c.get("scope", []) for c in consequences)


def test_functional_areas_and_affected_resources():
    node = query.get_cwe("CWE-27")
    assert node.functional_areas == ["File Processing"]
    assert node.affected_resources == ["File or Directory"]


def test_taxonomy_mappings():
    taxonomies = {m["taxonomy_name"] for m in query.get_cwe("CWE-27").taxonomy_mappings}
    assert "Software Fault Patterns" in taxonomies


def test_detection_methods_and_mitigations_are_populated():
    node = query.get_cwe("CWE-27")
    assert len(node.detection_methods) > 0
    assert all("method" in m for m in node.detection_methods)
    assert len(node.potential_mitigations) > 0
    assert all("phase" in m for m in node.potential_mitigations)


def test_observed_examples_reference_a_cve():
    examples = query.get_cwe("CWE-27").observed_examples
    assert len(examples) > 0
    assert any(e.get("reference", "").startswith("CVE-") for e in examples)


def test_related_weaknesses_includes_childof_view_1000():
    related = query.get_cwe("CWE-27").related_weaknesses
    assert {
        "nature": "ChildOf",
        "cwe_id": "CWE-23",
        "view_id": "1000",
        "ordinal": "Primary",
    } in related


def test_alternate_terms_and_notes_default_to_empty_list():
    node = query.get_cwe("CWE-27")
    assert node.alternate_terms == []
    assert node.notes == []
    assert node.related_attack_patterns == []


def test_background_details_defaults_to_empty_string():
    assert query.get_cwe("CWE-27").background_details == ""


def test_get_metadata_unknown_returns_none():
    assert query.get_metadata("CWE-9999999") is None


def test_root_of_cwe_27_tree_is_a_root_node():
    root_ids = {r.cwe_id for r in query.get_root_nodes()}
    assert "CWE-664" in root_ids
