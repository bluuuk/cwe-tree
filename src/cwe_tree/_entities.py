"""CweNode and CweEdge representations."""

import json
from typing import Any, Dict, List

from cpg2py import AbcEdgeQuerier, AbcNodeQuerier, Storage


class CweEdge(AbcEdgeQuerier):
    """Represents a relationship between two CWE nodes."""


class CweNode(AbcNodeQuerier):
    """Represents a single CWE (Common Weakness Enumeration) node.

    Attributes:
        storage: Reference to the underlying graph storage.

    A CWE node encapsulates all fields from the official CWE View-1000 export:
    identity, textual descriptions, applicability, consequences, mitigations,
    real-world examples, taxonomy mappings, and its layer/relationship data.
    """

    def __init__(self, storage: Storage, nid: str) -> None:
        """Initialize a CWE node.

        Args:
            storage: The graph storage backend.
            nid: The node identifier.
        """
        super().__init__(storage, nid)
        self.storage = storage

    def _get_str(self, name: str) -> str:
        value = self.get_property(name)
        return str(value) if value is not None else ""

    def _get_json(self, name: str, default: Any) -> Any:
        raw = self.get_property(name)
        if not raw:
            return default
        try:
            return json.loads(str(raw))
        except json.JSONDecodeError:
            return default

    @property
    def cwe_id(self) -> str:
        """Retrieves the unique CWE identifier.

        Returns:
            The CWE ID (e.g., "CWE-732").
        """
        return str(self.node_id)

    @property
    def name(self) -> str:
        """Retrieves the name/description of the weakness.

        Returns:
            The descriptive name of the CWE, or empty string if not available.
        """
        return self._get_str("name")

    @property
    def abstract(self) -> str:
        """Retrieves the abstraction type of the weakness.

        Returns:
            The abstraction type (e.g., "Class", "Base", "Variant"),
            or empty string if not available.
        """
        return self._get_str("abstract")

    @property
    def status(self) -> str:
        """Retrieves the CWE content status (e.g., "Draft", "Incomplete", "Stable")."""
        return self._get_str("status")

    @property
    def description(self) -> str:
        """Retrieves the description of the weakness.

        Returns:
            The weakness description, or empty string if not available.
        """
        return self._get_str("description")

    @property
    def extended_description(self) -> str:
        """Retrieves the extended description of the weakness.

        Returns:
            The extended weakness description, or empty string if not available.
        """
        return self._get_str("extended_description")

    @property
    def background_details(self) -> str:
        """Retrieves background details providing extra context for the weakness."""
        return self._get_str("background_details")

    @property
    def alternate_terms(self) -> List[Dict[str, Any]]:
        """Retrieves alternate terms used to refer to this weakness.

        Returns:
            List of dicts with keys like "term" and "description".
        """
        return self._get_json("alternate_terms", [])

    @property
    def weakness_ordinalities(self) -> List[Dict[str, Any]]:
        """Retrieves whether this weakness is primary, resultant, or indirect.

        Returns:
            List of dicts with keys like "ordinality" and "description".
        """
        return self._get_json("weakness_ordinalities", [])

    @property
    def applicable_platforms(self) -> List[Dict[str, Any]]:
        """Retrieves languages, technologies, and platforms this weakness applies to.

        Returns:
            List of dicts describing a language/technology/operating
            system/architecture and its prevalence.
        """
        return self._get_json("applicable_platforms", [])

    @property
    def modes_of_introduction(self) -> List[Dict[str, Any]]:
        """Retrieves the development phases in which this weakness may be introduced.

        Returns:
            List of dicts with keys like "phase" and "note".
        """
        return self._get_json("modes_of_introduction", [])

    @property
    def common_consequences(self) -> List[Dict[str, Any]]:
        """Retrieves the consequences of this weakness being exploited.

        Returns:
            List of dicts with keys like "scope", "impact", "likelihood", and "note".
        """
        return self._get_json("common_consequences", [])

    @property
    def detection_methods(self) -> List[Dict[str, Any]]:
        """Retrieves methods that can be used to detect this weakness.

        Returns:
            List of dicts with keys like "method", "description", and "effectiveness".
        """
        return self._get_json("detection_methods", [])

    @property
    def potential_mitigations(self) -> List[Dict[str, Any]]:
        """Retrieves potential mitigations for this weakness.

        Returns:
            List of dicts with keys like "phase", "strategy", "description",
            and "effectiveness".
        """
        return self._get_json("potential_mitigations", [])

    @property
    def observed_examples(self) -> List[Dict[str, Any]]:
        """Retrieves real-world examples (e.g., CVEs) of this weakness.

        Returns:
            List of dicts with keys "reference", "description", and "link".
        """
        return self._get_json("observed_examples", [])

    @property
    def functional_areas(self) -> List[str]:
        """Retrieves functional areas associated with this weakness."""
        return self._get_json("functional_areas", [])

    @property
    def affected_resources(self) -> List[str]:
        """Retrieves the types of resources affected by this weakness."""
        return self._get_json("affected_resources", [])

    @property
    def taxonomy_mappings(self) -> List[Dict[str, Any]]:
        """Retrieves mappings to external taxonomies (e.g., OWASP, 7 Pernicious Kingdoms).

        Returns:
            List of dicts with keys like "taxonomy_name", "entry_id",
            "entry_name", and "mapping_fit".
        """
        return self._get_json("taxonomy_mappings", [])

    @property
    def related_attack_patterns(self) -> List[str]:
        """Retrieves related CAPEC attack pattern IDs (e.g., "CAPEC-21")."""
        return self._get_json("related_attack_patterns", [])

    @property
    def notes(self) -> List[Dict[str, Any]]:
        """Retrieves miscellaneous notes about this weakness.

        Returns:
            List of dicts with keys "type" and "note".
        """
        return self._get_json("notes", [])

    @property
    def related_weaknesses(self) -> List[Dict[str, Any]]:
        """Retrieves all raw CWE relationships from the source data.

        Unlike `parents`/`children` (which reflect only ChildOf edges in View
        1000), this includes every relationship nature (e.g. PeerOf,
        CanPrecede, CanAlsoBe, Requires) across all CWE views.

        Returns:
            List of dicts with keys like "nature", "cwe_id", "view_id",
            "ordinal", and "chain_id".
        """
        return self._get_json("related_weaknesses", [])

    @property
    def layer(self) -> Dict[str, int]:
        """Retrieves the layer mapping for this node.

        The layer mapping indicates the depth of this node within different
        root hierarchies.

        Returns:
            Dictionary mapping root CWE IDs to depth levels.
        """
        return self._get_json("layer", {})

    def get_metadata(self) -> Dict[str, Any]:
        """Retrieves the intrinsic metadata of this CWE node.

        Returns only properties stored directly on the node, without
        traversing relationships.

        Returns:
            Dictionary containing every intrinsic CWE field for this node.
        """
        return {
            "id": self.cwe_id,
            "name": self.name,
            "abstract": self.abstract,
            "status": self.status,
            "description": self.description,
            "extended_description": self.extended_description,
            "background_details": self.background_details,
            "alternate_terms": self.alternate_terms,
            "weakness_ordinalities": self.weakness_ordinalities,
            "applicable_platforms": self.applicable_platforms,
            "modes_of_introduction": self.modes_of_introduction,
            "common_consequences": self.common_consequences,
            "detection_methods": self.detection_methods,
            "potential_mitigations": self.potential_mitigations,
            "observed_examples": self.observed_examples,
            "functional_areas": self.functional_areas,
            "affected_resources": self.affected_resources,
            "taxonomy_mappings": self.taxonomy_mappings,
            "related_attack_patterns": self.related_attack_patterns,
            "notes": self.notes,
            "related_weaknesses": self.related_weaknesses,
            "layer": self.layer,
        }
