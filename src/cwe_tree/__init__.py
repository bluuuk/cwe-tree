"""CWE Tree module for querying CWE forests."""

import csv
import json
import os

from ._entities import CweNode
from ._forest import CweForest
from ._parser import compute_layers, find_parent, parse_node

__all__ = ["query", "CweForest", "CweNode"]

SOURCE_FILE = "1000.csv"


def _get_data_path(filename: str) -> str:
    """Return absolute path to a data file.

    Args:
        filename: The data file name (e.g., '1000.csv').

    Returns:
        Absolute path to the data file in the package directory.
    """
    base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, "data", filename)


def _load_data() -> CweForest:
    """Parse the CWE View-1000 CSV export into a new CweForest instance.

    Reads the raw CWE export from the package data directory, parses each
    weakness into a node, derives parent-child relationships (ChildOf edges
    within view 1000), and computes each node's depth within its root tree.

    Returns:
        Populated CweForest instance with all CWE data.

    Raises:
        FileNotFoundError: If the source CSV cannot be found.
    """
    source_path = _get_data_path(SOURCE_FILE)
    if not os.path.exists(source_path):
        raise FileNotFoundError(f"CWE data file not found: {source_path}")

    with open(source_path, encoding="utf-8") as f:
        nodes = [parse_node(row) for row in csv.DictReader(f)]

    parent_of = {
        node["id"]: parent
        for node in nodes
        if (parent := find_parent(node["related_weaknesses"]))
    }
    layers = compute_layers([node["id"] for node in nodes], parent_of)

    forest = CweForest()
    for node in nodes:
        node["layer"] = layers.get(node["id"], {})
        props = {
            key: value if isinstance(value, str) else json.dumps(value)
            for key, value in node.items()
            if key != "id"
        }
        forest._add_node(node["id"], props)

    for child, parent in parent_of.items():
        forest._add_edge(parent, child)

    return forest


query: CweForest = _load_data()
