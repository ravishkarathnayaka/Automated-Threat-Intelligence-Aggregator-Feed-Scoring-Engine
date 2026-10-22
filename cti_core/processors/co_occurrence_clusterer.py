"""Indicator co-occurrence clusterer for automated threat campaign attribution."""

from collections import defaultdict
from typing import Any, Dict, List, Set


class CoOccurrenceClusterer:
    """Clusters Indicators of Compromise into campaign infrastructure clusters using shared pivot attributes."""

    def __init__(self) -> None:
        self.adjacency: Dict[str, Set[str]] = defaultdict(set)
        self.indicator_meta: Dict[str, Dict[str, Any]] = {}

    def add_link(self, ioc_a: str, ioc_b: str, pivot_attr: str = "shared_infrastructure") -> None:
        """Register a bipartite co-occurrence relationship."""
        clean_a = ioc_a.strip().lower()
        clean_b = ioc_b.strip().lower()
        if clean_a != clean_b:
            self.adjacency[clean_a].add(clean_b)
            self.adjacency[clean_b].add(clean_a)

    def find_clusters(self) -> List[List[str]]:
        """Find connected components of co-occurring infrastructure."""
        visited: Set[str] = set()
        clusters: List[List[str]] = []

        for node in self.adjacency:
            if node not in visited:
                component: List[str] = []
                queue = [node]
                visited.add(node)
                while queue:
                    curr = queue.pop(0)
                    component.append(curr)
                    for neighbor in self.adjacency[curr]:
                        if neighbor not in visited:
                            visited.add(neighbor)
                            queue.append(neighbor)
                clusters.append(sorted(component))

        return clusters

    @classmethod
    def calculate_campaign_density(cls, cluster: List[str]) -> float:
        """Calculates cluster cohesion score [0.0, 1.0]."""
        n = len(cluster)
        if n <= 1:
            return 1.0
        # Larger coordinated campaign clusters carry higher attribution weight
        return round(min(1.0, 0.4 + (n * 0.1)), 2)
