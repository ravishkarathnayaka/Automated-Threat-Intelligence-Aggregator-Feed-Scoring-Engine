"""Kleinberg HITS threat hub and authority centrality scoring model."""

import math
from typing import Dict, List, Set, Tuple


class HITSAuthorityScorer:
    """Computes Hub and Authority centrality scores for threat infrastructure graph nodes.

    - Authority nodes: Infrastructure nodes (e.g., C2 servers, malware staging) heavily targeted/used.
    - Hub nodes: Infrastructure pivots (e.g., rogue ASNs, bulletproof DNS resolvers) pointing to authorities.
    """

    def __init__(self, max_iterations: int = 50, tolerance: float = 1e-5):
        self.max_iterations = max_iterations
        self.tolerance = tolerance

    def compute_hits(
        self, graph: Dict[str, List[str]]
    ) -> Tuple[Dict[str, float], Dict[str, float]]:
        """Computes Kleinberg HITS scores given an adjacency list graph: {src: [dst, ...]}.

        Returns:
            Tuple[Dict[str, float], Dict[str, float]]: (hub_scores, authority_scores)
        """
        all_nodes: Set[str] = set(graph.keys())
        for targets in graph.values():
            all_nodes.update(targets)

        if not all_nodes:
            return {}, {}

        # Initialize uniform weights
        hubs: Dict[str, float] = {node: 1.0 for node in all_nodes}
        authorities: Dict[str, float] = {node: 1.0 for node in all_nodes}

        for _ in range(self.max_iterations):
            # 1. Update authority scores: a(v) = sum_{u -> v} h(u)
            new_authorities: Dict[str, float] = {node: 0.0 for node in all_nodes}
            for u, targets in graph.items():
                h_u = hubs[u]
                for v in targets:
                    new_authorities[v] += h_u

            # Normalize authorities (L2 norm)
            norm_a = math.sqrt(sum(val**2 for val in new_authorities.values()))
            if norm_a > 0:
                for v in new_authorities:
                    new_authorities[v] /= norm_a

            # 2. Update hub scores: h(u) = sum_{u -> v} a(v)
            new_hubs: Dict[str, float] = {node: 0.0 for node in all_nodes}
            for u, targets in graph.items():
                for v in targets:
                    new_hubs[u] += new_authorities[v]

            # Normalize hubs (L2 norm)
            norm_h = math.sqrt(sum(val**2 for val in new_hubs.values()))
            if norm_h > 0:
                for u in new_hubs:
                    new_hubs[u] /= norm_h

            # Check convergence
            diff_h = sum(abs(new_hubs[k] - hubs[k]) for k in all_nodes)
            diff_a = sum(abs(new_authorities[k] - authorities[k]) for k in all_nodes)
            hubs, authorities = new_hubs, new_authorities

            if diff_h + diff_a < self.tolerance:
                break

        return (
            {k: round(v, 4) for k, v in hubs.items()},
            {k: round(v, 4) for k, v in authorities.items()},
        )

    @classmethod
    def evaluate(
        cls, graph: Dict[str, List[str]], top_n: int = 5
    ) -> Dict[str, object]:
        """Convenience method returning sorted top hubs and authorities."""
        scorer = cls()
        hubs, authorities = scorer.compute_hits(graph)
        sorted_hubs = sorted(hubs.items(), key=lambda x: x[1], reverse=True)[:top_n]
        sorted_auths = sorted(authorities.items(), key=lambda x: x[1], reverse=True)[:top_n]
        return {
            "hubs": dict(sorted_hubs),
            "authorities": dict(sorted_auths),
            "all_hubs": hubs,
            "all_authorities": authorities,
        }
