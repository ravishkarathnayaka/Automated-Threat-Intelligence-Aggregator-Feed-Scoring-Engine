"""Graph centrality and random-walk PageRank indicator influence model."""

from typing import Dict, List, Set, Tuple


class PageRankThreatGraph:
    """Computes PageRank centrality to identify high-influence hub infrastructure in threat graphs."""

    @classmethod
    def compute_pagerank(
        cls,
        edges: List[Tuple[str, str]],
        damping: float = 0.85,
        max_iterations: int = 50,
        tolerance: float = 1e-5,
    ) -> Dict[str, float]:
        """Calculates PageRank score for each indicator node in the bipartite/multipartite graph.

        Args:
            edges: List of directed/undirected (source_node, target_node) edges (e.g. ('domain.com', '198.51.100.1')).
            damping: Damping factor (standard 0.85).
            max_iterations: Maximum power iterations.
            tolerance: Convergence delta threshold.

        Returns:
            Dict[str, float]: Node -> Normalized PageRank centrality score [0.0, 1.0].
        """
        # Collect all unique nodes and build adjacency
        nodes: Set[str] = set()
        outgoing: Dict[str, List[str]] = {}
        incoming: Dict[str, List[str]] = {}

        for u, v in edges:
            nodes.add(u)
            nodes.add(v)
            outgoing.setdefault(u, []).append(v)
            incoming.setdefault(v, []).append(u)
            # Bidirectional threat relationship
            outgoing.setdefault(v, []).append(u)
            incoming.setdefault(u, []).append(v)

        n = len(nodes)
        if n == 0:
            return {}

        initial_val = 1.0 / n
        ranks = {node: initial_val for node in nodes}

        base_val = (1.0 - damping) / n
        for _ in range(max_iterations):
            new_ranks: Dict[str, float] = {}
            max_diff = 0.0

            for node in nodes:
                rank_sum = 0.0
                for neighbor in incoming.get(node, []):
                    out_degree = len(outgoing.get(neighbor, []))
                    if out_degree > 0:
                        rank_sum += ranks[neighbor] / out_degree
                new_rank = base_val + damping * rank_sum
                max_diff = max(max_diff, abs(new_rank - ranks[node]))
                new_ranks[node] = new_rank

            ranks = new_ranks
            if max_diff < tolerance:
                break

        # Normalize so maximum score is scaled cleanly
        max_r = max(ranks.values()) if ranks else 1.0
        return {node: round(score / max_r, 4) for node, score in ranks.items()}
