"""Web of trust (PGP-style decentralized model): nodes are people, edges are
"X vouches for / signed the key of Y". No central authority -- trust is
evaluated by finding a path through the graph, unlike hierarchical PKI
(app.algorithms.pki.certificates) where everything traces back to one root.
"""
from __future__ import annotations

from collections import deque

from app.core.step_trace import AlgorithmRunResult, step

FAMILY = "pki"
ALGORITHM = "web_of_trust"


def _parse_edges(raw: str) -> list[tuple[str, str]]:
    edges = []
    for part in raw.split(","):
        part = part.strip()
        if "->" in part:
            a, b = part.split("->", 1)
            a, b = a.strip(), b.strip()
            if a and b:
                edges.append((a, b))
    return edges


def evaluate_trust(raw_edges: str, verifier: str, target: str) -> AlgorithmRunResult:
    verifier, target = verifier.strip(), target.strip()
    edges = _parse_edges(raw_edges)

    if not edges:
        msg = "No se pudo interpretar ninguna relación de confianza. Usa el formato 'A->B, B->C'."
        return AlgorithmRunResult(
            ok=False, family=FAMILY, algorithm=ALGORITHM, operation="trust_path",
            input_summary={"text": raw_edges, "verifier": verifier, "target": target},
            output=None, output_label="Resultado",
            steps=[step(1, "Interpretar las relaciones de confianza", msg, ok=False)], error=msg,
        )

    graph: dict[str, list[str]] = {}
    for a, b in edges:
        graph.setdefault(a, []).append(b)

    edges_step = step(
        1,
        "Grafo de confianza",
        f"Se registran {len(edges)} relaciones directas de confianza (cada una es como una llave "
        "firmando la llave de otra persona, al estilo PGP).",
        columns=["Quién confía", "En quién"],
        rows=[[a, b] for a, b in edges],
    )

    visited = {verifier}
    parent: dict[str, str] = {}
    queue = deque([verifier])
    found = verifier == target
    while queue and not found:
        node = queue.popleft()
        for neighbor in graph.get(node, []):
            if neighbor in visited:
                continue
            visited.add(neighbor)
            parent[neighbor] = node
            if neighbor == target:
                found = True
                break
            queue.append(neighbor)

    if found and verifier != target:
        path = [target]
        cur = target
        while cur != verifier:
            cur = parent[cur]
            path.append(cur)
        path.reverse()
    elif verifier == target:
        path = [verifier]
    else:
        path = []

    hop_rows = [[i + 1, path[i], path[i + 1]] for i in range(len(path) - 1)]
    bfs_step = step(
        2,
        f"Buscar un camino de confianza: {verifier} -> {target}",
        "Se recorre el grafo salto por salto (búsqueda en anchura), siguiendo relaciones de confianza "
        "directa a partir del verificador, hasta llegar al objetivo o agotar el grafo.",
        columns=["Salto #", "Desde", "Hasta"] if hop_rows else None,
        rows=hop_rows if hop_rows else None,
        ok=found,
    )

    if found:
        length = len(path) - 1
        if length == 0:
            msg = f"{verifier} y {target} son la misma persona/llave."
        elif length == 1:
            msg = f"{verifier} confía DIRECTAMENTE en {target} (confianza de 1 salto -- la más fuerte)."
        else:
            msg = (
                f"Hay un camino de confianza TRANSITIVA de {length} saltos: {' → '.join(path)}. "
                "Entre más saltos, más débil suele considerarse la confianza (no hay garantía "
                "matemática como en una firma directa -- es una convención social del modelo)."
            )
    else:
        msg = f"No existe ningún camino de confianza desde {verifier} hasta {target} en este grafo."

    result_step = step(3, "Resultado", msg, ok=found)

    return AlgorithmRunResult(
        ok=True,
        family=FAMILY,
        algorithm=ALGORITHM,
        operation="trust_path",
        input_summary={"text": raw_edges, "verifier": verifier, "target": target},
        output=" → ".join(path) if found else "Sin camino de confianza",
        output_label="Camino de confianza",
        steps=[edges_step, bfs_step, result_step],
    )
