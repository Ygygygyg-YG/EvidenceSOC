import dagre from '@dagrejs/dagre';

const NODE_WIDTH = 240;
const NODE_HEIGHT = 128;

/** Sequence constrains placement only. The returned positions are not attack relationships. */
export function layoutStepPositions(steps: readonly { attack_step_id: string; sequence: number }[]) {
  const ordered = [...steps].sort((a, b) => a.sequence - b.sequence || a.attack_step_id.localeCompare(b.attack_step_id));
  const graph = new dagre.graphlib.Graph();
  graph.setGraph({ rankdir: 'LR', ranksep: 64, nodesep: 24, marginx: 20, marginy: 20 });
  graph.setDefaultEdgeLabel(() => ({}));
  for (const step of ordered) graph.setNode(step.attack_step_id, { width: NODE_WIDTH, height: NODE_HEIGHT });
  for (let index = 1; index < ordered.length; index += 1) {
    // Dagre needs ordering constraints; these edges never become rendered or claimed as causal.
    graph.setEdge(ordered[index - 1].attack_step_id, ordered[index].attack_step_id);
  }
  dagre.layout(graph);
  return new Map(ordered.map((step) => {
    const point = graph.node(step.attack_step_id);
    return [step.attack_step_id, { x: point.x - NODE_WIDTH / 2, y: point.y - NODE_HEIGHT / 2 }] as const;
  }));
}
