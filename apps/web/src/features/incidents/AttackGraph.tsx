'use client';

import { useMemo } from 'react';
import {
  Background, BackgroundVariant, Controls, Handle, MarkerType, Position, ReactFlow,
  type Edge, type Node, type NodeProps,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import type { IncidentSummary } from './incidentContract';
import type { AttackGraphData } from './investigationSnapshotContract';
import { layoutStepPositions } from './graphLayout';
import { StepMetadata, stepDetails } from './attackStepDetails';
import styles from './IncidentDetail.module.css';

type AttackStep = IncidentSummary['attack_steps'][number];
type StepNode = Node<{
  step: AttackStep;
  graphNode?: AttackGraphData['nodes'][number];
  selected: boolean;
  selectStep: (id: string) => void;
}, 'attackStep'>;

function StepCard({ data }: NodeProps<StepNode>) {
  const { step, graphNode, selected, selectStep } = data;
  const details = stepDetails(step, graphNode);
  return (
    <button type="button" className={styles.graphStep} aria-pressed={selected}
      data-support-status={graphNode?.support_status ?? 'unknown'}
      aria-label={`第 ${step.sequence} 步 ${step.description}`}
      onClick={() => selectStep(step.attack_step_id)}>
      <Handle type="target" position={Position.Left} isConnectable={false} style={{ opacity: 0 }} />
      <span className={styles.graphStepTop}><span>第 {step.sequence} 步</span><span title={details.phase}>{details.phase}</span></span>
      <strong>{step.description}</strong>
      <StepMetadata step={step} node={graphNode} />
      <span className={styles.graphStepMeta} title={details.techniques}>{details.techniques} · {step.evidence_ids.length} 条证据引用</span>
      <span className={styles.graphStepHint}>{details.support}</span>
      <Handle type="source" position={Position.Right} isConnectable={false} style={{ opacity: 0 }} />
    </button>
  );
}

const nodeTypes = { attackStep: StepCard };

export default function AttackGraph({ steps, graph, selectedStepId, selectStep }: {
  steps: AttackStep[];
  graph?: AttackGraphData;
  selectedStepId: string | null;
  selectStep: (id: string) => void;
}) {
  const positions = useMemo(() => layoutStepPositions(steps), [steps]);
  const graphNodes = useMemo(() => new Map(graph?.nodes.map((node) => [node.step_id, node]) ?? []), [graph]);
  const nodes = useMemo<StepNode[]>(() => steps.map((step) => ({
    id: step.attack_step_id,
    type: 'attackStep',
    position: positions.get(step.attack_step_id) ?? { x: 0, y: 0 },
    data: { step, graphNode: graphNodes.get(step.attack_step_id), selected: selectedStepId === step.attack_step_id, selectStep },
    draggable: false,
    selectable: true,
  })), [graphNodes, positions, selectedStepId, selectStep, steps]);
  const edges = useMemo<Edge[]>(() => {
    const visible = new Set(steps.map((step) => step.attack_step_id));
    return graph?.edges.filter((edge) => visible.has(edge.source_step_id) && visible.has(edge.target_step_id))
      .map((edge) => {
        const relationLabel = edge.relation === 'temporal' ? '时间先后' :
          edge.relation === 'causal_candidate' ? '因果候选' :
            edge.relation === 'related' ? '行为关联' : '未分类关系';
        const supportLabel = edge.support_status === 'insufficient' ? '证据不足' :
          edge.support_status === 'candidate' || edge.relation === 'causal_candidate' ? '待证实' : null;
        const directed = edge.relation === 'temporal' || edge.relation === 'causal_candidate';
        const ariaRelation = edge.relation === 'temporal'
          ? `${edge.source_step_id} 早于 ${edge.target_step_id}`
          : edge.relation === 'causal_candidate'
            ? `${edge.source_step_id} 可能导致 ${edge.target_step_id}`
            : `${edge.source_step_id} 与 ${edge.target_step_id}，方向未定义`;
        return {
          id: edge.edge_id, source: edge.source_step_id, target: edge.target_step_id,
          type: 'smoothstep', label: [relationLabel, supportLabel].filter(Boolean).join(' · '),
          ariaLabel: `${relationLabel}：${ariaRelation}${supportLabel ? `；${supportLabel}` : ''}`,
          markerEnd: directed ? { type: MarkerType.ArrowClosed } : undefined,
          style: {
            stroke: edge.support_status === 'supported' ? 'var(--soc-primary)' : 'var(--soc-text-muted)',
            strokeDasharray: edge.relation === 'causal_candidate' ? '6 4' :
              edge.relation === 'temporal' ? undefined : '2 4',
          },
        };
      }) ?? [];
  }, [graph, steps]);

  return (
    <div className={styles.graphCanvas} data-testid="attack-graph">
      <ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes} colorMode="dark"
        fitView fitViewOptions={{ padding: 0.15, maxZoom: 1 }} minZoom={0.3} maxZoom={1.5}
        nodesConnectable={false} nodesDraggable={false}
        panOnDrag zoomOnScroll zoomOnPinch>
        <Background variant={BackgroundVariant.Dots} gap={24} size={1} color="var(--soc-border)" />
        <Controls showInteractive={false} />
      </ReactFlow>
    </div>
  );
}
