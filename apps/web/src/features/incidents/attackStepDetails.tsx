import type { IncidentSummary } from './incidentContract';
import type { AttackGraphData } from './investigationSnapshotContract';
import styles from './IncidentDetail.module.css';

type AttackStep = IncidentSummary['attack_steps'][number];
export type GraphStep = AttackGraphData['nodes'][number];

const dateFormatter = new Intl.DateTimeFormat('zh-CN', {
  timeZone: 'Asia/Shanghai', year: 'numeric', month: '2-digit', day: '2-digit',
  hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false,
});

export function stepDetails(step: AttackStep, node?: GraphStep) {
  return {
    phase: (node ? node.phase : step.phase) ?? '阶段未提供',
    entities: `${node?.host ?? '主机未提供'} / ${node?.service ?? '服务未提供'}`,
    observedAt: node ? node.observed_at : step.occurred_at,
    techniques: (node ? node.technique_ids : step.technique_id ? [step.technique_id] : []).join('、') || '技术未提供',
    confidence: node?.confidence === null || node?.confidence === undefined
      ? '置信度未提供' : `步骤输出置信度 ${Math.round(node.confidence * 100)}%`,
    support: node?.support_status === 'supported' ? '证据引用完整' :
      node?.support_status === 'candidate' ? '候选步骤 · 待证实' :
        node?.support_status === 'insufficient' ? '证据引用不足' : '支持状态未提供',
  };
}

export function StepTime({ value }: { value: string | null }) {
  return value ? <time dateTime={value}>{dateFormatter.format(new Date(value))}</time> : <>时间未提供</>;
}

export function StepMetadata({ step, node }: { step: AttackStep; node?: GraphStep }) {
  const details = stepDetails(step, node);
  return <>
    <span className={styles.graphStepEntities} title={details.entities}>{details.entities}</span>
    <span className={styles.graphStepMeta}><StepTime value={details.observedAt} />（UTC+8）</span>
    <span className={styles.graphStepMeta} title={node?.confidence != null ? '步骤输出置信度；计算依据未提供，不表示校准后的发生概率。' : undefined}>{details.confidence}</span>
  </>;
}
