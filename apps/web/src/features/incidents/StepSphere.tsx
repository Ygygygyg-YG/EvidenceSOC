import {
  CircleDotDashed, Database, KeyRound, Network, RadioTower, Search, ShieldAlert,
  ShieldOff, Terminal, Upload,
} from 'lucide-react';
import styles from './StepSphere.module.css';

function PhaseIcon({ phase }: { phase: string }) {
  const value = phase.toLowerCase();
  if (value.includes('initial') || value.includes('access') || value.includes('入口')) return <ShieldAlert />;
  if (value.includes('execution') || value.includes('执行')) return <Terminal />;
  if (value.includes('credential') || value.includes('凭据')) return <KeyRound />;
  if (value.includes('discovery') || value.includes('侦察') || value.includes('发现')) return <Search />;
  if (value.includes('lateral') || value.includes('横向')) return <Network />;
  if (value.includes('collection') || value.includes('收集')) return <Database />;
  if (value.includes('command') || value.includes('control') || value.includes('控制')) return <RadioTower />;
  if (value.includes('exfil') || value.includes('外传')) return <Upload />;
  if (value.includes('impact') || value.includes('影响')) return <ShieldOff />;
  return <CircleDotDashed />;
}

export default function StepSphere({ phase, supportStatus = 'unknown', selected = false, compact = false }: {
  phase: string;
  supportStatus?: string;
  selected?: boolean;
  compact?: boolean;
}) {
  return (
    <span className={`${styles.sphere} ${compact ? styles.compact : ''}`}
      data-testid="step-sphere" data-support-status={supportStatus} data-selected={selected ? 'true' : 'false'}
      aria-hidden="true">
      <PhaseIcon phase={phase} />
    </span>
  );
}
