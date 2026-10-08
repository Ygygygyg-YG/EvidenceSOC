import { describe, expect, it } from 'vitest';
import { layoutStepPositions } from './graphLayout';

describe('attack step layout', () => {
  it('uses sequence only to position steps and does not emit a factual relationship', () => {
    const layout = layoutStepPositions([
      { attack_step_id: 'STEP-B', sequence: 2 },
      { attack_step_id: 'STEP-A', sequence: 1 },
      { attack_step_id: 'STEP-C', sequence: 3 },
    ]);
    expect(layout.get('STEP-A')!.x).toBeLessThan(layout.get('STEP-B')!.x);
    expect(layout.get('STEP-B')!.x).toBeLessThan(layout.get('STEP-C')!.x);
    expect(layout.size).toBe(3);
  });
});
