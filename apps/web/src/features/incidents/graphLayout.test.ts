import { describe, expect, it } from 'vitest';
import { GRAPH_NODE_HEIGHT, GRAPH_NODE_WIDTH, layoutStepPositions } from './graphLayout';

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

  it('returns an empty map for no steps and finite coordinates for one step', () => {
    expect(layoutStepPositions([]).size).toBe(0);
    const point = layoutStepPositions([{ attack_step_id: 'ONLY', sequence: 1 }]).get('ONLY');
    expect(point).toBeDefined();
    expect(Number.isFinite(point!.x)).toBe(true);
    expect(Number.isFinite(point!.y)).toBe(true);
  });

  it('uses stable identifier ordering when sequence numbers tie', () => {
    const input = [{ attack_step_id: 'STEP-Z', sequence: 2 }, { attack_step_id: 'STEP-A', sequence: 2 }];
    const first = layoutStepPositions(input);
    const second = layoutStepPositions([...input].reverse());
    expect(first).toEqual(second);
    expect(first.get('STEP-A')!.x).toBeLessThan(first.get('STEP-Z')!.x);
  });

  it('keeps fixed spherical nodes from overlapping', () => {
    const layout = layoutStepPositions(Array.from({ length: 5 }, (_, index) => ({
      attack_step_id: `STEP-${index + 1}`, sequence: index + 1,
    })));
    const points = [...layout.values()];
    for (let index = 1; index < points.length; index += 1) {
      expect(points[index].x - points[index - 1].x).toBeGreaterThanOrEqual(GRAPH_NODE_WIDTH);
      expect(Math.abs(points[index].y - points[index - 1].y)).toBeLessThan(GRAPH_NODE_HEIGHT);
    }
  });

  it('exports dimensions that match the approved fixed node footprint', () => {
    expect(GRAPH_NODE_WIDTH).toBe(240);
    expect(GRAPH_NODE_HEIGHT).toBe(304);
  });
});
