import { expect, it } from 'vitest';
import { nextStreamCursor, streamEventNames, terminalStreamEvents } from './investigationStream';

it('只接受单调增加的数字游标，重连和重放不会重复刷新', () => {
  expect(nextStreamCursor(undefined, '1')).toBe('1');
  expect(nextStreamCursor('3', '4')).toBe('4');
  expect(nextStreamCursor('3', '3')).toBeNull();
  expect(nextStreamCursor('3', '2')).toBeNull();
  expect(nextStreamCursor('3', 'not-an-id')).toBeNull();
  expect(nextStreamCursor('3', '999999999999999999999')).toBeNull();
  expect(nextStreamCursor('9007199254740992', '9007199254740993')).toBe('9007199254740993');
});

it('订阅调查变化并在最终事件后停止重连', () => {
  expect(streamEventNames).toContain('evidence.added');
  expect(streamEventNames).toContain('approval.required');
  expect(streamEventNames).toContain('validation.completed');
  expect(terminalStreamEvents.has('investigation.completed')).toBe(true);
  expect(terminalStreamEvents.has('investigation.failed')).toBe(true);
  expect(terminalStreamEvents.has('approval.required')).toBe(false);
});
