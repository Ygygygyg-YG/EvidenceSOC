export const streamEventNames = [
  'investigation.started', 'status', 'agent.started', 'agent.completed',
  'evidence.added', 'approval.required', 'decision.recorded',
  'validation.completed', 'investigation.completed', 'investigation.failed',
] as const;

export const terminalStreamEvents = new Set<string>(['investigation.completed', 'investigation.failed']);

const cursorPattern = /^[0-9]{1,20}$/;

export function nextStreamCursor(previous: string | undefined, eventId: string): string | null {
  if (!cursorPattern.test(eventId)) return null;
  if (previous && cursorPattern.test(previous) && BigInt(eventId) <= BigInt(previous)) return null;
  return eventId;
}
