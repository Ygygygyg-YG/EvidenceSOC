'use client';

import { useEffect, useRef, useState } from 'react';
import { IncidentRequestError } from './incidentContract';
import { nextStreamCursor, streamEventNames, terminalStreamEvents } from './investigationStream';
import { loadInvestigationSnapshot, type InvestigationSnapshot } from './investigationSnapshotContract';

export type StreamConnection = 'connecting' | 'live' | 'reconnecting' | 'offline' |
  'unauthorized' | 'forbidden' | 'closed';

const terminalStatuses = new Set(['completed', 'failed', 'manual_review', 'rejected']);
const staleAfterMs = 30_000;
const probeIntervalMs = 5_000;

export function useInvestigationStream(
  investigationId: string | null,
  enabled: boolean,
  onSnapshot: (snapshot: InvestigationSnapshot) => void,
  retryKey = 0,
): StreamConnection {
  const [connection, setConnection] = useState<StreamConnection>('closed');
  const snapshotRef = useRef(onSnapshot);
  useEffect(() => { snapshotRef.current = onSnapshot; }, [onSnapshot]);

  useEffect(() => {
    if (!investigationId || !enabled || !/^[A-Za-z0-9_-]{1,64}$/.test(investigationId)) return;
    const controller = new AbortController();
    let disposed = false;
    let terminated = false;
    let source: EventSource | undefined;
    let reconnectTimer: ReturnType<typeof setTimeout> | undefined;
    let refreshTimer: ReturnType<typeof setTimeout> | undefined;
    let staleTimer: ReturnType<typeof setTimeout> | undefined;
    let cursor: string | undefined;
    let retries = 0;
    let generation = 0;
    let lastProbeAt = 0;
    let replaceCursorFromSnapshot = false;

    function closeSource(): void {
      source?.close();
      source = undefined;
      if (staleTimer) clearTimeout(staleTimer);
      staleTimer = undefined;
    }

    function clearRefresh(): void {
      if (refreshTimer) clearTimeout(refreshTimer);
      refreshTimer = undefined;
    }

    function stopForAccess(status: number): void {
      terminated = true;
      closeSource();
      clearRefresh();
      if (reconnectTimer) clearTimeout(reconnectTimer);
      setConnection(status === 401 ? 'unauthorized' : 'forbidden');
    }

    async function synchronize(attempt: number): Promise<InvestigationSnapshot | null> {
      if (!investigationId) return null;
      try {
        const snapshot = await loadInvestigationSnapshot(investigationId, controller.signal);
        if (disposed || attempt !== generation || terminated) return null;
        cursor = replaceCursorFromSnapshot
          ? snapshot.stream_cursor
          : nextStreamCursor(cursor, snapshot.stream_cursor) ?? cursor ?? snapshot.stream_cursor;
        replaceCursorFromSnapshot = false;
        snapshotRef.current(snapshot);
        return snapshot;
      } catch (error) {
        if (!disposed && attempt === generation && error instanceof IncidentRequestError &&
          (error.status === 401 || error.status === 403)) stopForAccess(error.status);
        return null;
      }
    }

    function scheduleReconnect(attempt: number): void {
      if (disposed || terminated || attempt !== generation) return;
      if (retries >= 8) {
        setConnection('offline');
        return;
      }
      const delay = Math.min(1000 * 2 ** retries++, 30_000);
      reconnectTimer = setTimeout(() => {
        reconnectTimer = undefined;
        void calibrateAndConnect(attempt);
      }, delay);
    }

    function watchActivity(eventSource: EventSource): void {
      if (staleTimer) clearTimeout(staleTimer);
      staleTimer = setTimeout(() => {
        if (source === eventSource && !disposed && !terminated) recover(false);
      }, staleAfterMs);
    }

    function parseEventIdentity(data: string): boolean {
      try {
        const payload: unknown = JSON.parse(data);
        return typeof payload === 'object' && payload !== null &&
          'investigation_id' in payload && payload.investigation_id === investigationId;
      } catch { return false; }
    }

    function recover(resetCursor: boolean): void {
      if (disposed || terminated) return;
      closeSource();
      clearRefresh();
      if (reconnectTimer) clearTimeout(reconnectTimer);
      reconnectTimer = undefined;
      if (resetCursor) replaceCursorFromSnapshot = true;
      setConnection('reconnecting');
      void calibrateAndConnect(++generation);
    }

    function connect(attempt: number): void {
      if (disposed || terminated || !investigationId || attempt !== generation) return;
      const url = `/api/v1/investigations/${encodeURIComponent(investigationId)}/stream?cursor=${encodeURIComponent(cursor ?? '0')}`;
      let eventSource: EventSource;
      try { eventSource = new EventSource(url); }
      catch {
        setConnection('reconnecting');
        scheduleReconnect(attempt);
        return;
      }
      source = eventSource;
      watchActivity(eventSource);
      eventSource.onopen = () => {
        if (source !== eventSource || disposed || terminated) return;
        retries = 0;
        watchActivity(eventSource);
        setConnection('live');
      };
      eventSource.addEventListener('stream.heartbeat', (event) => {
        if (source !== eventSource || disposed || terminated) return;
        if (!parseEventIdentity((event as MessageEvent).data)) {
          recover(false);
          return;
        }
        watchActivity(eventSource);
      });
      eventSource.addEventListener('stream.reset', () => {
        if (source !== eventSource || disposed || terminated) return;
        // Re-read the snapshot even if the reset payload is malformed.
        recover(true);
      });
      for (const name of streamEventNames) {
        eventSource.addEventListener(name, (event) => {
          if (source !== eventSource || disposed || terminated) return;
          const message = event as MessageEvent;
          if (!parseEventIdentity(message.data)) {
            recover(false);
            return;
          }
          watchActivity(eventSource);
          const next = nextStreamCursor(cursor, message.lastEventId);
          if (!next) {
            if (!/^[0-9]{1,20}$/.test(message.lastEventId)) recover(false);
            return;
          }
          if (BigInt(next) !== BigInt(cursor ?? '0') + BigInt(1)) {
            recover(false);
            return;
          }
          cursor = next;
          if (terminalStreamEvents.has(name)) {
            closeSource();
            clearRefresh();
            void synchronize(attempt).then((snapshot) => {
              if (disposed || terminated || attempt !== generation) return;
              terminated = true;
              setConnection(snapshot ? 'closed' : 'offline');
            });
          } else if (!refreshTimer) {
            refreshTimer = setTimeout(() => {
              refreshTimer = undefined;
              if (!disposed && !terminated && attempt === generation) void synchronize(attempt);
            }, 100);
          }
        });
      }
      eventSource.onerror = () => {
        if (source !== eventSource || disposed || terminated) return;
        setConnection('reconnecting');
        // Native EventSource resumes with Last-Event-ID; probe the snapshot for
        // an expired session or revoked access without starting a second stream.
        if (Date.now() - lastProbeAt < probeIntervalMs) return;
        lastProbeAt = Date.now();
        void synchronize(attempt).then((snapshot) => {
          if (!snapshot || disposed || attempt !== generation) return;
          if (terminalStatuses.has(snapshot.status)) {
            terminated = true;
            closeSource();
            setConnection('closed');
          }
        });
      };
    }

    async function calibrateAndConnect(attempt: number): Promise<void> {
      const snapshot = await synchronize(attempt);
      if (disposed || terminated || attempt !== generation) return;
      if (!snapshot) {
        setConnection('reconnecting');
        scheduleReconnect(attempt);
      } else if (terminalStatuses.has(snapshot.status)) {
        terminated = true;
        setConnection('closed');
      } else {
        connect(attempt);
      }
    }

    queueMicrotask(() => { if (!disposed) setConnection('connecting'); });
    void calibrateAndConnect(++generation);
    return () => {
      disposed = true;
      controller.abort();
      closeSource();
      if (reconnectTimer) clearTimeout(reconnectTimer);
      clearRefresh();
    };
  }, [investigationId, enabled, retryKey]);

  return enabled && investigationId ? connection : 'closed';
}
