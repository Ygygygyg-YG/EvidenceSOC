'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { ArrowRight, Shield } from 'lucide-react';
import styles from './OpeningExperience.module.css';

type Props = {
  replayToken: number;
  motionPaused: boolean;
  autoOpen: boolean;
  onOpenChange: (open: boolean) => void;
};
type Particle = { x: number; y: number; radius: number; alpha: number; vx: number; vy: number };
type ParticleState = 'running' | 'static' | 'paused';
type RendererState = 'running' | 'static' | 'fallback';

export default function OpeningExperience({ replayToken, motionPaused, autoOpen, onOpenChange }: Props) {
  const [open, setOpen] = useState(autoOpen);
  const [leaving, setLeaving] = useState(false);
  const [reducedMotion, setReducedMotion] = useState(false);
  const [fallback, setFallback] = useState(false);
  const [rendererState, setRendererState] = useState<RendererState>('static');
  const enterButton = useRef<HTMLButtonElement>(null);
  const particleCanvas = useRef<HTMLCanvasElement>(null);
  const coreCanvas = useRef<HTMLCanvasElement>(null);
  const closeTimer = useRef<number | null>(null);
  const returnFocusFrame = useRef<number | null>(null);
  const autoChecked = useRef(autoOpen);
  const lastReplayToken = useRef(0);

  const reveal = useCallback(() => {
    if (closeTimer.current !== null) window.clearTimeout(closeTimer.current);
    closeTimer.current = null;
    setFallback(false);
    setLeaving(false);
    setOpen(true);
  }, []);

  const complete = useCallback(() => {
    if (closeTimer.current !== null) window.clearTimeout(closeTimer.current);
    closeTimer.current = null;
    setLeaving(false);
    setOpen(false);
    if (returnFocusFrame.current !== null) window.cancelAnimationFrame(returnFocusFrame.current);
    returnFocusFrame.current = window.requestAnimationFrame(() => {
      returnFocusFrame.current = null;
      document.querySelector<HTMLElement>('#soc-main')?.focus({ preventScroll: true });
    });
  }, []);

  const finish = useCallback((immediate: boolean) => {
    if (!open || (leaving && !immediate)) return;
    setLeaving(true);
    if (immediate || reducedMotion || motionPaused) complete();
    else closeTimer.current = window.setTimeout(complete, 620);
  }, [complete, leaving, motionPaused, open, reducedMotion]);

  useEffect(() => {
    const query = window.matchMedia('(prefers-reduced-motion: reduce)');
    const changed = (event: MediaQueryListEvent) => setReducedMotion(event.matches);
    const initialFrame = window.requestAnimationFrame(() => setReducedMotion(query.matches));
    query.addEventListener('change', changed);
    return () => {
      window.cancelAnimationFrame(initialFrame);
      query.removeEventListener('change', changed);
    };
  }, []);

  useEffect(() => {
    if (!autoOpen || autoChecked.current) return;
    // Auto-open once per mounted document. A full reload remounts the shell and
    // shows the opening again; closing it never reopens it within the same page.
    autoChecked.current = true;
    reveal();
  }, [autoOpen, reveal]);

  useEffect(() => {
    if (replayToken <= 0 || replayToken === lastReplayToken.current) return;
    lastReplayToken.current = replayToken;
    const frame = window.requestAnimationFrame(reveal);
    return () => window.cancelAnimationFrame(frame);
  }, [replayToken, reveal]);

  useEffect(() => { onOpenChange(open); }, [onOpenChange, open]);

  useEffect(() => {
    if (!open) return;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    const focusFrame = window.requestAnimationFrame(() => enterButton.current?.focus({ preventScroll: true }));
    return () => {
      window.cancelAnimationFrame(focusFrame);
      document.body.style.overflow = previousOverflow;
    };
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const keydown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.preventDefault();
        finish(true);
        return;
      }
      if (event.key !== 'Tab') return;
      const dialog = document.querySelector<HTMLElement>('#soc-opening-experience');
      const focusable = dialog ? [...dialog.querySelectorAll<HTMLElement>('button:not(:disabled), [href], [tabindex]:not([tabindex="-1"])')] : [];
      if (!focusable.length) return;
      const first = focusable[0], last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
    };
    document.addEventListener('keydown', keydown, true);
    return () => document.removeEventListener('keydown', keydown, true);
  }, [finish, open]);

  useEffect(() => () => {
    if (closeTimer.current !== null) window.clearTimeout(closeTimer.current);
    if (returnFocusFrame.current !== null) window.cancelAnimationFrame(returnFocusFrame.current);
  }, []);

  useEffect(() => {
    if (!open) return;
    const canvas = particleCanvas.current;
    if (!canvas) return;
    let context: CanvasRenderingContext2D | null;
    try { context = canvas.getContext('2d'); }
    catch { context = null; }
    if (!context) { canvas.dataset.motionState = 'static'; return; }
    const ctx = context;
    const smallQuery = window.matchMedia('(max-width: 767px)');
    const systemReduced = reducedMotion || window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    let small = smallQuery.matches, hidden = document.hidden, disposed = false;
    let width = 0, height = 0, frame = 0, lastPaint: number | null = null, points: Particle[] = [];
    const setState = (state: ParticleState) => { canvas.dataset.motionState = state; };
    const stop = () => { if (frame) window.cancelAnimationFrame(frame); frame = 0; lastPaint = null; };
    const paint = (delta: number) => {
      ctx.clearRect(0, 0, width, height);
      for (const point of points) {
        point.x = (point.x + point.vx * delta + width) % width;
        point.y = (point.y + point.vy * delta + height) % height;
        ctx.beginPath(); ctx.arc(point.x, point.y, point.radius, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(167, 205, 214, ${point.alpha})`; ctx.fill();
      }
    };
    const canAnimate = () => !disposed && !hidden && !small && !systemReduced && !motionPaused && !leaving && width > 0 && height > 0;
    const tick = (time: number) => {
      frame = 0;
      if (!canAnimate()) return;
      if (lastPaint === null || time - lastPaint >= 1000 / 30 - .5) {
        paint(lastPaint === null ? 0 : Math.min((time - lastPaint) / 1000, .1));
        lastPaint = time;
      }
      if (canAnimate()) frame = window.requestAnimationFrame(tick);
    };
    const reconcile = () => {
      stop();
      if (hidden || leaving) setState('paused');
      else if (small || systemReduced || motionPaused) { setState('static'); paint(0); }
      else { setState('running'); frame = window.requestAnimationFrame(tick); }
    };
    const resize = () => {
      if (disposed) return;
      const rect = canvas.getBoundingClientRect(); width = Math.max(0, rect.width); height = Math.max(0, rect.height);
      const dpr = Math.min(small ? 1 : 1.5, Math.max(1, window.devicePixelRatio || 1));
      canvas.width = Math.max(1, Math.round(width * dpr)); canvas.height = Math.max(1, Math.round(height * dpr));
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      let seed = 91;
      const random = () => { seed = (seed * 1664525 + 1013904223) >>> 0; return seed / 4294967296; };
      const count = small ? 32 : 180;
      points = Array.from({ length: count }, () => {
        const radius = .65 + Math.pow(random(), 1.75) * 2.35;
        const depth = (radius - .65) / 2.35;
        return {
          x: random() * width, y: random() * height, radius,
          alpha: .16 + random() * .26 + depth * .12,
          vx: (random() - .5) * (2.4 + depth * 1.2), vy: -1.3 - random() * (2.8 + depth * 1.4),
        };
      });
      canvas.dataset.particleCount = String(count);
      canvas.dataset.particleSizeRange = '.65-3.00';
      paint(0); reconcile();
    };
    const sizeChanged = (event: MediaQueryListEvent) => { small = event.matches; resize(); };
    const visibilityChanged = () => { hidden = document.hidden; reconcile(); };
    smallQuery.addEventListener('change', sizeChanged);
    document.addEventListener('visibilitychange', visibilityChanged);
    window.addEventListener('resize', resize, { passive: true });
    const observer = typeof ResizeObserver === 'undefined' ? null : new ResizeObserver(resize);
    observer?.observe(canvas); resize();
    return () => {
      disposed = true; stop(); observer?.disconnect(); smallQuery.removeEventListener('change', sizeChanged);
      document.removeEventListener('visibilitychange', visibilityChanged); window.removeEventListener('resize', resize);
      setState('paused');
    };
  }, [leaving, motionPaused, open, reducedMotion]);

  useEffect(() => {
    if (!open || leaving) return;
    const canvas = coreCanvas.current;
    if (!canvas) return;
    let disposed = false;
    let controller: import('./OpeningCore').OpeningCoreController | null = null;
    const staticMode = reducedMotion || motionPaused || window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const visibilityChanged = () => {
      if (!controller) return;
      if (document.hidden) { controller.stop(); setRendererState('static'); }
      else if (staticMode) { controller.renderOnce(); setRendererState('static'); }
      else { controller.start(); setRendererState('running'); }
    };
    document.addEventListener('visibilitychange', visibilityChanged);
    void import('./OpeningCore').then(({ createOpeningCore }) => {
      if (disposed) return;
      controller = createOpeningCore(canvas, {
        reducedMotion: staticMode,
        onFallback: () => { if (!disposed) { setFallback(true); setRendererState('fallback'); } },
      });
      const state = controller.getState();
      if (!state.supported) { setFallback(true); setRendererState('fallback'); return; }
      if (staticMode) { controller.renderOnce(); setRendererState('static'); }
      else { controller.start(); setRendererState(document.hidden ? 'static' : 'running'); }
    }).catch(() => { if (!disposed) { setFallback(true); setRendererState('fallback'); } });
    return () => {
      disposed = true; document.removeEventListener('visibilitychange', visibilityChanged);
      controller?.stop(); controller?.dispose();
    };
  }, [leaving, motionPaused, open, reducedMotion]);

  if (!open) return null;
  return (
    <section id="soc-opening-experience" className={styles.overlay} data-testid="opening-experience"
      data-state={leaving ? 'leaving' : 'open'} role="dialog" aria-modal="true"
      aria-label="证链；让每一次安全判断，都有证据可循" aria-describedby="soc-opening-description">
      <header className={styles.header}>
        <div className={styles.brand}><Shield size={21} aria-hidden="true" /><span>EvidenceSOC</span></div>
        <span className={styles.securityLabel}>EVIDENCE-DRIVEN SECURITY</span>
        <button type="button" className={styles.skipButton} onClick={() => finish(true)}>跳过开场</button>
      </header>
      <canvas ref={particleCanvas} className={styles.particles} data-testid="opening-particles"
        data-particle-count="0" data-motion-state="static" aria-hidden="true" />
      <h1 className={styles.giantWord}><span>证</span><span>链</span></h1>
      <div className={styles.coreWrap}>
        <canvas ref={coreCanvas} className={styles.coreCanvas} data-testid="opening-core"
          data-renderer-state={rendererState} data-animation-speed="1.8" role="img"
          aria-label="旋转的证据核心球体与关系轨道" hidden={fallback} />
        {fallback && <div className={styles.fallback} data-testid="opening-core-fallback" role="img"
          aria-label="旋转的证据核心球体与关系轨道">
          <span className={styles.fallbackOrbitA} aria-hidden="true" />
          <span className={styles.fallbackOrbitB} aria-hidden="true" />
          <span className={styles.fallbackSphere} aria-hidden="true" />
        </div>}
      </div>
      <div className={styles.copy}>
        <p aria-hidden="true">让每一次安全判断，<br />都有证据可循</p>
        <span id="soc-opening-description">证据驱动的安全调查与模拟响应</span>
      </div>
      <div className={styles.entry}>
        <button ref={enterButton} type="button" disabled={leaving} onClick={() => finish(false)}>
          进入工作台<ArrowRight size={18} aria-hidden="true" />
        </button>
      </div>
      <span className={styles.srOnly} role="status">
        {fallback ? '动态核心暂不可用，已显示静态核心，可直接进入工作台' : rendererState === 'running' ? '证据核心动效已开启' : '证据核心以静态方式显示'}
      </span>
    </section>
  );
}
