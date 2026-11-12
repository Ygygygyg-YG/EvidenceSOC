'use client';

import { useEffect, useRef } from 'react';
import styles from './ParticleBackground.module.css';

type Particle = { x: number; y: number; radius: number; alpha: number; vx: number; vy: number };
type MotionState = 'running' | 'static' | 'paused';

/** Decorative only: this component never reads or changes business data. */
export default function ParticleBackground({ paused }: { paused: boolean }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const node = canvasRef.current;
    if (!node) return;
    const canvas: HTMLCanvasElement = node;
    let context: CanvasRenderingContext2D | null;
    try {
      context = canvas.getContext('2d');
    } catch {
      canvas.dataset.motionState = 'static';
      return;
    }
    if (!context) {
      canvas.dataset.motionState = 'static';
      return;
    }
    const ctx = context;
    const motionQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
    const smallQuery = window.matchMedia('(max-width: 767px)');
    // Cache media values in event handlers. Diagnostic DOM reads must not poll matches.
    let reduced = motionQuery.matches;
    let small = smallQuery.matches;
    let hidden = document.hidden;
    let disposed = false;
    let width = 0;
    let height = 0;
    let points: Particle[] = [];
    let frame: number | null = null;
    let lastPaint: number | null = null;

    function setState(state: MotionState) {
      if (canvas.dataset.motionState !== state) canvas.dataset.motionState = state;
    }

    function stop() {
      if (frame !== null) window.cancelAnimationFrame(frame);
      frame = null;
      lastPaint = null;
    }

    function paint(delta: number) {
      ctx.clearRect(0, 0, width, height);
      for (const point of points) {
        point.x = (point.x + point.vx * delta + width) % width;
        point.y = (point.y + point.vy * delta + height) % height;
        ctx.beginPath();
        ctx.arc(point.x, point.y, point.radius, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(155, 221, 221, ${point.alpha})`;
        ctx.fill();
      }
    }

    function canAnimate() {
      return !disposed && !paused && !reduced && !small && !hidden && width > 0 && height > 0;
    }

    function tick(time: number) {
      frame = null;
      if (!canAnimate()) return;
      const interval = 1000 / 30;
      if (lastPaint === null || time - lastPaint >= interval) {
        paint(lastPaint === null ? 0 : Math.min((time - lastPaint) / 1000, 0.1));
        lastPaint = time;
      }
      if (canAnimate()) frame = window.requestAnimationFrame(tick);
    }

    function reconcile() {
      if (disposed) return;
      if (!canAnimate()) {
        stop();
        setState(paused || hidden ? 'paused' : 'static');
        if (!hidden && width > 0 && height > 0) paint(0);
      } else {
        setState('running');
        if (frame === null) frame = window.requestAnimationFrame(tick);
      }
    }

    function resize() {
      if (disposed) return;
      const rect = canvas.getBoundingClientRect();
      width = Math.max(0, rect.width);
      height = Math.max(0, rect.height);
      const dpr = Math.min(small ? 1 : 1.5, Math.max(1, window.devicePixelRatio || 1));
      canvas.width = Math.max(1, Math.round(width * dpr));
      canvas.height = Math.max(1, Math.round(height * dpr));
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      let seed = 27;
      const random = () => {
        seed = (seed * 1664525 + 1013904223) >>> 0;
        return seed / 4294967296;
      };
      const count = small ? 24 : 96;
      points = Array.from({ length: count }, () => {
        const radius = 0.55 + Math.pow(random(), 1.7) * 1.85;
        const depth = (radius - 0.55) / 1.85;
        return {
          x: random() * width,
          y: random() * height,
          radius,
          alpha: 0.13 + random() * 0.17 + depth * 0.1,
          vx: (random() - 0.5) * (2.5 + depth),
          vy: -1.3 - random() * (2.8 + depth),
        };
      });
      canvas.dataset.particleCount = String(count);
      canvas.dataset.particleSizeRange = '.55-2.40';
      lastPaint = null;
      if (!hidden && width > 0 && height > 0) paint(0);
      reconcile();
    }

    function motionChanged(event: MediaQueryListEvent) {
      reduced = event.matches;
      reconcile();
    }
    function sizeChanged(event: MediaQueryListEvent) {
      small = event.matches;
      resize();
    }
    function visibilityChanged() {
      hidden = document.hidden;
      reconcile();
    }

    motionQuery.addEventListener('change', motionChanged);
    smallQuery.addEventListener('change', sizeChanged);
    document.addEventListener('visibilitychange', visibilityChanged);
    window.addEventListener('resize', resize, { passive: true });
    const observer = typeof ResizeObserver === 'undefined' ? null : new ResizeObserver(resize);
    observer?.observe(canvas);
    resize();

    return () => {
      disposed = true;
      stop();
      observer?.disconnect();
      motionQuery.removeEventListener('change', motionChanged);
      smallQuery.removeEventListener('change', sizeChanged);
      document.removeEventListener('visibilitychange', visibilityChanged);
      window.removeEventListener('resize', resize);
      setState('paused');
    };
  }, [paused]);

  return <canvas ref={canvasRef} id="soc-background-particles" className={styles.canvas}
    data-testid="particle-background" data-particle-count="0" data-particle-size-range=".55-2.40"
    data-motion-state="static" aria-hidden="true" />;
}
