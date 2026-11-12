'use client';

import { useEffect, useRef, useState, type ReactNode } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useQuery } from '@tanstack/react-query';
import { Drawer } from 'antd';
import { Bell, LayoutDashboard, Menu, Pause, Play, RotateCcw, Search, Shield, ShieldCheck, X } from 'lucide-react';
import { loadDashboard, loadSourceHealth } from '@/features/dashboard/dashboardContract';
import OpeningExperience from '@/components/opening/OpeningExperience';
import ParticleBackground from './ParticleBackground';
import styles from './SocShell.module.css';

const navigationItems = [
  { href: '/', label: '运营总览', icon: LayoutDashboard },
  { href: '/alerts', label: '告警列表', icon: Bell },
  { href: '/incidents', label: '调查列表', icon: Search },
  { href: '/responses', label: '响应审批', icon: ShieldCheck },
] as const;

export default function SocShell({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const [menuOpen, setMenuOpen] = useState(false);
  const [motionPaused, setMotionPaused] = useState(false);
  const [introOpen, setIntroOpen] = useState(pathname === '/');
  const [introReplayToken, setIntroReplayToken] = useState(0);
  const menuButton = useRef<HTMLButtonElement>(null);
  const closeMenuButton = useRef<HTMLButtonElement>(null);
  const mainContent = useRef<HTMLElement>(null);
  const pendingNavigation = useRef<string | null>(null);
  const focusPending = useRef(false);
  const dashboardQuery = useQuery({ queryKey: ['dashboard-summary', '24h'],
    queryFn: ({ signal }) => loadDashboard('24h', signal), retry: false, staleTime: 30_000 });
  const healthQuery = useQuery({ queryKey: ['source-health'],
    queryFn: ({ signal }) => loadSourceHealth(signal), retry: false, staleTime: 30_000 });
  const health = healthQuery.data;
  const isActive = (href: string) => pathname === href || (href !== '/' && pathname.startsWith(`${href}/`));

  useEffect(() => {
    if (menuOpen || !focusPending.current) return;
    if (pendingNavigation.current === null) {
      menuButton.current?.focus({ preventScroll: true });
      focusPending.current = false;
    } else if (pendingNavigation.current === pathname) {
      mainContent.current?.focus({ preventScroll: true });
      focusPending.current = false;
    }
  }, [menuOpen, pathname]);

  return (
    <div className={styles.shell} data-testid="soc-shell">
      <ParticleBackground paused={motionPaused || introOpen} />
      <OpeningExperience replayToken={introReplayToken} motionPaused={motionPaused}
        autoOpen={pathname === '/'} onOpenChange={setIntroOpen} />
      <a className={styles.skipLink} href="#soc-main">跳转到主内容</a>
      <header className={styles.topbar}>
        <div className={styles.brandGroup}>
          <button
            ref={menuButton}
            type="button"
            className={`${styles.menuButton} ${styles.menuTrigger}`}
            aria-label="打开导航菜单"
            title="打开导航菜单"
            aria-haspopup="dialog"
            aria-expanded={menuOpen}
            aria-controls={menuOpen ? 'soc-navigation-menu' : undefined}
            onClick={() => {
              pendingNavigation.current = null;
              focusPending.current = true;
              setMenuOpen(true);
            }}
          >
            <Menu size={20} aria-hidden="true" />
          </button>
          <Link href="/" className={styles.brand} aria-label="EvidenceSOC 首页">
            <Shield size={22} aria-hidden="true" />
            <span>EvidenceSOC</span>
          </Link>
        </div>
        <div className={styles.headerUtilities}>
          <div className={styles.statusGroup} aria-label="连接与数据源状态">
            <span className={styles.status} data-status={dashboardQuery.isError ? 'error' : dashboardQuery.data ? 'connected' : 'unknown'}>
              <span className={styles.statusDot} aria-hidden="true" />
              {dashboardQuery.isError ? '统计连接不可用' : dashboardQuery.data ? '统计接口已连接' : '连接状态未确认'}
            </span>
            <span className={styles.status} data-status={healthQuery.isError ? 'error' :
              health?.postgresql_status === 'ok' && health.opensearch_status === 'ok' ? 'connected' :
                health?.postgresql_status === 'ok' ? 'partial' : 'unknown'}>
              <span className={styles.statusDot} aria-hidden="true" />
              {healthQuery.isError ? '数据源健康不可用' : health?.postgresql_status === 'ok' && health.opensearch_status === 'ok' ? '已核实数据源正常' :
                health?.postgresql_status === 'ok' ? '数据源健康部分未知' : '源健康未知'}
            </span>
            {dashboardQuery.data && <span className={`${styles.status} ${styles.executionMode}`}>
              {dashboardQuery.data.execution_mode === 'rules' ? '规则演示' : '模型调查'}
            </span>}
          </div>
          <button type="button" className={`${styles.motionButton} ${styles.replayButton}`}
            aria-label="重播开场" title="重播开场" aria-controls="soc-opening-experience"
            onClick={() => setIntroReplayToken((value) => value + 1)}>
            <RotateCcw size={15} aria-hidden="true" />
            <span className={styles.replayLabel}>重播开场</span>
          </button>
          <button type="button" className={styles.motionButton}
            aria-label={motionPaused ? '恢复背景动效' : '暂停背景动效'}
            title={motionPaused ? '恢复背景动效' : '暂停背景动效'}
            aria-controls="soc-background-particles" aria-describedby="soc-motion-description"
            onClick={() => setMotionPaused((value) => !value)}>
            {motionPaused ? <Play size={15} aria-hidden="true" /> : <Pause size={15} aria-hidden="true" />}
            <span className={styles.motionLabel}>{motionPaused ? '恢复动效' : '暂停动效'}</span>
          </button>
          <span id="soc-motion-description" className={styles.srOnly}>仅控制背景装饰动效；系统减少动态设置优先。</span>
        </div>
      </header>

      <nav className={styles.rail} aria-label="主导航">
        <span className={styles.navCaption}>工作空间</span>
        {navigationItems.map(({ href, label, icon: Icon }) => (
          <Link key={href} href={href} className={styles.railLink}
            aria-label={label} title={label} aria-current={isActive(href) ? 'page' : undefined}>
            <Icon size={20} aria-hidden="true" />
            <span>{label}</span>
            <span className={styles.navArrow} aria-hidden="true">→</span>
          </Link>
        ))}
        <div className={styles.railFooter}><span>证据驱动</span><p>安全调查与模拟响应</p></div>
      </nav>

      <main ref={mainContent} id="soc-main" className={styles.main} tabIndex={-1}>{children}</main>

      <Drawer
        title="工作区导航"
        placement="left"
        size="min(320px, calc(100vw - 32px))"
        open={menuOpen}
        onClose={() => setMenuOpen(false)}
        destroyOnHidden
        keyboard
        mask={{ closable: true, blur: false }}
        focusable={{ trap: true, focusTriggerAfterClose: false }}
        afterOpenChange={(open) => {
          if (open && menuOpen) closeMenuButton.current?.focus({ preventScroll: true });
        }}
        closable={false}
        extra={
          <button ref={closeMenuButton} type="button" className={styles.menuButton} aria-label="关闭导航菜单"
            title="关闭导航菜单" onClick={() => setMenuOpen(false)}>
            <X size={20} aria-hidden="true" />
          </button>
        }
        styles={{
          wrapper: { boxShadow: 'none' },
          section: { background: 'var(--soc-surface)', color: 'var(--soc-text)', boxShadow: 'none' },
          header: { borderBottom: '1px solid var(--soc-border)', padding: '12px 16px' },
          body: { padding: 16 },
          mask: { backgroundColor: 'rgba(2, 3, 4, 0.76)', backdropFilter: 'none' },
        }}
      >
        <nav id="soc-navigation-menu" className={styles.drawerNavigation} aria-label="完整导航">
          {navigationItems.map(({ href, label, icon: Icon }) => (
            <Link key={href} href={href} className={styles.textLink}
              aria-current={isActive(href) ? 'page' : undefined} onNavigate={() => {
                pendingNavigation.current = href;
                setMenuOpen(false);
              }}>
              <Icon size={20} aria-hidden="true" />
              <span>{label}</span>
            </Link>
          ))}
        </nav>
      </Drawer>
    </div>
  );
}
