import Link from 'next/link';
import { CircleHelp } from 'lucide-react';
import styles from '@/features/dashboard/DashboardOverview.module.css';

type WorkspacePlaceholderProps = {
  title: string;
  description: string;
  dataName: string;
  fields: readonly string[];
  notice?: string;
};

export default function WorkspacePlaceholder({ title, description, dataName, fields, notice }: WorkspacePlaceholderProps) {
  return (
    <div className={styles.page}>
      <header className={styles.pageHeader}>
        <div><h1>{title}</h1><p>{description}</p></div>
        <span className={styles.unavailable}>未获得数据</span>
      </header>
      <section className={styles.panel} aria-label={dataName}>
        <header className={styles.panelHeader}><h2>{dataName}</h2><span className={styles.panelMeta}>状态未知</span></header>
        <div className={styles.columnHeader} aria-label="记录字段">
          {fields.map((field) => <span key={field}>{field}</span>)}
        </div>
        <div className={`${styles.emptyState} ${styles.workspaceEmpty}`}>
          <CircleHelp size={28} aria-hidden="true" />
          <h3>未获得{dataName}</h3>
          <p>当前无法判断是否存在待处理记录。获得数据后将在这里展示。</p>
        </div>
        <footer className={styles.workspaceFooter}>
          <p>{notice ?? '记录数量与处理状态尚未确认。'}</p>
          <Link href="/">返回运营总览</Link>
        </footer>
      </section>
    </div>
  );
}
