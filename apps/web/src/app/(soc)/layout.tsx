import type { ReactNode } from 'react';
import SocShell from '@/components/shell/SocShell';

export default function SocLayout({ children }: { children: ReactNode }) {
  return <SocShell>{children}</SocShell>;
}
