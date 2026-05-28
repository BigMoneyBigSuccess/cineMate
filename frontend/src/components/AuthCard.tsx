import type { ReactNode } from 'react';
import Brand from './Brand';

interface AuthCardProps {
  title: string;
  subtitle: string;
  children: ReactNode;
  footer?: ReactNode;
}

export default function AuthCard({ title, subtitle, children, footer }: AuthCardProps) {
  return (
    <main className="auth-screen">
      <header className="auth-topbar">
        <Brand />
      </header>
      <section className="auth-card" aria-labelledby="auth-title">
        <header className="auth-card-header">
          <h1 id="auth-title">{title}</h1>
          <p>{subtitle}</p>
        </header>
        {children}
        {footer ? <footer className="auth-footer">{footer}</footer> : null}
      </section>
      <aside className="auth-preview" aria-hidden="true">
        <div className="preview-window preview-window-main">
          <div className="preview-bar" />
          <div className="preview-grid">
            <span />
            <span />
            <span />
            <span />
          </div>
        </div>
        <div className="preview-window preview-window-side">
          <div className="preview-portrait" />
          <div className="preview-lines">
            <span />
            <span />
            <span />
          </div>
        </div>
      </aside>
    </main>
  );
}
