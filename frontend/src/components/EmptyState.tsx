import type { ReactNode } from 'react';

interface EmptyStateProps {
  title: string;
  text: string;
  action?: ReactNode;
}

export default function EmptyState({ title, text, action }: EmptyStateProps) {
  return (
    <section className="empty-state">
      <h2>{title}</h2>
      <p>{text}</p>
      {action}
    </section>
  );
}
