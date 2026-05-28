import { Star } from 'lucide-react';

interface RatingControlProps {
  value?: number;
  onChange: (value: number) => void;
  compact?: boolean;
}

export default function RatingControl({ value, onChange, compact = false }: RatingControlProps) {
  const scores = Array.from({ length: 10 }, (_, index) => index + 1);

  return (
    <div className={`rating-control${compact ? ' rating-control-compact' : ''}`} aria-label="Оценка">
      {scores.map((score) => (
        <button
          key={score}
          className={value === score ? 'rating-score rating-score-active' : 'rating-score'}
          type="button"
          onClick={() => onChange(score)}
          title={`Оценить на ${score}`}
        >
          {compact ? (
            <Star size={13} fill={value !== undefined && score <= value ? 'currentColor' : 'none'} />
          ) : (
            score
          )}
        </button>
      ))}
    </div>
  );
}
