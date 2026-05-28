import { Clapperboard } from 'lucide-react';
import { Link } from 'react-router-dom';

export default function Brand() {
  return (
    <Link className="brand" to="/">
      <span className="brand-mark" aria-hidden="true">
        <Clapperboard size={18} strokeWidth={2.4} />
      </span>
      <span>Cinemate</span>
    </Link>
  );
}
