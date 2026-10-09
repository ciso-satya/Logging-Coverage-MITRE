import { useEffect, useState } from "react";
import type { ReactNode } from "react";

export interface TipState {
  x: number;
  y: number;
  content: ReactNode;
}

export function Tooltip({ tip }: { tip: TipState | null }) {
  const [pos, setPos] = useState({ left: 0, top: 0 });
  useEffect(() => {
    if (!tip) return;
    const w = 330;
    const h = 140;
    const left = Math.min(tip.x + 14, window.innerWidth - w - 8);
    const top = tip.y + 16 + h > window.innerHeight ? tip.y - h - 8 : tip.y + 16;
    setPos({ left, top });
  }, [tip]);
  if (!tip) return null;
  return (
    <div className="tooltip" style={pos} role="tooltip">
      {tip.content}
    </div>
  );
}
