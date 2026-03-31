import React from 'react';

type Direction = 'up' | 'down' | 'left' | 'right';

interface ArrowIconProps {
  direction?: Direction;
  size?: number;
  color?: string; // supports CSS color strings, e.g., 'var(--stateboy-dark)'
  className?: string;
}

const transforms: Record<Direction, string> = {
  up: 'rotate(0 12 12) translate(0 -2)',
  down: 'rotate(180 12 12) translate(0 -2)',
  left: 'rotate(-90 12 12) translate(0 -2)',
  right: 'rotate(90 12 12) translate(0 -2)'
};

const ArrowIcon: React.FC<ArrowIconProps> = ({ direction = 'down', size = 12, color = 'currentColor', className }) => {
  const vw = Math.max(8, size);
  const vh = Math.max(8, size);
  // Use switch to avoid object injection sink warning from security/detect-object-injection
  let transform: string;
  switch (direction) {
    case 'up':
      transform = transforms.up;
      break;
    case 'down':
      transform = transforms.down;
      break;
    case 'left':
      transform = transforms.left;
      break;
    case 'right':
      transform = transforms.right;
      break;
    default:
      transform = transforms.down;
  }
  return (
    <svg
      className={className}
      width={vw}
      height={vh}
      viewBox="0 0 24 24"
      xmlns="http://www.w3.org/2000/svg"
      aria-hidden="true"
      role="img"
      style={{ display: 'inline-block', verticalAlign: 'middle', color }}
    >
      <path d="M7 10l5 5 5-5z" fill="currentColor" transform={transform} />
    </svg>
  );
};

export default ArrowIcon;
