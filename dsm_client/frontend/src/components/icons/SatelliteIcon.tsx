import React from 'react';

interface Props {
  size?: number;
  title?: string;
  className?: string;
  color?: string;
}

const SatelliteIcon: React.FC<Props> = ({ size = 16, title = 'Satellite', className, color }) => (
  <svg
    width={size}
    height={size}
    viewBox="0 0 24 24"
    fill="none"
    xmlns="http://www.w3.org/2000/svg"
    className={className}
    aria-hidden={title ? undefined : 'true'}
    role="img"
    style={{ color }}
  >
    {title && <title>{title}</title>}
    {/* Monochrome satellite icon - simple, minimal glyph */}
    <path fill="currentColor" d="M21.71 11.29l-4-4a1 1 0 0 0-1.41 0L14 9.59 8.41 15.17a2 2 0 0 0 0 2.83l1.59 1.59a2 2 0 0 0 2.83 0L16 19.42l2.29-2.29a1 1 0 0 0 0-1.41l3.42-3.42a1 1 0 0 0 0-1.41zM9.5 14.67a1 1 0 1 1-1.41-1.41 1 1 0 0 1 1.41 1.41zM6.4 17.78a3.5 3.5 0 0 1 0-4.95l1.1 1.1a2 2 0 0 0 0 2.83l-1.1 1.02z" />
    <path fill="currentColor" d="M4.3 20.6L3 19.3a1 1 0 0 0-1.41 1.41l1.3 1.3a1 1 0 0 0 1.41-1.41z" />
  </svg>
);

export default SatelliteIcon;
