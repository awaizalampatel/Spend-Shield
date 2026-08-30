/**
 * The shared pieces. Everything visual in the app is built from these, so a
 * change to a severity chip or a money figure lands everywhere at once.
 */
import { useEffect, useState } from 'react';
import { api, rupees } from '../api';

export const Mark = ({ size = 22 }) => (
  <svg width={size} height={size * 1.08} viewBox="0 0 72 78" aria-hidden="true">
    <defs>
      <clipPath id="ss-shield">
        <path d="M36 5 L64 15 V41 C64 58 51 69 36 73 C21 69 8 58 8 41 V15 Z" />
      </clipPath>
    </defs>
    <g clipPath="url(#ss-shield)">
      <rect x="15" y="50" width="7" height="12" fill="var(--navy)" />
      <rect x="26" y="43" width="7" height="19" fill="var(--navy)" />
      <rect x="37" y="35" width="7" height="27" fill="var(--navy)" />
      <rect x="48" y="27" width="7" height="35" fill="var(--navy)" />
      <polyline points="13,25 26,29 39,42 57,49" fill="none" stroke="var(--crit)"
                strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" />
    </g>
    <path d="M36 5 L64 15 V41 C64 58 51 69 36 73 C21 69 8 58 8 41 V15 Z"
          fill="none" stroke="var(--ink)" strokeWidth="3.2" strokeLinejoin="round" />
  </svg>
);

export const Card = ({ title, extra, children, className = '' }) => (
  <div className={`card ${className}`}>
    {(title || extra) && (
      <div className="ch">
        {title && <span className="ct">{title}</span>}
        {extra && <span className="cx">{extra}</span>}
      </div>
    )}
    {children}
  </div>
);

export const Kpi = ({ label, value, caption, delta, deltaDir, small }) => (
  <div className="card">
    <div className="ch">
      <span className="ct">{label}</span>
      {delta != null && <span className={`delta ${deltaDir || ''}`}>{delta}</span>}
    </div>
    <div className={`fig ${small ? 'sm' : ''}`}>{value}</div>
    {caption && <div className="cx">{caption}</div>}
  </div>
);

/** Severity always ships with its word. Color alone is never the signal. */
export const Severity = ({ level, short }) => {
  const key = (level || '').toLowerCase();
  const map = { critical: 'crit', high: 'high', medium: 'med', low: 'low' };
  const cls = map[key];
  if (!cls) return <span className="chip">unrated</span>;
  const label = short
    ? { critical: 'Crit', high: 'High', medium: 'Med', low: 'Low' }[key]
    : key[0].toUpperCase() + key.slice(1);
  return <span className={`chip ${cls}`}><i className="sq" />{label}</span>;
};

/** A money figure and its band. A point estimate with no band is a lie the UI
 *  should not be able to tell, so the band rides along in the tooltip. */
export const Money = ({ m, band, className = '' }) => {
  if (!m) return <span className="cx">—</span>;
  const title = band
    ? `${rupees(band.min)} – ${rupees(band.max)} · likely ${rupees(m)}`
    : rupees(m);
  return <span className={`num ${className}`} title={title}>{rupees(m)}</span>;
};

export const Bar = ({ value, color = 'var(--navy)', width }) => (
  <div className="track" style={width ? { width } : undefined}>
    <i style={{ background: color, width: `${Math.max(0, Math.min(1, value)) * 100}%` }} />
  </div>
);

export const Empty = ({ children, action }) => (
  <div className="empty"><span>{children}</span>{action}</div>
);

export const Loading = ({ rows = 4 }) => (
  <div className="card" style={{ gap: 10 }}>
    {Array.from({ length: rows }).map((_, i) => (
      <div key={i} className="skel" style={{ width: `${100 - i * 12}%` }} />
    ))}
  </div>
);

export const ErrorBox = ({ error, retry }) => (
  <div className="banner">
    <span className="bar" />
    <div>
      <b>{error?.message || 'Something went wrong.'}</b>
      {retry && <div style={{ marginTop: 6 }}>
        <button className="btn" onClick={retry}>Try again</button>
      </div>}
    </div>
  </div>
);

/**
 * One line chart. Single series, navy, 12% area fill, emphasized endpoint —
 * and a hover crosshair, because an SVG chart that cannot be interrogated is a
 * picture of data rather than data.
 */
export const Plot = ({ points, height = 120, format = (v) => v, label }) => {
  const [hover, setHover] = useState(null);
  if (!points || points.length === 0) {
    return <Empty>Not enough history yet — the trend appears once a few days of scores exist.</Empty>;
  }
  if (points.length === 1) {
    return (
      <div className="cx">
        Collecting history — one day of {points.length} so far.{' '}
        <b className="num" style={{ color: 'var(--ink)' }}>{format(points[0].value)}</b>
      </div>
    );
  }

  const W = 460, H = height, padL = 34, padR = 12, padT = 10, padB = 18;
  const vals = points.map((p) => p.value);
  const min = Math.min(...vals) * 0.95;
  const max = Math.max(...vals) * 1.05 || 1;
  const x = (i) => padL + (i / (points.length - 1)) * (W - padL - padR);
  const y = (v) => padT + (1 - (v - min) / (max - min || 1)) * (H - padT - padB);

  const line = points.map((p, i) => `${x(i)},${y(p.value)}`).join(' ');
  const area = `M${x(0)},${y(points[0].value)} ` +
    points.map((p, i) => `L${x(i)},${y(p.value)}`).join(' ') +
    ` L${x(points.length - 1)},${H - padB} L${x(0)},${H - padB} Z`;

  const onMove = (e) => {
    const r = e.currentTarget.getBoundingClientRect();
    const px = ((e.clientX - r.left) / r.width) * W;
    const i = Math.round(((px - padL) / (W - padL - padR)) * (points.length - 1));
    setHover(i >= 0 && i < points.length ? i : null);
  };

  return (
    <svg className="plot" viewBox={`0 0 ${W} ${H}`} onMouseMove={onMove}
         onMouseLeave={() => setHover(null)} role="img"
         aria-label={label || 'Trend over time'}>
      {[0, 0.5, 1].map((t) => (
        <line key={t} className="gridline" x1={padL} x2={W - padR}
              y1={padT + t * (H - padT - padB)} y2={padT + t * (H - padT - padB)} />
      ))}
      <text className="axis" x="0" y={padT + 4}>{format(max)}</text>
      <text className="axis" x="0" y={H - padB}>{format(min)}</text>
      <path className="area" d={area} />
      <polyline className="line" points={line} />
      <circle className="end" cx={x(points.length - 1)} cy={y(points[points.length - 1].value)} r="4" />
      {hover != null && (
        <g>
          <line className="gridline" x1={x(hover)} x2={x(hover)} y1={padT} y2={H - padB}
                strokeDasharray="3 3" />
          <circle cx={x(hover)} cy={y(points[hover].value)} r="4" fill="var(--navy)" />
          <text className="lab" x={Math.min(x(hover) + 6, W - 90)} y={Math.max(y(points[hover].value) - 8, 14)}>
            {format(points[hover].value)} · {points[hover].date}
          </text>
        </g>
      )}
    </svg>
  );
};

/** Data loading, with the three states every screen owes the reader. */
export function useApi(path, deps = []) {
  const [state, setState] = useState({ loading: true, data: null, error: null });
  const [nonce, setNonce] = useState(0);

  useEffect(() => {
    const ctrl = new AbortController();
    let live = true;
    setState((s) => ({ ...s, loading: true, error: null }));
    api(path, { signal: ctrl.signal })
      .then((data) => live && setState({ loading: false, data, error: null }))
      .catch((error) => {
        if (error.name === 'AbortError' || !live) return;
        setState({ loading: false, data: null, error });
      });
    return () => { live = false; ctrl.abort(); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [path, nonce, ...deps]);

  return { ...state, reload: () => setNonce((n) => n + 1) };
}
