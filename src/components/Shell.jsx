/**
 * The frame behind every authenticated route: a navigation rail grouped by job,
 * and a topbar carrying the page title and its one primary action.
 *
 * The rail is grouped Posture / Money / Engine — what is true, what it costs and
 * what to do, and how the system decides. Routes an executive cannot reach are
 * hidden rather than shown-and-refused; the API still enforces it either way.
 */
import { NavLink, useNavigate } from 'react-router-dom';
import { Mark } from './ui';
import { logout, tokenStore } from '../api';

const GROUPS = [
  { label: 'Posture', items: [
    ['Dashboard', '/dashboard', ['owner', 'executive', 'analyst', 'viewer']],
    ['Findings', '/findings', ['owner', 'analyst', 'viewer']],
    ['Assets', '/assets', ['owner', 'analyst', 'viewer']],
    ['Controls', '/controls', ['owner', 'analyst', 'viewer']],
  ]},
  { label: 'Money', items: [
    ['Exposure', '/exposure', ['owner', 'executive', 'analyst', 'viewer']],
    ['Optimizer', '/optimizer', ['owner', 'executive', 'analyst', 'viewer']],
    ['Simulator', '/simulator', ['owner', 'executive', 'analyst']],
  ]},
  { label: 'Engine', items: [
    ['Risk agents', '/agents', ['owner', 'executive', 'analyst', 'viewer']],
    ['Monitoring', '/monitor', ['owner', 'executive', 'analyst', 'viewer']],
  ]},
];

export function Shell({ children }) {
  const navigate = useNavigate();
  const user = tokenStore.user();
  const role = user?.role || 'viewer';

  const signOut = async () => {
    await logout();
    navigate('/login', { replace: true });
  };

  return (
    <div className="shell">
      <aside className="rail">
        <div className="brand">
          <Mark size={20} />
          <b>Spend<span>Shield</span></b>
        </div>

        {GROUPS.map((g) => {
          const visible = g.items.filter(([, , roles]) => roles.includes(role));
          if (!visible.length) return null;
          return (
            <div className="navgroup" key={g.label}>
              <div className="gl">{g.label}</div>
              {visible.map(([label, to]) => (
                <NavLink key={to} to={to}
                         className={({ isActive }) => `navitem${isActive ? ' on' : ''}`}>
                  <i className="dot" />{label}
                </NavLink>
              ))}
            </div>
          );
        })}

        <div className="foot">
          {user?.tenant?.name}
          <br />
          <span className="mono" style={{ fontSize: 10 }}>
            {user?.name} · {role}
          </span>
          <br />
          <button onClick={signOut}>Sign out</button>
        </div>
      </aside>

      <div className="main">{children}</div>
    </div>
  );
}

export function TopBar({ title, sub, actions }) {
  return (
    <div className="topbar">
      <div>
        <h1>{title}</h1>
        {sub && <div className="sub">{sub}</div>}
      </div>
      {actions && <div className="tbactions">{actions}</div>}
    </div>
  );
}
