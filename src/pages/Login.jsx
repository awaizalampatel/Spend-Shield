/**
 * Sign in. A security product's login screen is a credibility test, so: the form
 * at a comfortable width, the product's actual claim beside it, and never a
 * stock photograph.
 */
import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Mark } from '../components/ui';
import { login } from '../api';

export default function Login({ onSignedIn }) {
  const [email, setEmail] = useState('awaiz@acme.co.in');
  const [password, setPassword] = useState('');
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);
  const navigate = useNavigate();

  const submit = async (e) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const user = await login(email.trim(), password);
      onSignedIn?.(user);
      navigate('/dashboard', { replace: true });
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="login">
      <form className="form" onSubmit={submit}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 4 }}>
          <Mark size={30} />
          <b style={{ fontSize: 20, letterSpacing: '-.02em' }}>
            Spend<span style={{ color: 'var(--navy)' }}>Shield</span>
          </b>
        </div>
        <div style={{ fontSize: 17, fontWeight: 600 }}>Sign in</div>

        {error && <div className="err">{error}</div>}

        <div className="field">
          <label htmlFor="email">Work email</label>
          <input id="email" type="email" autoComplete="username" required
                 value={email} onChange={(e) => setEmail(e.target.value)} />
        </div>
        <div className="field">
          <label htmlFor="password">Password</label>
          <input id="password" type="password" autoComplete="current-password" required
                 value={password} onChange={(e) => setPassword(e.target.value)} />
        </div>

        <button className="btn pri" type="submit" disabled={busy} style={{ padding: 9 }}>
          {busy ? 'Signing in…' : 'Continue'}
        </button>

        <div className="cx">
          Demo tenant · <span className="mono">awaiz@acme.co.in</span> / <span className="mono">spendshield-demo</span>
          <br />Also priya@ (owner), cfo-office@ (executive), ops@ (viewer).
        </div>
      </form>

      <aside className="aside">
        <span className="chip nav">Continuous cyber risk quantification</span>
        <div style={{ fontSize: 20, fontWeight: 600, lineHeight: 1.25, letterSpacing: '-.02em' }}>
          You have 1,284 vulnerabilities.<br />Which ones cost you money?
        </div>
        <div className="cx" style={{ fontSize: 12.5, lineHeight: 1.6 }}>
          Exposure is recalculated the moment a CVE you own lands in the CISA KEV catalog.
          Every figure carries the evidence behind it — CVSS from NVD, exploitation
          probability from FIRST EPSS, exploited-in-the-wild status from CISA.
        </div>
      </aside>
    </div>
  );
}
