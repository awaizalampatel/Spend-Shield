/**
 * What-if simulator. Test a decision before committing to it.
 *
 * Two kinds of lever, kept visually and arithmetically apart: navy levers are
 * ACTIONS you could fund, grey levers are ASSUMPTIONS you could be wrong about.
 * Mixing them would let someone "reduce" risk by editing a belief, so the result
 * attributes the movement to each separately.
 *
 * Nothing is written. The computation runs server-side against the real finding
 * set through the same evaluator the dashboard uses.
 */
import { useEffect, useState } from 'react';
import { TopBar } from '../components/Shell';
import { Card, Kpi, Money, Loading, ErrorBox } from '../components/ui';
import { api, rupees } from '../api';

const CONTROLS = [
  ['mfa', 'Multi-factor authentication'],
  ['segmentation', 'Network segmentation'],
  ['edr', 'Endpoint detection'],
  ['waf', 'Web application firewall'],
  ['patch', 'Patch management'],
];

export default function Simulator() {
  const [levers, setLevers] = useState({ mfa: 0, segmentation: 0, edr: 0, waf: 0, patch: 0 });
  const [revenue, setRevenue] = useState(0);
  const [state, setState] = useState({ loading: true, data: null, error: null });

  useEffect(() => {
    const t = setTimeout(() => {
      const controls = {};
      const deploy = {};
      for (const [k] of CONTROLS) {
        if (levers[k] > 0) {
          controls[k] = levers[k];
          deploy[k] = ['all'];
        }
      }
      const bodyPayload = { controls, deploy };
      if (revenue > 0) bodyPayload.assumptions = { revenue_per_hour: revenue };

      setState((s) => ({ ...s, loading: true }));
      api('simulate.php', { method: 'POST', body: bodyPayload })
        .then((data) => setState({ loading: false, data, error: null }))
        .catch((error) => setState({ loading: false, data: null, error }));
    }, 250); // debounce — every keystroke is a full server-side re-evaluation
    return () => clearTimeout(t);
  }, [levers, revenue]);

  const { data, loading, error } = state;
  const dirty = Object.values(levers).some((v) => v > 0) || revenue > 0;

  return (
    <>
      <TopBar title="What-if simulator"
              sub={dirty ? 'Unsaved scenario' : 'Move a lever to test a decision'}
              actions={<button className="btn" onClick={() => { setLevers({ mfa: 0, segmentation: 0, edr: 0, waf: 0, patch: 0 }); setRevenue(0); }}>Reset</button>} />

      <div className="page">
        <div className="row r-1-2">
          <Card title="Levers" extra="navy = action · grey = assumption">
            {CONTROLS.map(([key, label]) => (
              <div key={key}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11.5 }}>
                  <span>{label}</span>
                  <span className="mono">
                    {levers[key] > 0 ? levers[key].toFixed(2) : 'unchanged'}
                  </span>
                </div>
                <input type="range" min="0" max="0.95" step="0.05" value={levers[key]}
                       aria-label={`${label} effectiveness`}
                       onChange={(e) => setLevers({ ...levers, [key]: Number(e.target.value) })} />
              </div>
            ))}

            <div style={{ borderTop: '1px solid var(--line-soft)', paddingTop: 10, marginTop: 4 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11.5 }}>
                <span style={{ color: 'var(--ink-3)' }}>Revenue per hour (assumption)</span>
                <span className="mono">{revenue > 0 ? `₹${(revenue / 100000).toFixed(1)} L` : 'unchanged'}</span>
              </div>
              <input type="range" min="0" max="5000000" step="100000" value={revenue}
                     aria-label="Revenue per hour"
                     onChange={(e) => setRevenue(Number(e.target.value))}
                     style={{ accentColor: 'var(--med)' }} />
              <div className="cx">
                Moving this tests the model, not a plan. Risk that falls because you
                changed a belief has not actually fallen.
              </div>
            </div>
          </Card>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {error && <ErrorBox error={error} />}
            {loading && !data && <Loading rows={4} />}
            {data && (
              <>
                <div className="row r2">
                  <Kpi label="Today" small value={rupees(data.baseline)} caption="annualized" />
                  <Kpi label="In this scenario" small value={rupees(data.result)}
                       caption={`removes ${rupees(data.removed)}`}
                       delta={data.percent > 0 ? `−${data.percent}%` : '—'} deltaDir="dn" />
                </div>

                <Card title="What moved it">
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12 }}>
                    <span>From actions you could fund</span>
                    <b className="num" style={{ color: 'var(--good)' }}>{rupees(data.attribution.from_actions)}</b>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12 }}>
                    <span style={{ color: 'var(--ink-3)' }}>From changed assumptions</span>
                    <b className="num" style={{ color: 'var(--ink-3)' }}>{rupees(data.attribution.from_assumptions)}</b>
                  </div>
                  <div className="cx">{data.attribution.note}</div>
                </Card>

                <Card title="Remaining exposure by asset">
                  <div className="scrollx">
                    <table className="tbl">
                      <thead><tr><th>Asset</th><th className="n">Exposure</th></tr></thead>
                      <tbody>
                        {data.by_asset.slice(0, 8).map((r) => (
                          <tr key={r.asset}>
                            <td>{r.asset}</td>
                            <td className="n"><Money m={r.exposure} /></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </Card>
              </>
            )}
          </div>
        </div>
      </div>
    </>
  );
}
