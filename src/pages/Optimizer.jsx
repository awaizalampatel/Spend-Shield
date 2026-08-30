/**
 * Investment optimizer. One input, one output: give it a budget, it returns the
 * exact set of fixes that removes the most exposure inside it.
 *
 * Rejected options are shown with their reasons. An optimizer that displays only
 * its picks is a black box; the near-misses are what make the pick believable.
 */
import { useState } from 'react';
import { TopBar } from '../components/Shell';
import { Card, Kpi, Loading, ErrorBox, useApi } from '../components/ui';
import { rupees } from '../api';

const PRESETS = [500000, 1000000, 1800000, 3000000, 5000000];

export default function Optimizer() {
  const [budget, setBudget] = useState(1800000);
  const [applied, setApplied] = useState(1800000);
  const { data, loading, error, reload } = useApi(`optimizer.php?budget=${applied}`);

  return (
    <>
      <TopBar
        title="Investment optimizer"
        sub={data
          ? `${data.options_considered} options · solved in ${data.solved_ms}ms`
          : 'Solving…'}
        actions={<>
          <input type="number" value={budget} step={50000} min={0}
                 onChange={(e) => setBudget(Number(e.target.value))}
                 style={{ border: '1px solid var(--line)', background: 'var(--surface-2)',
                          color: 'var(--ink)', padding: '6px 10px', borderRadius: 4,
                          fontFamily: '"IBM Plex Mono", monospace', width: 130, fontSize: 12 }} />
          <button className="btn pri" onClick={() => setApplied(budget)}>Solve</button>
        </>}
      />

      <div className="page">
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
          <span className="cx">Budget</span>
          {PRESETS.map((p) => (
            <button key={p} type="button"
                    className={`chip ${applied === p ? 'active' : ''}`}
                    onClick={() => { setBudget(p); setApplied(p); }}>
              ₹{(p / 100000).toFixed(0)} L
            </button>
          ))}
        </div>

        {loading && <Loading rows={6} />}
        {error && <ErrorBox error={error} retry={reload} />}

        {data && (
          <>
            <div className="row r4">
              <Kpi label="Budget" small value={rupees(data.budget)}
                   caption={`${rupees(data.allocated)} allocated · ${rupees(data.unspent)} unspent`} />
              <Kpi label="Exposure removed" small value={rupees(data.removed)}
                   caption={`of ${rupees(data.baseline)}`}
                   delta={`−${data.percent}%`} deltaDir="dn" />
              <Kpi label="Return" small
                   value={data.return_per_rupee != null ? `₹${data.return_per_rupee}` : '—'}
                   caption="exposure removed per rupee spent" />
              <Kpi label="Fixes selected" small value={data.selected.length}
                   caption={`of ${data.options_considered} considered`} />
            </div>

            {data.overlap?.value > 0 && (
              <div className="banner info">
                <span className="bar" />
                <div>
                  <b>These fixes overlap by {rupees(data.overlap)}.</b>{' '}
                  <span className="cx">
                    Some cover the same findings, so their individual values do not add up.
                    The {rupees(data.removed)} above is the joint value of the whole set, not the sum of its parts.
                  </span>
                </div>
              </div>
            )}

            <Card title="Selected plan" extra="knapsack-optimal within the budget">
              <div className="scrollx">
                <table className="tbl">
                  <thead>
                    <tr><th>Remediation</th><th className="n">Covers</th><th className="n">Cost</th>
                        <th className="n">Removes</th><th className="n">Return</th></tr>
                  </thead>
                  <tbody>
                    {data.selected.map((s) => (
                      <tr key={s.id}>
                        <td><b>{s.name}</b>{s.description && <><br /><span className="cx">{s.description}</span></>}</td>
                        <td className="n">{s.covers}</td>
                        <td className="n">{rupees(s.cost)}</td>
                        <td className="n" style={{ color: 'var(--good)' }}>{rupees(s.removes)}</td>
                        <td className="n">{s.ratio > 1000 ? `${Math.round(s.ratio)}×` : `${s.ratio.toFixed(1)}×`}</td>
                      </tr>
                    ))}
                    {data.selected.length === 0 && (
                      <tr><td colSpan={5} className="cx">Nothing fits this budget.</td></tr>
                    )}
                  </tbody>
                </table>
              </div>
            </Card>

            <Card title="Not selected" extra="and why">
              <div className="scrollx">
                <table className="tbl">
                  <thead>
                    <tr><th>Remediation</th><th className="n">Cost</th>
                        <th className="n">Would remove</th><th>Reason</th></tr>
                  </thead>
                  <tbody>
                    {data.rejected.slice(0, 8).map((s) => (
                      <tr key={s.id} style={{ opacity: .75 }}>
                        <td>{s.name}</td>
                        <td className="n">{rupees(s.cost)}</td>
                        <td className="n">{rupees(s.removes)}</td>
                        <td className="cx">{s.reason}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Card>
          </>
        )}
      </div>
    </>
  );
}
