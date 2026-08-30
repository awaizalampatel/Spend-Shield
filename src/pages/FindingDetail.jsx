/**
 * Finding detail. Where the number has to defend itself.
 *
 * The factor table is never collapsed and never behind a tab. If a figure cannot
 * show severity × threat × criticality × exposure × control gap with a source on
 * every row, it must not be displayed as money.
 */
import { Link, useParams } from 'react-router-dom';
import { TopBar } from '../components/Shell';
import { Card, Kpi, Money, Severity, Bar, Loading, ErrorBox, useApi } from '../components/ui';
import { rupees } from '../api';

export default function FindingDetail() {
  const { id } = useParams();
  const { data, loading, error, reload } = useApi(`finding.php?id=${encodeURIComponent(id)}`);

  if (loading) return <><TopBar title="Finding" /><div className="page"><Loading rows={7} /></div></>;
  if (error) return <><TopBar title="Finding" /><div className="page"><ErrorBox error={error} retry={reload} /></div></>;

  const { finding, asset, score, factors, formula, controls, evidence, cheapest_fix: fix, siblings } = data;

  return (
    <>
      <TopBar
        title={finding.title || finding.ref}
        sub={<>
          <span className="mono">{finding.ref}</span>{' · '}
          <Link to={`/assets/${asset.id}`}>{asset.hostname}</Link>
          {' · assessed '}{score?.computed_at?.slice(0, 16) || 'not yet'}
        </>}
        actions={<>
          <button className="btn" disabled title="Lands with the workflow phase">Accept risk</button>
          <Link to="/optimizer" className="btn pri">Add to plan</Link>
        </>}
      />

      <div className="page">
        <div className="row r-2-1">
          <Card title="How this number was built"
                extra={score ? `loss model v${score.loss_model_version}` : ''}>
            <div className="scrollx">
              <table className="tbl">
                <thead>
                  <tr><th>Factor</th><th className="n">Value</th><th>Where it came from</th></tr>
                </thead>
                <tbody>
                  {factors.map((f) => (
                    <tr key={f.factor}>
                      <td><b>{f.factor}</b></td>
                      <td className="n">{f.value.toFixed(4)}</td>
                      <td className="cx">{f.source}</td>
                    </tr>
                  ))}
                  {score && (
                    <tr>
                      <td><b>Raw risk</b></td>
                      <td className="n">{score.raw_risk.toFixed(6)}</td>
                      <td className="cx">{formula}</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
            <div className="cx">
              Every factor is a probability between 0 and 1, and the raw risk is exactly
              their product. Nothing here involves a language model.
            </div>
          </Card>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {score && (
              <Kpi label="Annualized loss" small
                   value={rupees(score.loss)}
                   caption={`band ${rupees(score.band.min)} – ${rupees(score.band.max)} · confidence ${score.confidence.toFixed(2)}`} />
            )}
            <Card title="Assessed by">
              <div style={{ fontWeight: 600, fontSize: 13 }}>{score?.agent || '—'}</div>
              <div className="cx">
                {score?.reuse === 'fresh'
                  ? 'Scored fresh for this finding.'
                  : `Reused a prior assessment (${score?.reuse}) — this finding cost ₹0 to score.`}
              </div>
            </Card>
            {fix && (
              <Card title="Cheapest fix">
                <div style={{ fontWeight: 600, fontSize: 13 }}>{fix.name}</div>
                <div className="cx">{rupees(fix.cost)} · {fix.effort_days} days</div>
                <Bar value={score && score.loss.value > 0 ? fix.removes.value / score.loss.value : 0}
                     color="var(--good)" />
                <div className="cx">Removes {rupees(fix.removes)} of exposure</div>
              </Card>
            )}
          </div>
        </div>

        <div className="row r2">
          <Card title="Evidence" extra={`${evidence.length} sources`}>
            {evidence.map((e, i) => (
              <div key={i} className="cx" style={{ display: 'flex', gap: 8, alignItems: 'baseline' }}>
                <span className="chip nav">{e.source}</span>
                <span style={{ flex: 1 }}>
                  {e.detail}
                  {e.retrieved && <> <span style={{ opacity: .7 }}>· {String(e.retrieved).slice(0, 16)}</span></>}
                </span>
              </div>
            ))}
          </Card>

          <Card title="Controls on this asset" extra="observed effectiveness is what the score uses">
            {controls.length === 0 && <div className="cx">No controls are deployed on this asset.</div>}
            {controls.map((c) => (
              <div key={c.key}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11.5 }}>
                  <span>
                    {c.name}
                    {!c.applied && <span className="cx"> — cannot affect this weakness</span>}
                  </span>
                  <span className="mono">
                    {c.observed != null ? c.observed.toFixed(2) : c.claimed.toFixed(2)}
                    {c.observed != null && c.observed < c.claimed && (
                      <span className="cx"> (claims {c.claimed.toFixed(2)})</span>
                    )}
                  </span>
                </div>
                <Bar value={c.observed ?? c.claimed}
                     color={c.applied ? 'var(--navy)' : 'var(--line)'} />
              </div>
            ))}
          </Card>
        </div>

        <div className="row r2">
          <Card title="Impact channels" extra="from the CVSS vector">
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
              {Object.entries(finding.impacts).map(([k, v]) => (
                <span key={k} className={`chip ${v ? 'nav' : ''}`} style={v ? {} : { opacity: .55 }}>
                  {k}{v ? '' : ' — not affected'}
                </span>
              ))}
            </div>
            <div className="cx">
              A confidentiality-only weakness is never charged for production downtime,
              and an availability weakness never carries a data-protection penalty.
            </div>
          </Card>

          <Card title="Also on this asset" extra={`${siblings.length} open`}>
            {siblings.length === 0 && <div className="cx">Nothing else is open on {asset.hostname}.</div>}
            {siblings.map((s) => (
              <div key={s.id} style={{ display: 'flex', justifyContent: 'space-between', gap: 10, fontSize: 12 }}>
                <Link to={`/findings/${s.id}`}>{(s.title || s.ref).slice(0, 44)}</Link>
                <Money m={s.loss} />
              </div>
            ))}
            {siblings.length > 0 && (
              <div className="cx">
                These share one asset, so their losses are shares of that asset's
                expected loss — not separate losses that add up.
              </div>
            )}
          </Card>
        </div>
      </div>
    </>
  );
}
