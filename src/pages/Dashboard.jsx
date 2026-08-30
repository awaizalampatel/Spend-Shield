/**
 * Executive dashboard. Read by a CISO and a CFO looking at the same screen for
 * different reasons, so money comes first — it is the number they share — and
 * the technical breakdown sits below it.
 *
 * One API request, not six: the page is read as a single picture, and six
 * requests would put six different moments in time on one screen.
 */
import { Link } from 'react-router-dom';
import { TopBar } from '../components/Shell';
import { Card, Kpi, Money, Plot, Severity, Loading, ErrorBox, useApi } from '../components/ui';
import { rupees } from '../api';

const crore = (v) => `₹${(v / 10000000).toFixed(2)} Cr`;

export default function Dashboard() {
  const { data, loading, error, reload } = useApi('dashboard.php');

  if (loading) return <><TopBar title="Executive dashboard" /><div className="page"><Loading rows={6} /></div></>;
  if (error) return <><TopBar title="Executive dashboard" /><div className="page"><ErrorBox error={error} retry={reload} /></div></>;

  const { exposure, composition, coverage, unbudgeted, trend, top_findings: top, recommendation, feeds } = data;
  const staleFeed = feeds?.find((f) => f.status !== 'ok');

  return (
    <>
      <TopBar
        title="Executive dashboard"
        sub={`${data.tenant.name} · ${coverage.assets} assets · ${exposure.scored_findings} findings scored`}
        actions={<>
          <Link to="/optimizer" className="btn">Open optimizer</Link>
          <Link to="/exposure" className="btn pri">Where this comes from</Link>
        </>}
      />

      <div className="page">
        {staleFeed && (
          <div className="banner">
            <span className="bar" />
            <div><b>{staleFeed.feed.toUpperCase()} feed has not refreshed.</b>{' '}
              <span className="cx">Scores built on it are shown as current but may be stale.</span></div>
          </div>
        )}

        <div className="row r4">
          <Kpi label="Annualized exposure" small
               value={rupees(exposure.total)}
               caption={`band ${rupees(exposure.band.min)} – ${rupees(exposure.band.max)}`}
               delta={exposure.change_30d != null ? `${exposure.change_30d > 0 ? '+' : ''}${exposure.change_30d}%` : null}
               deltaDir={exposure.change_30d > 0 ? 'up' : 'dn'} />
          <Kpi label="Critical findings" small
               value={composition.counts.critical}
               caption={`of ${composition.total} open`} />
          <Kpi label="Crown jewels" small
               value={coverage.crown_jewels}
               caption="systems the business cannot run without" />
          <Kpi label="Unbudgeted risk" small
               value={rupees(unbudgeted)}
               caption="no funded remediation" />
        </div>

        <div className="row r-2-1">
          <Card title="Exposure over time" extra="annualized loss expectancy">
            <Plot points={trend} format={crore} label="Annualized exposure over time" />
            {data.annotations?.length > 0 && (
              <div className="cx">
                Latest change: <b style={{ color: 'var(--ink)' }}>{data.annotations[0].label}</b>
                {' — '}{data.annotations[0].note}
              </div>
            )}
          </Card>

          <Card title="Composition" extra={`${composition.total} findings`}>
            <div className="stack">
              {['critical', 'high', 'medium', 'low'].map((k) => {
                const pct = composition.total ? (composition.counts[k] / composition.total) * 100 : 0;
                const color = { critical: 'var(--crit)', high: 'var(--high)', medium: 'var(--med)', low: 'var(--low)' }[k];
                return pct > 0 ? <i key={k} style={{ background: color, width: `${pct}%` }} /> : null;
              })}
            </div>
            <div className="legend">
              {['critical', 'high', 'medium', 'low'].map((k) => (
                <span key={k}>
                  <i style={{ background: { critical: 'var(--crit)', high: 'var(--high)', medium: 'var(--med)', low: 'var(--low)' }[k] }} />
                  {k[0].toUpperCase() + k.slice(1)} {composition.counts[k]}
                </span>
              ))}
            </div>

            <div className="ch" style={{ marginTop: 6 }}><span className="ct">Scan coverage</span></div>
            <div className="track">
              <i style={{ background: coverage.percent >= 80 ? 'var(--navy)' : 'var(--high)', width: `${coverage.percent}%` }} />
            </div>
            <div className="cx">{coverage.scanned_7d} of {coverage.assets} assets scanned in the last 7 days</div>
          </Card>
        </div>

        {recommendation && (
          <Card title="Standing recommendation" extra={`run #${recommendation.run_id}`}>
            <div className="row r4" style={{ gap: 10 }}>
              <div><div className="cx">Budget</div><div className="num">{rupees(recommendation.budget)}</div></div>
              <div><div className="cx">Would allocate</div><div className="num">{rupees(recommendation.allocated)}</div></div>
              <div><div className="cx">Removes</div><div className="num" style={{ color: 'var(--good)' }}>{rupees(recommendation.removed)}</div></div>
              <div><div className="cx">Of total exposure</div><div className="num">{recommendation.percent}%</div></div>
            </div>
          </Card>
        )}

        <Card title="Where the money is" extra={`top ${top.length} of ${composition.total} · sorted by annualized loss`}>
          <div className="scrollx">
            <table className="tbl">
              <thead>
                <tr>
                  <th>Finding</th><th>Asset</th><th>Severity</th><th className="n">EPSS</th>
                  <th>Assessed by</th><th className="n">Annualized loss</th>
                </tr>
              </thead>
              <tbody>
                {top.map((f) => (
                  <tr key={f.id}>
                    <td>
                      <Link to={`/findings/${f.id}`}><b>{f.title?.slice(0, 52) || f.ref}</b></Link>
                      <br />
                      <span className="mono cx">{f.ref}</span>
                      {f.kev && <> <span className="chip crit"><i className="sq" />KEV</span></>}
                      {f.ransomware && <> <span className="chip crit"><i className="sq" />ransomware</span></>}
                    </td>
                    <td>
                      {f.asset}
                      {f.crown && <><br /><span className="cx">crown jewel</span></>}
                    </td>
                    <td><Severity level={f.severity} /></td>
                    <td className="n">{f.epss != null ? f.epss.toFixed(3) : '—'}</td>
                    <td className="mono cx">{f.agent}</td>
                    <td className="n"><Money m={f.loss} band={f.band} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      </div>
    </>
  );
}
