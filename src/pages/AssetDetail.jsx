/**
 * One system's whole story: what it is, what it is worth, what is wrong with it,
 * and what protects it today.
 */
import { Link, useParams } from 'react-router-dom';
import { TopBar } from '../components/Shell';
import { Card, Kpi, Money, Severity, Bar, Plot, Loading, ErrorBox, useApi } from '../components/ui';
import { rupees } from '../api';

const lakh = (v) => `₹${(v / 100000).toFixed(1)} L`;

export default function AssetDetail() {
  const { id } = useParams();
  const { data, loading, error, reload } = useApi(`assets.php?id=${encodeURIComponent(id)}`);

  if (loading) return <><TopBar title="Asset" /><div className="page"><Loading rows={6} /></div></>;
  if (error) return <><TopBar title="Asset" /><div className="page"><ErrorBox error={error} retry={reload} /></div></>;

  const { asset, controls, findings, history } = data;

  return (
    <>
      <TopBar title={asset.hostname}
              sub={`${asset.ip} · ${asset.os} · ${asset.owner} · ${asset.environment}`} />
      <div className="page">
        {asset.scan_stale && (
          <div className="banner"><span className="bar" />
            <div><b>This asset has not been scanned recently.</b>{' '}
              <span className="cx">Its exposure figure reflects what was last seen, not what is true now.</span></div>
          </div>
        )}

        <div className="row r4">
          <Kpi label="Total exposure" small value={rupees(asset.exposure)}
               caption={`${findings.length} open findings`} />
          <Kpi label="Criticality" small value={asset.criticality.toFixed(2)}
               caption={asset.crown_jewel ? 'crown jewel' : 'standard system'} />
          <Kpi label="Records held" small value={asset.pii_records.toLocaleString('en-IN')}
               caption={asset.pii_records > 0 ? 'carries breach cost' : 'no confidentiality loss'} />
          <Kpi label="Reachability" small value={asset.internet_facing ? 'Internet' : 'Internal'}
               caption={asset.internet_facing ? 'reachable from outside' : 'behind the perimeter'} />
        </div>

        <div className="row r2">
          <Card title="Controls on this asset" extra="claimed vs observed">
            {controls.length === 0 && <div className="cx">No controls are deployed here.</div>}
            {controls.map((c) => (
              <div key={c.key}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11.5 }}>
                  <span>{c.name}</span>
                  <span className="mono">
                    {c.observed != null ? c.observed.toFixed(2) : `${c.claimed.toFixed(2)} claimed`}
                  </span>
                </div>
                <Bar value={c.observed ?? c.claimed}
                     color={c.observed != null && c.observed < c.claimed - 0.15 ? 'var(--high)' : 'var(--navy)'} />
                {c.observed != null && c.observed < c.claimed - 0.15 && (
                  <div className="cx">
                    Vendor claims {c.claimed.toFixed(2)}; telemetry says {c.observed.toFixed(2)}.
                    The score uses the observed figure.
                  </div>
                )}
              </div>
            ))}
          </Card>

          <Card title="Exposure history" extra="from the score record">
            <Plot points={history} height={92} format={lakh} label="Exposure on this asset over time" />
          </Card>
        </div>

        <Card title="Open findings" extra={`${findings.length} · sorted by loss`}>
          <div className="scrollx">
            <table className="tbl">
              <thead>
                <tr><th>Finding</th><th>Sev</th><th className="n">EPSS</th>
                    <th className="n">Age</th><th className="n">Loss / yr</th></tr>
              </thead>
              <tbody>
                {findings.map((f) => (
                  <tr key={f.id}>
                    <td>
                      <Link to={`/findings/${f.id}`}><b>{(f.title || f.ref).slice(0, 56)}</b></Link>
                      <br /><span className="mono cx">{f.ref}</span>
                      {f.kev && <> <span className="chip crit"><i className="sq" />KEV</span></>}
                    </td>
                    <td><Severity level={f.severity} short /></td>
                    <td className="n">{f.epss != null ? f.epss.toFixed(3) : '—'}</td>
                    <td className="n">{f.age_days}d</td>
                    <td className="n"><Money m={f.loss} /></td>
                  </tr>
                ))}
                {findings.length === 0 && (
                  <tr><td colSpan={5} className="cx">Nothing open on this asset.</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </Card>
      </div>
    </>
  );
}
