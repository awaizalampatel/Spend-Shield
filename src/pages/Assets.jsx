/**
 * The estate, priced. "Unscanned" reads as exposure UNKNOWN, never as zero — a
 * gap in coverage that renders as a low number is the most dangerous thing a
 * risk tool can do.
 */
import { Link, useNavigate } from 'react-router-dom';
import { TopBar } from '../components/Shell';
import { Card, Kpi, Money, Loading, ErrorBox, useApi } from '../components/ui';
import { rupees } from '../api';

export default function Assets() {
  const { data, loading, error, reload } = useApi('assets.php');
  const navigate = useNavigate();

  return (
    <>
      <TopBar title="Assets"
              sub={data ? `${data.summary.assets} discovered · ${data.summary.crown_jewels} crown jewels` : 'Loading…'} />
      <div className="page">
        {loading && <Loading rows={7} />}
        {error && <ErrorBox error={error} retry={reload} />}
        {data && (
          <>
            <div className="row r4">
              <Kpi label="Crown jewels" small value={data.summary.crown_jewels}
                   caption={`${rupees(data.summary.crown_exposure)} of exposure`} />
              <Kpi label="Internet-facing" small value={data.summary.internet_facing}
                   caption={`${Math.round(data.summary.internet_facing / data.summary.assets * 100)}% of the estate`} />
              <Kpi label="Unscanned > 30 d" small value={data.summary.unscanned_30d}
                   caption={data.summary.unscanned_note} />
              <Kpi label="Assets" small value={data.summary.assets} caption="under management" />
            </div>

            <Card>
              <div className="scrollx">
                <table className="tbl">
                  <thead>
                    <tr><th>Asset</th><th>Class</th><th>Owner</th><th className="n">Findings</th>
                        <th>Last scan</th><th className="n">Exposure</th></tr>
                  </thead>
                  <tbody>
                    {data.assets.map((a) => (
                      <tr key={a.id} className="clickable" onClick={() => navigate(`/assets/${a.id}`)}>
                        <td>
                          <Link to={`/assets/${a.id}`} onClick={(e) => e.stopPropagation()}><b>{a.hostname}</b></Link>
                          <br /><span className="cx">{a.ip} · {a.os}</span>
                        </td>
                        <td>
                          {a.class}
                          {a.crown_jewel && <> <span className="chip nav">Crown</span></>}
                          {a.internet_facing && <><br /><span className="cx">internet-facing</span></>}
                        </td>
                        <td className="cx">{a.owner}</td>
                        <td className="n">
                          {a.critical > 0 && <span className="chip crit"><i className="sq" />{a.critical}</span>}{' '}
                          {a.high > 0 && <span className="chip high"><i className="sq" />{a.high}</span>}
                          {a.open_findings === 0 && <span className="cx">none</span>}
                        </td>
                        <td className="cx" style={a.scan_stale ? { color: 'var(--high)' } : undefined}>
                          {a.last_scan ? String(a.last_scan).slice(0, 10) : 'never'}
                        </td>
                        <td className="n"><Money m={a.exposure} /></td>
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
