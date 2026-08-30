/**
 * Risk register. Default sort is annualized loss, not CVSS — that single
 * default is the product's whole thesis expressed as a table order.
 *
 * Filter state lives in the URL so a filtered view can be pasted into a ticket.
 */
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { TopBar } from '../components/Shell';
import { Card, Money, Severity, Bar, Loading, ErrorBox, Empty, useApi } from '../components/ui';
import { rupees } from '../api';

const SEVERITIES = ['critical', 'high', 'medium', 'low'];
const SORTS = [['loss', 'Annualized loss'], ['cvss', 'CVSS'], ['epss', 'Exploitation probability'], ['age', 'Age']];

export default function Findings() {
  const [params, setParams] = useSearchParams();
  const navigate = useNavigate();

  const sort = params.get('sort') || 'loss';
  const severity = (params.get('severity') || '').split(',').filter(Boolean);
  const internet = params.get('exposure') === 'internet';
  const kev = params.get('kev') === '1';
  const crown = params.get('crown') === '1';

  const qs = new URLSearchParams({ sort, limit: '100' });
  if (severity.length) qs.set('severity', severity.join(','));
  if (internet) qs.set('exposure', 'internet');
  if (kev) qs.set('kev', '1');
  if (crown) qs.set('crown', '1');

  const { data, loading, error, reload } = useApi(`findings.php?${qs.toString()}`);

  const toggle = (key, value) => {
    const next = new URLSearchParams(params);
    if (key === 'severity') {
      const set = new Set(severity);
      set.has(value) ? set.delete(value) : set.add(value);
      set.size ? next.set('severity', [...set].join(',')) : next.delete('severity');
    } else if (next.get(key) === value) {
      next.delete(key);
    } else {
      next.set(key, value);
    }
    setParams(next, { replace: true });
  };

  const setSort = (s) => {
    const next = new URLSearchParams(params);
    next.set('sort', s);
    setParams(next, { replace: true });
  };

  return (
    <>
      <TopBar
        title="Findings"
        sub={data
          ? `${data.summary.matched} matching · ${rupees(data.summary.exposure)} of exposure`
          : 'Loading the register…'}
        actions={<Link to="/optimizer" className="btn pri">Send to optimizer</Link>}
      />

      <div className="page">
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
          {SEVERITIES.map((s) => (
            <button key={s} type="button"
                    className={`chip ${severity.includes(s) ? 'active' : ''}`}
                    onClick={() => toggle('severity', s)}>
              {s[0].toUpperCase() + s.slice(1)}
            </button>
          ))}
          <button type="button" className={`chip ${internet ? 'active' : ''}`}
                  onClick={() => toggle('exposure', 'internet')}>Internet-facing</button>
          <button type="button" className={`chip ${kev ? 'active' : ''}`}
                  onClick={() => toggle('kev', '1')}>Exploited in the wild</button>
          <button type="button" className={`chip ${crown ? 'active' : ''}`}
                  onClick={() => toggle('crown', '1')}>Crown jewels</button>

          <label className="cx" style={{ marginLeft: 'auto', display: 'flex', gap: 6, alignItems: 'center' }}>
            Sort by
            <select value={sort} onChange={(e) => setSort(e.target.value)}
                    style={{ border: '1px solid var(--line)', background: 'var(--surface-2)',
                             color: 'var(--ink)', borderRadius: 4, padding: '4px 6px', fontSize: 12 }}>
              {SORTS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
            </select>
          </label>
        </div>

        {loading && <Loading rows={8} />}
        {error && <ErrorBox error={error} retry={reload} />}

        {data && data.findings.length === 0 && (
          <Empty action={<button className="btn" onClick={() => setParams(new URLSearchParams({ sort }))}>Clear filters</button>}>
            No findings match these filters.
          </Empty>
        )}

        {data && data.findings.length > 0 && (
          <Card>
            <div className="scrollx">
              <table className="tbl">
                <thead>
                  <tr>
                    <th>Finding</th><th>Asset</th><th>Sev</th>
                    <th className="n">EPSS</th><th>Control gap</th><th className="n">Loss / yr</th>
                  </tr>
                </thead>
                <tbody>
                  {data.findings.map((f) => (
                    <tr key={f.id} className="clickable"
                        onClick={() => navigate(`/findings/${f.id}`)}>
                      <td>
                        <Link to={`/findings/${f.id}`} onClick={(e) => e.stopPropagation()}>
                          <b>{(f.title || f.ref).slice(0, 58)}</b>
                        </Link>
                        <br />
                        <span className="mono cx">{f.ref}</span>
                        {f.kev && <> <span className="chip crit"><i className="sq" />KEV</span></>}
                      </td>
                      <td>
                        {f.asset.hostname}
                        {f.asset.crown_jewel && <><br /><span className="cx">crown jewel</span></>}
                      </td>
                      <td><Severity level={f.severity} short /></td>
                      <td className="n">{f.epss != null ? f.epss.toFixed(3) : '—'}</td>
                      <td>
                        {f.control_gap != null ? (
                          <>
                            <Bar value={f.control_gap} width={56}
                                 color={f.control_gap > 0.6 ? 'var(--crit)' : 'var(--med)'} />
                            <span className="cx">{Math.round(f.control_gap * 100)}% open</span>
                          </>
                        ) : <span className="cx">—</span>}
                      </td>
                      <td className="n"><Money m={f.loss} band={f.band} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="cx">
              Showing {data.summary.returned} of {data.summary.matched}
              {' · sorted by '}<b style={{ color: 'var(--ink)' }}>{SORTS.find(([v]) => v === sort)?.[1]}</b>
            </div>
          </Card>
        )}
      </div>
    </>
  );
}
