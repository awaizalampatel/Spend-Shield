/**
 * The risk agent registry.
 *
 * This page exists because it is the visible proof that the platform builds and
 * grades its own specialists rather than claiming to. Every agent here was
 * created by a finding arriving — nobody wrote this list.
 */
import { Link } from 'react-router-dom';
import { TopBar } from '../components/Shell';
import { Card, Kpi, Bar, Loading, ErrorBox, useApi } from '../components/ui';

const usd = (v) => (v >= 0.01 ? `$${v.toFixed(4)}` : `$${v.toFixed(6)}`);

const statusChip = (s) => {
  const map = { active: 'ok', canary: 'nav', deprecated: '', retired: '' };
  return <span className={`chip ${map[s] ?? ''}`}>{s}</span>;
};

export default function Agents() {
  const { data, loading, error, reload } = useApi('agents.php');

  if (loading) return <><TopBar title="Risk agents" /><div className="page"><Loading rows={7} /></div></>;
  if (error) return <><TopBar title="Risk agents" /><div className="page"><ErrorBox error={error} retry={reload} /></div></>;

  const s = data.summary;

  return (
    <>
      <TopBar
        title="Risk agents"
        sub={`${s.control_agents} control · ${s.task_agents} created by findings · ${s.merged} merged away`}
        actions={<button className="btn" onClick={reload}>Refresh</button>}
      />

      <div className="page">
        {data.notice && (
          <div className="banner info">
            <span className="bar" />
            <div><b>Running without semantic matching.</b> <span className="cx">{data.notice}</span></div>
          </div>
        )}

        <div className="row r4">
          <Kpi label="Assessments reused" small value={`${s.reuse_rate}%`}
               caption={`${s.assessments} assessments recorded`} />
          <Kpi label="Cost avoided" small value={usd(s.saved_usd)}
               caption={`vs writing every assessment fresh`} />
          <Kpi label="Spent" small value={usd(s.spent_usd)}
               caption="every model call, measured not estimated" />
          <Kpi label="Roster" small value={s.task_agents}
               caption={`${s.active} active · ${s.canary} canary · ${s.deprecated} deprecated`} />
        </div>

        <Card title="What reuse is worth" extra="from the experience log">
          <div className="scrollx">
            <table className="tbl">
              <thead>
                <tr><th>Path</th><th className="n">Assessments</th><th className="n">Avg latency</th>
                    <th className="n">Cost</th><th>What it means</th></tr>
              </thead>
              <tbody>
                {[
                  ['fresh', 'A model wrote a new assessment'],
                  ['exact', 'Same finding shape — replayed, no API call at all'],
                  ['semantic', 'Equivalent shape, matched by meaning'],
                ].map(([k, meaning]) => {
                  const r = s.by_reuse[k];
                  return (
                    <tr key={k}>
                      <td><b>{k}</b></td>
                      <td className="n">{r?.count ?? 0}</td>
                      <td className="n">{r ? `${r.avg_ms} ms` : '—'}</td>
                      <td className="n">{r ? usd(r.cost) : '—'}</td>
                      <td className="cx">{meaning}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          <div className="cx">
            The warehouse holds {data.warehouse.entries} written assessments, replayed{' '}
            {data.warehouse.replays} times.
          </div>
        </Card>

        <Card title="Agents created by findings" extra={`${data.agents.length} on the roster`}>
          <div className="row r3">
            {data.agents.map((a) => (
              <div key={a.key} className="card alt" style={{ background: 'var(--surface-2)' }}>
                <div className="ch">
                  <Link to={`/agents/${encodeURIComponent(a.key)}`}
                        style={{ fontWeight: 600, fontSize: 13 }}>{a.name}</Link>
                  {statusChip(a.status)}
                </div>
                <div className="cx mono">{a.key}</div>
                <div className="cx">{a.description}</div>
                {a.quality != null && (
                  <>
                    <Bar value={a.quality / 10} />
                    <div className="cx">Quality {a.quality.toFixed(1)} / 10</div>
                  </>
                )}
                <div style={{ display: 'flex', justifyContent: 'space-between' }} className="cx">
                  <span>{a.uses} uses · {a.reuse_rate}% reused</span>
                  <span className="mono">{usd(a.cost_usd)}</span>
                </div>
                <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap' }}>
                  <span className="chip">{a.lane}</span>
                  {a.subject && <span className="chip nav">{a.subject}</span>}
                </div>
              </div>
            ))}
          </div>
        </Card>

        {data.merged.length > 0 && (
          <Card title="Merged away" extra="duplicate jobs collapsed onto one agent">
            <div className="scrollx">
              <table className="tbl">
                <thead><tr><th>Merged agent</th><th>Survivor</th><th className="n">Uses moved</th></tr></thead>
                <tbody>
                  {data.merged.map((m) => (
                    <tr key={m.key}>
                      <td className="mono">{m.key}<br /><span className="cx">{m.name}</span></td>
                      <td className="mono">
                        <Link to={`/agents/${encodeURIComponent(m.into)}`}>{m.into}</Link>
                      </td>
                      <td className="n">{m.uses}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="cx">
              A merge requires the same technology family, not just a similar name —
              similarity alone once merged MOVEit into Log4j.
            </div>
          </Card>
        )}

        <Card title="Control plane" extra="fixed agents — these are the pipeline itself">
          <div className="row r3">
            {data.control_plane.map((a) => (
              <div key={a.key} style={{ borderLeft: '2px solid var(--navy)', paddingLeft: 10 }}>
                <div style={{ fontWeight: 600, fontSize: 12.5 }}>{a.name}</div>
                <div className="cx">{a.description}</div>
              </div>
            ))}
          </div>
        </Card>
      </div>
    </>
  );
}
