/**
 * One agent's record: its instruction, what it has assessed, and the
 * assessments it wrote that are now being replayed for free.
 */
import { Link, useParams } from 'react-router-dom';
import { TopBar } from '../components/Shell';
import { Card, Kpi, Money, Bar, Loading, ErrorBox, useApi } from '../components/ui';

const usd = (v) => (v >= 0.01 ? `$${v.toFixed(4)}` : `$${v.toFixed(6)}`);

export default function AgentDetail() {
  const { key } = useParams();
  const { data, loading, error, reload } = useApi(`agents.php?key=${encodeURIComponent(key)}`);

  if (loading) return <><TopBar title="Agent" /><div className="page"><Loading rows={6} /></div></>;
  if (error) return <><TopBar title="Agent" /><div className="page"><ErrorBox error={error} retry={reload} /></div></>;

  const a = data.agent;

  return (
    <>
      <TopBar
        title={a.name}
        sub={<><span className="mono">{a.key}</span>{' · v'}{a.version}{' · '}{a.model || 'no model'}{' · created '}{String(a.created_at).slice(0, 10)}</>}
        actions={<Link to="/agents" className="btn">Back to roster</Link>}
      />

      <div className="page">
        <div className="row r4">
          <Kpi label="Status" small value={a.status}
               caption={a.origin === 'dynamic' ? 'created by a finding' : 'fixed control agent'} />
          <Kpi label="Uses" small value={a.uses}
               caption={`${a.reuse_rate}% served from reuse`} />
          <Kpi label="Quality" small value={a.quality != null ? a.quality.toFixed(1) : '—'}
               caption={a.quality != null ? 'rolling average' : 'not yet graded'} />
          <Kpi label="Cost" small value={usd(a.cost_usd)} caption="total, this agent" />
        </div>

        <div className="row r2">
          <Card title="Instruction" extra={`v${a.version}`}>
            <div className="mono" style={{
              fontSize: 11.5, lineHeight: 1.6, color: 'var(--ink-2)',
              background: 'var(--surface-2)', border: '1px solid var(--line)',
              padding: '10px 12px', borderRadius: 4,
            }}>
              {a.template || 'No template — this agent is part of the control plane.'}
            </div>
            <div className="cx">
              This is what shapes the agent's answers. Two agents assess their families
              differently because their instructions differ, not because the model does.
            </div>
          </Card>

          <Card title="What it owns">
            <div className="cx">{a.description}</div>
            <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap' }}>
              <span className="chip">{a.lane}</span>
              {a.subject && <span className="chip nav">family: {a.subject}</span>}
              <span className="chip">{a.tier}</span>
              {a.pinned && <span className="chip ok">pinned</span>}
            </div>
            {data.merged_in.length > 0 && (
              <>
                <div className="ct" style={{ marginTop: 6 }}>Absorbed</div>
                {data.merged_in.map((m) => (
                  <div key={m.key} className="cx mono">{m.key}</div>
                ))}
              </>
            )}
          </Card>
        </div>

        {data.written.length > 0 && (
          <Card title="Assessments it wrote" extra="stored once, replayed since">
            {data.written.map((w, i) => (
              <div key={i} style={{ borderTop: i ? '1px solid var(--line-soft)' : 'none', paddingTop: i ? 10 : 0 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', gap: 10 }}>
                  <span className="cx mono">{w.shape}</span>
                  <span className="chip nav">replayed {w.replays}×</span>
                </div>
                <div style={{ fontSize: 12.5, color: 'var(--ink-2)', marginTop: 6, maxWidth: '78ch' }}>
                  {w.narrative}
                </div>
              </div>
            ))}
          </Card>
        )}

        <Card title="Findings it assessed" extra={`${data.assessments.length} current`}>
          <div className="scrollx">
            <table className="tbl">
              <thead>
                <tr><th>Finding</th><th>Asset</th><th>Path</th>
                    <th className="n">Cost</th><th className="n">Annual loss</th></tr>
              </thead>
              <tbody>
                {data.assessments.map((r) => (
                  <tr key={r.finding_id}>
                    <td>
                      <Link to={`/findings/${r.finding_id}`}>
                        <b>{(r.title || r.ref).slice(0, 52)}</b>
                      </Link>
                      <br /><span className="mono cx">{r.ref}</span>
                    </td>
                    <td className="cx">{r.asset}</td>
                    <td>
                      <span className={`chip ${r.reuse === 'fresh' ? '' : 'nav'}`}>{r.reuse}</span>
                    </td>
                    <td className="n">{r.cost_usd > 0 ? usd(r.cost_usd) : '$0.00'}</td>
                    <td className="n"><Money m={r.loss} /></td>
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
