/**
 * Continuous monitoring. What changed, and what it cost.
 *
 * Feed health reports CONSEQUENCE, not status — "this data has not refreshed for
 * 30 hours, so scores built on it are stale" rather than a red dot. A status
 * without a consequence gets ignored.
 */
import { TopBar } from '../components/Shell';
import { Card, Kpi, Money, Loading, ErrorBox, useApi } from '../components/ui';
import { rupees } from '../api';

export default function Monitor() {
  const { data, loading, error, reload } = useApi('monitor.php');

  if (loading) return <><TopBar title="Monitoring" /><div className="page"><Loading rows={6} /></div></>;
  if (error) return <><TopBar title="Monitoring" /><div className="page"><ErrorBox error={error} retry={reload} /></div></>;

  return (
    <>
      <TopBar title="Monitoring"
              sub={`${data.headline.new_findings_24h} new findings in 24 h · ${data.headline.alerts} alerts`}
              actions={<button className="btn" onClick={reload}>Refresh</button>} />

      <div className="page">
        {data.alerts.map((a, i) => (
          <div className={`banner ${a.level === 'critical' ? '' : 'info'}`} key={i}>
            <span className="bar" />
            <div><b>{a.title}</b> <span className="cx">{a.detail}</span></div>
          </div>
        ))}

        <div className="row r4">
          {data.feeds.map((f) => (
            <Kpi key={f.feed}
                 label={f.feed.toUpperCase()}
                 small
                 value={f.age_hours < 1 ? 'just now' : `${Math.round(f.age_hours)} h ago`}
                 caption={f.consequence || `${f.records.toLocaleString('en-IN')} records · healthy`} />
          ))}
          <Kpi label="Exposure moved (24 h)" small value={rupees(data.headline.exposure_moved_24h)}
               caption="net, across every recorded change" />
        </div>

        <Card title="Activity" extra="every entry names the money it moved">
          <div className="scrollx">
            <table className="tbl">
              <thead>
                <tr><th>When</th><th>Actor</th><th>Event</th><th>Change</th><th className="n">Exposure moved</th></tr>
              </thead>
              <tbody>
                {data.activity.map((r, i) => (
                  <tr key={i}>
                    <td className="mono cx">{String(r.at).slice(5, 16)}</td>
                    <td className="cx">{r.actor}</td>
                    <td><b>{r.action}</b>{r.note && <><br /><span className="cx">{r.note}</span></>}</td>
                    <td className="mono cx">{r.change || '—'}</td>
                    <td className="n" style={{ color: r.effect?.value > 0 ? 'var(--crit)' : (r.effect?.value < 0 ? 'var(--good)' : undefined) }}>
                      {r.effect ? <Money m={r.effect} /> : '—'}
                    </td>
                  </tr>
                ))}
                {data.activity.length === 0 && (
                  <tr><td colSpan={5} className="cx">Nothing has changed in this window. That is a good state, not a broken one.</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </Card>
      </div>
    </>
  );
}
