/**
 * The page that keeps the model honest. Claimed effectiveness beside observed,
 * and what each control is worth in rupees — the argument for renewing it at
 * contract time, and a number nobody currently has.
 */
import { TopBar } from '../components/Shell';
import { Card, Money, Bar, Loading, ErrorBox, useApi } from '../components/ui';

export default function Controls() {
  const { data, loading, error, reload } = useApi('controls.php');

  return (
    <>
      <TopBar title="Controls"
              sub={data
                ? `${data.controls.length} deployed · ${data.underperforming.length} below their claim`
                : 'Loading…'} />
      <div className="page">
        {loading && <Loading rows={6} />}
        {error && <ErrorBox error={error} retry={reload} />}
        {data && (
          <>
            {data.underperforming.map((u) => (
              <div className="banner" key={u.key}>
                <span className="bar" />
                <div><b>{u.name} is underperforming.</b> <span className="cx">{u.message}</span></div>
              </div>
            ))}

            <Card title="Controls" extra="exposure reduced = what the estate would carry without it">
              <div className="scrollx">
                <table className="tbl">
                  <thead>
                    <tr><th>Control</th><th>Coverage</th><th className="n">Claimed</th>
                        <th className="n">Observed</th><th>Evidence</th><th className="n">Exposure reduced</th></tr>
                  </thead>
                  <tbody>
                    {data.controls.map((c) => (
                      <tr key={c.key}>
                        <td><b>{c.name}</b><br /><span className="cx">{c.vendor}</span></td>
                        <td>
                          <Bar value={c.coverage.percent / 100} width={64} />
                          <span className="cx">{c.coverage.assets} / {c.coverage.total} assets</span>
                        </td>
                        <td className="n">{c.claimed.toFixed(2)}</td>
                        <td className="n" style={c.gap >= 0.15 ? { color: 'var(--crit)' } : undefined}>
                          {c.observed != null ? c.observed.toFixed(2) : '—'}
                        </td>
                        <td className="cx">
                          {c.telemetry.observations > 0
                            ? `${c.telemetry.observations.toLocaleString('en-IN')} detections, ${c.telemetry.misses} misses`
                            : 'no telemetry yet'}
                        </td>
                        <td className="n"><Money m={c.exposure_reduced} /></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <div className="cx">{data.note}</div>
            </Card>
          </>
        )}
      </div>
    </>
  );
}
