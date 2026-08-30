/**
 * The CFO's page. Where the money figures come from, what assumptions produced
 * them, and how sensitive the total is to each.
 *
 * Drivers are computed by actually re-running the model with each channel muted,
 * not by apportioning the total — apportioning would only tell the reader what
 * we already assumed.
 */
import { TopBar } from '../components/Shell';
import { Card, Kpi, Money, Bar, Loading, ErrorBox, useApi } from '../components/ui';
import { rupees } from '../api';

export default function Exposure() {
  const { data, loading, error, reload } = useApi('exposure.php');

  if (loading) return <><TopBar title="Financial exposure" /><div className="page"><Loading rows={6} /></div></>;
  if (error) return <><TopBar title="Financial exposure" /><div className="page"><ErrorBox error={error} retry={reload} /></div></>;

  const a = data.assumptions;
  const maxDriver = Math.max(...data.drivers.map((d) => d.value.value), 1);

  return (
    <>
      <TopBar title="Financial exposure"
              sub={`Annualized loss expectancy · loss model v${a.version}`} />
      <div className="page">
        <div className="row r-1-2">
          <Kpi label="Annualized loss expectancy"
               value={rupees(data.total)}
               caption={`${rupees(data.band.min)} — ${rupees(data.band.max)}`} />

          <Card title="What drives the total" extra="each channel muted and re-run">
            {data.drivers.map((d) => (
              <div key={d.driver}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11.5 }}>
                  <span>{d.label}</span>
                  <span className="mono">{rupees(d.value)} · {d.share}%</span>
                </div>
                <Bar value={d.value.value / maxDriver} />
              </div>
            ))}
            <div className="cx">{data.band.note}</div>
          </Card>
        </div>

        <Card title="Assumptions in force" extra="every one is owned by you, and versioned">
          <div className="row r4" style={{ gap: 10 }}>
            <div><div className="cx">Revenue per hour</div><div className="num">{rupees(a.revenue_per_hour)}</div></div>
            <div><div className="cx">Median recovery</div><div className="num">{a.median_recovery_hours} h</div></div>
            <div><div className="cx">Records held</div><div className="num">{a.pii_records.toLocaleString('en-IN')}</div></div>
            <div><div className="cx">Cost per record</div><div className="num">{rupees(a.cost_per_record)}</div></div>
            <div><div className="cx">Penalty band</div><div className="num" style={{ fontSize: 13 }}>{a.penalty_band}</div></div>
            <div><div className="cx">Penalty cap</div><div className="num">{rupees(a.penalty_cap)}</div></div>
            <div><div className="cx">Ransom / recovery</div><div className="num">{rupees(a.ransom_recovery_cost)}</div></div>
            <div><div className="cx">Reputational</div><div className="num">{rupees(a.reputational_cost)}</div></div>
          </div>
          {a.note && <div className="cx">{a.note}</div>}
        </Card>

        <Card title="Where it sits" extra="top assets by exposure">
          <div className="scrollx">
            <table className="tbl">
              <thead><tr><th>Asset</th><th className="n">Exposure</th></tr></thead>
              <tbody>
                {data.by_asset.map((r) => (
                  <tr key={r.asset}>
                    <td><b>{r.asset}</b></td>
                    <td className="n"><Money m={r.exposure} /></td>
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
