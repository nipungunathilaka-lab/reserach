import { useEffect, useState } from 'react'
import { AlertTriangle, Blocks, FileCheck2, Inbox } from 'lucide-react'
import api, { apiError } from '../api/client'
import StatCard from '../components/StatCard'
import ErrorBanner from '../components/ErrorBanner'

export default function Dashboard() {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    api.get('/dashboard/summary')
      .then(res => setData(res.data))
      .catch(err => setError(apiError(err)))
      .finally(() => setLoading(false))
  }, [])

  if (loading) return <p className="text-slate-300">Loading dashboard...</p>

  return (
    <div className="grid gap-5 md:gap-6">
      <ErrorBanner message={error} />
      {data && <>
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          <StatCard icon={FileCheck2} label="Total transfers" value={data.total_transfers} helper="Visible within your authorization scope" />
          <StatCard icon={Inbox} label="Received files" value={data.received_files} helper="Ready for decrypt/download" />
          <StatCard icon={AlertTriangle} label="AI alerts" value={data.ai_alerts} helper="Transfer and MFA/login-pattern alerts" />
          <StatCard icon={Blocks} label="Blockchain status" value={data.blockchain_valid ? 'Valid' : 'Invalid'} helper={data.blockchain_status} />
        </div>
        <div className="grid gap-6 xl:grid-cols-2">
          <section className="rounded-2xl border border-white/10 bg-slate-900/40 p-6 shadow-xl backdrop-blur-md">
            <h3 className="text-xl font-bold tracking-tight text-white">Recent Activity</h3>
            <div className="mt-4 grid gap-3 md:hidden">
              {data.recent_activity.map(t => <article key={t.id} className="rounded-2xl border border-white/10 bg-white/5 p-4"><p className="truncate font-semibold">{t.file_name}</p><p className="mt-1 text-xs text-slate-400">{t.sender.full_name} → {t.receiver.full_name}</p><p className="mt-2 text-xs text-cyan-200">{t.status}</p></article>)}
              {!data.recent_activity.length && <p className="text-sm text-slate-400">No transfers yet.</p>}
            </div>
            <div className="mt-4 hidden overflow-x-auto rounded-xl border border-white/5 bg-slate-950/50 md:block">
              <table className="w-full text-left text-sm text-slate-300">
                <thead className="border-b border-white/10 bg-white/[0.02] text-slate-400">
                  <tr><th className="px-4 py-3 font-semibold">File</th><th className="px-4 py-3 font-semibold">Sender</th><th className="px-4 py-3 font-semibold">Receiver</th><th className="px-4 py-3 font-semibold">Status</th></tr>
                </thead>
                <tbody className="divide-y divide-white/5">
                  {data.recent_activity.map(t => <tr key={t.id} className="transition-colors hover:bg-white/[0.02]"><td className="px-4 py-3 font-medium text-white">{t.file_name}</td><td className="px-4 py-3">{t.sender.full_name}</td><td className="px-4 py-3">{t.receiver.full_name}</td><td className="px-4 py-3">{t.status}</td></tr>)}
                  {!data.recent_activity.length && <tr><td className="px-4 py-6 text-center text-slate-400" colSpan="4">No transfers yet.</td></tr>}
                </tbody>
              </table>
            </div>
          </section>
          <section className="rounded-2xl border border-white/10 bg-slate-900/40 p-6 shadow-xl backdrop-blur-md">
            <h3 className="text-xl font-bold tracking-tight text-white">Recent AI Alerts</h3>
            <div className="mt-4 grid gap-3">
              {data.recent_alerts.map(a => <div key={a.id} className="rounded-2xl border border-red-500/20 bg-red-500/10 p-4 shadow-[0_0_15px_rgba(239,68,68,0.1)] transition-all hover:bg-red-500/15"><p className="font-bold capitalize text-red-100">{a.level} risk · {a.transfer_id ? `Transfer #${a.transfer_id}` : 'Login/MFA event'}</p><p className="mt-1 text-sm text-red-100/80">{a.reason}</p></div>)}
              {!data.recent_alerts.length && <p className="rounded-xl border border-white/5 bg-white/5 p-4 text-center text-sm text-slate-400">No alerts generated yet.</p>}
            </div>
          </section>
        </div>
        <section className="rounded-2xl border border-white/10 bg-slate-900/40 p-6 shadow-xl backdrop-blur-md">
          <h3 className="text-xl font-bold tracking-tight text-white">Blockchain Audit Logs</h3>
          <div className="mt-4 grid gap-3 md:hidden">
            {data.audit_logs?.map(log => (
              <article key={log.id || log.transaction_id} className="rounded-2xl border border-white/10 bg-white/5 p-4">
                <div className="flex items-center justify-between">
                  <p className="truncate font-mono text-sm font-semibold text-slate-300" title={log.transaction_id}>
                    {log.transaction_id.length > 16 ? `${log.transaction_id.substring(0, 16)}...` : log.transaction_id}
                  </p>
                  <span className={`rounded-full px-2 py-0.5 text-xs font-semibold ${(log.integrity_status === 'Valid' || log.integrity_status === 'Success') ? 'bg-emerald-500/20 text-emerald-300' : 'bg-red-500/20 text-red-300'}`}>
                    {log.integrity_status}
                  </span>
                </div>
                <p className="mt-2 text-xs text-slate-400">
                  {new Date(log.timestamp).toLocaleString()}
                </p>
                <p className="mt-1 text-xs text-slate-400">
                  {log.sender_id} → {log.receiver_id}
                </p>
                <p className="mt-1 text-xs text-cyan-200">{log.event_type}</p>
              </article>
            ))}
            {(!data.audit_logs || !data.audit_logs.length) && (
              <p className="text-sm text-slate-400">No audit logs available.</p>
            )}
          </div>
          <div className="mt-4 hidden overflow-x-auto rounded-xl border border-white/5 bg-slate-950/50 md:block">
            <table className="w-full text-left text-sm text-slate-300">
              <thead className="border-b border-white/10 bg-white/[0.02] text-slate-400">
                <tr>
                  <th className="px-4 py-3 font-semibold">Transaction ID</th>
                  <th className="px-4 py-3 font-semibold">Timestamp</th>
                  <th className="px-4 py-3 font-semibold">Sender / Receiver</th>
                  <th className="px-4 py-3 font-semibold">Event Type</th>
                  <th className="px-4 py-3 font-semibold">Integrity</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {data.audit_logs?.map(log => (
                  <tr key={log.id || log.transaction_id} className="transition-colors hover:bg-white/[0.02]">
                    <td className="px-4 py-3 font-mono text-xs text-slate-300" title={log.transaction_id}>
                      {log.transaction_id.length > 20 ? `${log.transaction_id.substring(0, 20)}...` : log.transaction_id}
                    </td>
                    <td className="px-4 py-3 text-xs whitespace-nowrap">
                      {new Date(log.timestamp).toLocaleString()}
                    </td>
                    <td className="px-4 py-3 text-xs">
                      {log.sender_id} → {log.receiver_id}
                    </td>
                    <td className="px-4 py-3 text-xs">{log.event_type}</td>
                    <td className="px-4 py-3 text-xs">
                      <span className={`inline-flex items-center rounded-full px-2 py-0.5 font-medium border ${(log.integrity_status === 'Valid' || log.integrity_status === 'Success') ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' : 'bg-red-500/10 text-red-400 border-red-500/20'}`}>
                        {log.integrity_status}
                      </span>
                    </td>
                  </tr>
                ))}
                {(!data.audit_logs || !data.audit_logs.length) && (
                  <tr>
                    <td className="px-4 py-6 text-center text-slate-400" colSpan="5">
                      No audit logs available.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </section>
      </>}
    </div>
  )
}
