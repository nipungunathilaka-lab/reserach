import { useEffect, useState } from 'react'
import { AlertOctagon, ShieldAlert, XOctagon } from 'lucide-react'
import api, { apiError } from '../api/client'
import ErrorBanner from '../components/ErrorBanner'

export default function AIAlerts() {
  const [alerts, setAlerts] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  useEffect(() => { api.get('/audit/ai-alerts').then(res => setAlerts(res.data)).catch(err => setError(apiError(err))).finally(() => setLoading(false)) }, [])
  if (loading) return <p className="text-slate-300">Loading AI alerts...</p>
  return (
    <div className="grid gap-6">
      <div className="flex items-center gap-4">
        <div className="flex h-14 w-14 shrink-0 items-center justify-center rounded-2xl bg-red-500/10 text-red-400 border border-red-500/30 shadow-[0_0_20px_rgba(239,68,68,0.3)]">
          <AlertOctagon size={28} />
        </div>
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-white">Security Operations Center</h1>
          <p className="mt-1 text-sm text-slate-400">Live AI Threat Detection & Malware Blocking</p>
        </div>
      </div>

      <ErrorBanner message={error} />
      
      <section className="rounded-2xl border border-red-500/20 bg-slate-900/40 p-6 shadow-[0_0_40px_rgba(239,68,68,0.08)] backdrop-blur-md">
        <h3 className="mb-6 text-xl font-bold text-red-400 flex items-center gap-2">
          <ShieldAlert size={20}/> Blocked Intrusions
        </h3>

        <div className="overflow-x-auto rounded-xl border border-white/5 bg-slate-950/50">
          <table className="w-full min-w-[900px] text-left text-sm text-slate-300">
            <thead className="border-b border-white/10 bg-white/[0.02] text-slate-400">
              <tr>
                <th className="px-5 py-4 font-semibold">Date / Time</th>
                <th className="px-5 py-4 font-semibold">Sender Email</th>
                <th className="px-5 py-4 font-semibold">Attempted File Name</th>
                <th className="px-5 py-4 font-semibold">AI Threat Score</th>
                <th className="px-5 py-4 font-semibold">Reason</th>
                <th className="px-5 py-4 font-semibold text-center">Action Taken</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {alerts.map(a => (
                <tr key={a.id} className="transition-colors hover:bg-white/[0.02]">
                  <td className="px-5 py-4 text-slate-400">
                    {new Date(a.created_at).toLocaleString()}
                  </td>
                  <td className="px-5 py-4 font-medium text-slate-200">
                    {a.user ? a.user.email : 'Unknown Sender'}
                  </td>
                  <td className="px-5 py-4 font-mono text-red-300">
                    {a.file_name || 'N/A'}
                  </td>
                  <td className="px-5 py-4">
                    <span className="inline-flex items-center gap-1.5 rounded-full bg-red-500/10 px-2.5 py-1 text-xs font-black text-red-400 border border-red-500/20">
                      {a.score.toFixed(2)}
                    </span>
                  </td>
                  <td className="px-5 py-4 text-xs text-slate-400">
                    {a.reason}
                  </td>
                  <td className="px-5 py-4 text-center">
                    <div className="inline-flex items-center gap-1.5 rounded-full bg-red-500/20 px-3 py-1 text-xs font-bold text-red-400 border border-red-500/40 shadow-[0_0_15px_rgba(239,68,68,0.2)]">
                      <XOctagon size={14} /> Blocked & Dropped
                    </div>
                  </td>
                </tr>
              ))}
              {!alerts.length && (
                <tr>
                  <td colSpan="6" className="py-12 text-center text-slate-500">
                    No malicious activity detected. Your vault is secure.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  )
}
