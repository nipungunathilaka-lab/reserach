import { useEffect, useState } from 'react'
import api, { apiError } from '../api/client'
import ErrorBanner from '../components/ErrorBanner'

const fmtSize = bytes => `${(bytes / 1024 / 1024).toFixed(3)} MB`

export default function TransferLogs() {
  const [logs, setLogs] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  useEffect(() => { api.get('/audit/transfers').then(res => setLogs(res.data)).catch(err => setError(apiError(err))).finally(() => setLoading(false)) }, [])
  if (loading) return <p className="text-slate-300">Loading transfer logs...</p>
  return (
    <section className="rounded-2xl border border-white/10 bg-slate-900/40 p-6 shadow-xl backdrop-blur-md">
      <h3 className="text-2xl font-bold tracking-tight text-white">Transfer Logs</h3>
      <p className="mt-1 text-sm text-slate-400">Admin sees all logs. Normal users see only sent/received transfers.</p>
      <ErrorBanner message={error} />

      <div className="mt-4 grid gap-3 md:hidden">
        {logs.map(t => <article key={t.id} className="rounded-3xl border border-white/10 bg-white/5 p-4">
          <p className="truncate font-bold">{t.file_name}</p>
          <p className="mt-1 text-xs text-slate-400">{t.sender?.full_name || 'Unknown'} → {t.receiver?.full_name || 'Unknown'}</p>
          <div className="mt-3 grid grid-cols-2 gap-2 text-xs text-slate-400"><p>{fmtSize(t.file_size)}</p><p>{t.status}</p><p>Integrity: {t.integrity_status}</p><p>{new Date(t.created_at).toLocaleDateString()}</p></div>
          <p className="mt-3 break-all rounded-2xl bg-slate-950/50 p-3 font-mono text-[11px] text-slate-400">SHA-256: {t.original_hash}</p>
        </article>)}
        {!logs.length && <p className="rounded-2xl bg-white/5 p-5 text-center text-sm text-slate-400">No transfer logs yet.</p>}
      </div>

      <div className="mt-6 hidden overflow-x-auto rounded-xl border border-white/5 bg-slate-950/50 md:block">
        <table className="w-full min-w-[1050px] text-left text-sm text-slate-300">
          <thead className="border-b border-white/10 bg-white/[0.02] text-slate-400"><tr><th className="px-4 py-4 font-semibold">File</th><th className="px-4 py-4 font-semibold">Sender</th><th className="px-4 py-4 font-semibold">Receiver</th><th className="px-4 py-4 font-semibold">Size</th><th className="px-4 py-4 font-semibold">Status</th><th className="px-4 py-4 font-semibold">Integrity</th><th className="px-4 py-4 font-semibold">SHA-256 Hash</th><th className="px-4 py-4 font-semibold">Date</th></tr></thead>
          <tbody className="divide-y divide-white/5">
            {logs.map(t => <tr key={t.id} className="transition-colors hover:bg-white/[0.02]"><td className="px-4 py-4 font-semibold text-white">{t.file_name}</td><td className="px-4 py-4">{t.sender?.full_name || 'Unknown'}</td><td className="px-4 py-4">{t.receiver?.full_name || 'Unknown'}</td><td className="px-4 py-4">{fmtSize(t.file_size)}</td><td className="px-4 py-4">{t.status}</td><td className="px-4 py-4">{t.integrity_status}</td><td className="px-4 py-4 max-w-xs truncate font-mono text-xs text-slate-400">{t.original_hash}</td><td className="px-4 py-4">{new Date(t.created_at).toLocaleString()}</td></tr>)}
            {!logs.length && <tr><td colSpan="8" className="py-8 text-center text-slate-400">No transfer logs yet.</td></tr>}
          </tbody>
        </table>
      </div>
    </section>
  )
}
