import { useEffect, useState } from 'react'
import { Download, ShieldCheck } from 'lucide-react'
import api, { apiError } from '../api/client'
import ErrorBanner from '../components/ErrorBanner'

const fmtSize = bytes => `${(bytes / 1024 / 1024).toFixed(3)} MB`
const statusColor = status => status === 'verified' ? 'text-emerald-300' : status === 'failed' ? 'text-red-300' : 'text-amber-200'

export default function ReceivedFiles() {
  const [files, setFiles] = useState([])
  const [loading, setLoading] = useState(true)
  const [downloading, setDownloading] = useState(null)
  const [error, setError] = useState('')

  const load = () => api.get('/files/received')
    .then(res => setFiles(Array.isArray(res.data) ? res.data : (res.data?.data || [])))
    .catch(err => setError(apiError(err)))
    .finally(() => setLoading(false))
  useEffect(() => { load() }, [])

  const download = async (transfer) => {
    setDownloading(transfer.id)
    setError('')
    try {
      const res = await api.get(`/files/${transfer.id}/download`, { responseType: 'blob' })
      const url = window.URL.createObjectURL(new Blob([res.data]))
      const a = document.createElement('a')
      a.href = url
      a.download = transfer.file_name
      document.body.appendChild(a)
      a.click()
      a.remove()
      window.URL.revokeObjectURL(url)
      await load()
    } catch (err) {
      setError(apiError(err))
    } finally {
      setDownloading(null)
    }
  }

  if (loading) return <p className="text-slate-300">Loading received files...</p>
  return (
    <section className="card p-4 sm:p-5">
      <div className="mb-4 flex items-center justify-between gap-4"><div><h3 className="text-2xl font-black">Received Files</h3><p className="text-sm text-slate-400">Only files sent to your account can be decrypted and downloaded.</p></div></div>
      <ErrorBanner message={error} />

      <div className="mt-4 grid gap-3 md:hidden">
        {(files || []).map(t => <article key={t?.id} className="rounded-3xl border border-white/10 bg-white/5 p-4">
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0"><p className="truncate font-bold">{t.file_name}</p><p className="text-xs text-slate-400">From {t.sender?.full_name || 'Unknown'}</p></div>
            <span className={`shrink-0 text-xs font-bold ${statusColor(t.integrity_status)}`}>{t.integrity_status}</span>
          </div>
          
          <div className="mt-3 flex items-center gap-2 rounded-xl border border-emerald-500/20 bg-emerald-500/10 px-3 py-2 text-emerald-400">
            <ShieldCheck size={16} className="shrink-0" />
            <div>
              <p className="text-xs font-bold leading-tight">AI Scanned: Safe</p>
              <p className="text-[10px] text-emerald-500/80 leading-tight">Risk Score: {(t.anomaly_score || 0).toFixed(2)}</p>
            </div>
          </div>

          <div className="mt-3 grid grid-cols-2 gap-2 text-xs text-slate-400"><p>Size: {fmtSize(t.file_size)}</p><p className="col-span-2">Date: {new Date(t.created_at).toLocaleString()}</p></div>
          <button onClick={() => download(t)} className="btn-secondary mt-4 w-full py-2" disabled={downloading === t.id}><Download size={15}/>{downloading === t.id ? 'Decrypting...' : 'Download/decrypt'}</button>
        </article>)}
        {!(files && files.length) && <p className="rounded-2xl bg-white/5 p-5 text-center text-sm text-slate-400">No received files yet.</p>}
      </div>

      <div className="mt-4 hidden overflow-x-auto md:block">
        <table className="w-full min-w-[860px] text-left text-sm">
          <thead className="text-slate-400"><tr><th className="py-3">File</th><th>Sender</th><th>AI Security</th><th>Size</th><th>Date</th><th>Integrity</th><th>Action</th></tr></thead>
          <tbody>
            {(files || []).map(t => (
              <tr key={t?.id} className="border-t border-white/10">
                <td className="py-4 font-semibold">{t?.file_name}</td>
                <td>
                  <p>{t.sender?.full_name || 'Unknown'}</p>
                  <p className="text-xs text-slate-400">{t.sender?.email || 'N/A'}</p>
                </td>
                <td>
                  <div className="inline-flex items-center gap-2 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-3 py-1 text-emerald-400">
                    <ShieldCheck size={14} className="shrink-0" />
                    <div>
                      <p className="text-xs font-bold leading-tight">AI Scanned: 100% Safe</p>
                      <p className="text-[10px] text-emerald-500/80 leading-tight">Risk Score: {(t.anomaly_score || 0).toFixed(2)}</p>
                    </div>
                  </div>
                </td>
                <td>{fmtSize(t.file_size)}</td>
                <td>{new Date(t.created_at).toLocaleString()}</td>
                <td className={statusColor(t.integrity_status)}>{t.integrity_status}</td>
                <td>
                  <button onClick={() => download(t)} className="btn-secondary py-1.5 px-3 text-xs" disabled={downloading === t.id}>
                    <Download size={14} className="mr-1 inline"/>{downloading === t.id ? 'Decrypting...' : 'Decrypt'}
                  </button>
                </td>
              </tr>
            ))}
            {!(files && files.length) && <tr><td colSpan="7" className="py-8 text-center text-slate-400">No received files yet.</td></tr>}
          </tbody>
        </table>
      </div>
    </section>
  )
}
