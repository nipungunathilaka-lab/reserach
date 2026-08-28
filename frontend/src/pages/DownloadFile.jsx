import { useEffect, useState } from 'react'
import { useParams } from 'react-router-dom'
import { FileArchive, Download, Lock, AlertTriangle } from 'lucide-react'
import api from '../api/client'

const fmtSize = bytes => `${(bytes / 1024 / 1024).toFixed(3)} MB`

export default function DownloadFile() {
  const { token } = useParams()
  const [fileMeta, setFileMeta] = useState(null)
  const [loadingMeta, setLoadingMeta] = useState(true)
  const [error, setError] = useState('')
  const [pin, setPin] = useState('')
  const [downloading, setDownloading] = useState(false)

  useEffect(() => {
    const fetchMeta = async () => {
      try {
        const res = await api.get(`/shared/${token}`)
        setFileMeta(res.data)
      } catch (err) {
        setError(err.response?.data?.detail || "Invalid or expired share link.")
      } finally {
        setLoadingMeta(false)
      }
    }
    fetchMeta()
  }, [token])

  const handleDownload = async (e) => {
    e.preventDefault()
    if (pin.length !== 6) {
      setError("PIN must be exactly 6 digits.")
      return
    }
    setError('')
    setDownloading(true)
    try {
      const res = await api.post(`/shared/${token}/download`, { pin }, { responseType: 'blob' })
      const url = window.URL.createObjectURL(new Blob([res.data]))
      const a = document.createElement('a')
      a.href = url
      a.download = fileMeta.filename
      document.body.appendChild(a)
      a.click()
      a.remove()
      window.URL.revokeObjectURL(url)
    } catch (err) {
      setError(err.response?.status === 401 ? "Incorrect PIN." : "Failed to decrypt and download file.")
    } finally {
      setDownloading(false)
    }
  }

  return (
    <div className="relative flex min-h-screen w-full flex-col items-center justify-center overflow-hidden bg-slate-950 p-6">
      <div className="absolute inset-0 bg-[linear-gradient(to_right,#80808012_1px,transparent_1px),linear-gradient(to_bottom,#80808012_1px,transparent_1px)] bg-[size:24px_24px] pointer-events-none" />
      <div className="absolute -top-40 -right-40 h-[500px] w-[500px] rounded-full bg-cyan-500/10 blur-[150px] pointer-events-none" />
      <div className="absolute -bottom-40 -left-40 h-[500px] w-[500px] rounded-full bg-blue-600/10 blur-[150px] pointer-events-none" />

      <div className="relative z-10 w-full max-w-md">
        <div className="rounded-[2rem] border border-white/10 bg-white/[0.02] p-8 backdrop-blur-xl shadow-2xl">
          <div className="flex flex-col items-center text-center">
            <div className="mb-6 grid h-16 w-16 place-items-center rounded-2xl bg-cyan-400/20 text-cyan-400 border border-cyan-400/20 shadow-[0_0_30px_-5px_rgba(34,211,238,0.3)]">
              <Lock size={32} />
            </div>
            <h1 className="text-2xl font-bold tracking-tight text-white mb-2">Secure File Share</h1>
            <p className="text-sm text-slate-400 mb-8">Enter the 6-digit PIN to decrypt and download this file securely.</p>
          </div>

          {loadingMeta ? (
            <div className="flex justify-center p-4">
              <div className="h-6 w-6 animate-spin rounded-full border-2 border-cyan-400 border-t-transparent" />
            </div>
          ) : error && !fileMeta ? (
            <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-4 text-sm font-semibold text-red-400 text-center shadow-[0_0_20px_rgba(239,68,68,0.2)]">
              {error}
            </div>
          ) : (
            <div className="grid gap-6">
              <div className="rounded-xl border border-white/5 bg-slate-950/50 p-4 flex items-center gap-4">
                <FileArchive size={24} className="text-cyan-400 shrink-0" />
                <div className="min-w-0">
                  <h3 className="text-sm font-bold text-white truncate" title={fileMeta.filename}>{fileMeta.filename}</h3>
                  <p className="text-xs text-slate-400 mt-1">{fmtSize(fileMeta.file_size)} • {fileMeta.classification_type}</p>
                </div>
              </div>

              {error && (
                <div className="flex items-center gap-2 rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-xs font-semibold text-red-400 shadow-[0_0_15px_rgba(239,68,68,0.2)]">
                  <AlertTriangle size={16} /> {error}
                </div>
              )}

              <form onSubmit={handleDownload} className="grid gap-6">
                <div className="grid gap-2 text-center">
                  <label className="text-xs font-semibold text-slate-300">Enter Access PIN</label>
                  <input
                    type="text"
                    value={pin}
                    onChange={e => setPin(e.target.value.replace(/\D/g, '').slice(0, 6))}
                    maxLength={6}
                    className="mx-auto w-full max-w-[200px] rounded-xl border border-white/10 bg-slate-950/80 px-4 py-3 text-center text-3xl tracking-[0.5em] text-white outline-none transition focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400 focus:shadow-[0_0_20px_rgba(34,211,238,0.2)] hover:border-white/20"
                    placeholder="000000"
                    autoComplete="off"
                  />
                </div>

                <button
                  type="submit"
                  disabled={pin.length !== 6 || downloading}
                  className="flex w-full items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-500 px-4 py-3.5 text-sm font-bold text-white transition-all hover:scale-[1.02] shadow-[0_0_20px_rgba(34,211,238,0.4)] hover:shadow-[0_0_30px_rgba(34,211,238,0.6)] disabled:opacity-70 disabled:hover:scale-100 disabled:hover:shadow-none focus:outline-none"
                >
                  {downloading ? 'Decrypting...' : 'Decrypt & Download'} <Download size={18} />
                </button>
              </form>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
