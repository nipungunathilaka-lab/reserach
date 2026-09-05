import { useEffect, useState } from 'react'
import { Send, UploadCloud, File as FileIcon, Shield, Loader2, AlertTriangle, CheckCircle, Cpu, Clock, Activity } from 'lucide-react'
import toast from 'react-hot-toast'
import api, { apiError } from '../api/client'
import ErrorBanner from '../components/ErrorBanner'

const fmtSize = bytes => `${(bytes / 1024 / 1024).toFixed(3)} MB`

export default function SendFile() {
  const [receivers, setReceivers] = useState([])
  const [receiverId, setReceiverId] = useState('')
  const [file, setFile] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [result, setResult] = useState(null)
  const [uploadProgress, setUploadProgress] = useState(0)
  const [progressData, setProgressData] = useState(null)
  const [telemetryData, setTelemetryData] = useState(null)
  const [isBlocked, setIsBlocked] = useState(false)
  const [blockedScore, setBlockedScore] = useState(null)

  useEffect(() => {
    api.get('/users/receivers')
      .then(res => {
        const users = Array.isArray(res.data) ? res.data : (res.data?.data || [])
        setReceivers(users)
        if (users.length > 0) {
          setReceiverId(String(users[0].id || users[0]._id))
        }
      })
      .catch(err => setError(apiError(err)))
  }, [])

  const submit = async (e) => {
    e.preventDefault()
    if (!file) return setError('Please choose a file')
    setLoading(true)
    setError('')
    setResult(null)
    setUploadProgress(0)
    setProgressData(null)
    setTelemetryData(null)
    setIsBlocked(false)
    setBlockedScore(null)

    const chunkSize = 50 * 1024 * 1024 // 50MB
    const totalChunks = Math.ceil(file.size / chunkSize)
    const uploadId = window.crypto && crypto.randomUUID ? crypto.randomUUID() : Date.now().toString(36) + Math.random().toString(36).substr(2)

    try {
      let finalResult = null
      for (let chunkIndex = 0; chunkIndex < totalChunks; chunkIndex++) {
        const start = chunkIndex * chunkSize
        const end = Math.min(start + chunkSize, file.size)
        const chunk = file.slice(start, end)

        const form = new FormData()
        form.append('receiver_id', receiverId)
        form.append('upload_id', uploadId)
        form.append('chunk_index', chunkIndex)
        form.append('total_chunks', totalChunks)
        form.append('file_name', file.name)
        form.append('file', new File([chunk], file.name))

        const res = await api.post('/files/upload-chunk', form, { headers: { 'Content-Type': 'multipart/form-data' } })

        if (chunkIndex === totalChunks - 1) {
          finalResult = res.data
        } else {
          setUploadProgress(Math.round(((chunkIndex + 1) / totalChunks) * 100))
        }
      }

      if (finalResult.status === 'processing') {
        setUploadProgress(99)
        setResult(finalResult)
        
        const pollInterval = setInterval(async () => {
          try {
            const statusRes = await api.get(`/files/status/${uploadId}`)
            if (statusRes.data.status === 'completed') {
              clearInterval(pollInterval)
              setUploadProgress(100)
              setProgressData(null)
              setResult(statusRes.data.result)
              if (statusRes.data.telemetry) {
                setTelemetryData(statusRes.data.telemetry)
              }
              toast.success('File encrypted and sent successfully!', { icon: '🛡️' })
              setLoading(false)
              setTimeout(() => setUploadProgress(0), 2000)
            } else if (statusRes.data.status === 'error' || statusRes.data.status === 'processing_error') {
              clearInterval(pollInterval)
              const errorMsg = statusRes.data.message || 'Encryption failed'
              setError(errorMsg)
              if (errorMsg.toLowerCase().includes('blocked') || errorMsg.toLowerCase().includes('malware')) {
                setIsBlocked(true)
                if (statusRes.data.anomaly_score !== undefined) {
                  setBlockedScore(statusRes.data.anomaly_score)
                }
              }
              setResult(null)
              setProgressData(null)
              toast.error('Processing failed')
              setLoading(false)
              setUploadProgress(0)
            } else if (statusRes.data.status === 'processing' && statusRes.data.processed_mb !== undefined) {
              setProgressData(statusRes.data)
            }
          } catch (err) {
            clearInterval(pollInterval)
            setError(apiError(err))
            setResult(null)
            setProgressData(null)
            toast.error('Failed to check status')
            setLoading(false)
            setUploadProgress(0)
          }
        }, 3000)
        return // Keep loading state active during polling
      } else {
        setResult(finalResult)
        toast.success('File encrypted and sent successfully!', {
          icon: '🛡️',
        })
      }
    } catch (err) {
      const errMsg = apiError(err)
      setError(errMsg)
      if (errMsg.toLowerCase().includes('blocked') || errMsg.toLowerCase().includes('malware')) {
        setIsBlocked(true)
        if (err.response?.data?.anomaly_score !== undefined) {
          setBlockedScore(err.response.data.anomaly_score)
        }
      }
      toast.error('Failed to encrypt and send file')
    } finally {
      // Only reset loading if we aren't starting a polling process
      if (result?.status !== 'processing' && !uploadId) {
          setLoading(false)
          setUploadProgress(0)
      }
    }
  }

  // Workaround for finally block running immediately when polling
  useEffect(() => {
    if (result?.status === 'processing') {
      setLoading(true)
    }
  }, [result])

  return (
    <div className="grid gap-6 xl:grid-cols-[.9fr_1.1fr]">
      <section className="rounded-2xl border border-white/10 bg-slate-900/40 p-6 shadow-xl backdrop-blur-md">
        <h3 className="text-2xl font-bold tracking-tight text-white">Send Encrypted File</h3>
        <p className="mt-2 text-sm text-slate-400">The backend encrypts the file with AES-256-GCM, wraps the AES key with RSA-2048 and ECDH-derived wrapping, stores metadata, runs AI detection, and adds a blockchain audit block.</p>
        <form onSubmit={submit} className="mt-6 grid gap-4">
          <ErrorBanner message={error} />
          <label className="grid gap-2 text-sm text-slate-300">Receiver
            <select className="w-full rounded-xl border border-white/10 bg-slate-900/50 px-4 py-3 text-sm text-white outline-none transition focus:border-cyan-400 focus:bg-slate-900 focus:ring-1 focus:ring-cyan-400 focus:shadow-[0_0_15px_-3px_rgba(34,211,238,0.3)] appearance-none" value={receiverId} onChange={e => setReceiverId(e.target.value)} required>
              <option value="" disabled hidden>{receivers.length ? 'Select a recipient...' : 'Loading users...'}</option>
              {receivers.map(u => (
                <option key={u.id || u._id} value={u.id || u._id} className="bg-slate-900 text-white">
                  {u.full_name} ({u.email}){u.company_name ? ` - ${u.company_name}` : ''}
                </option>
              ))}
            </select>
          </label>
          <label className="grid gap-2 text-sm text-slate-300">File
            <div className="relative mt-2 flex cursor-pointer flex-col items-center justify-center rounded-3xl border-2 border-dashed border-cyan-500/40 bg-slate-800/30 p-10 transition-all hover:bg-slate-800/50">
              <input className="absolute inset-0 h-full w-full cursor-pointer opacity-0" type="file" onChange={e => setFile(e.target.files?.[0] || null)} />
              {file ? (
                <div className="flex flex-col items-center gap-3">
                  <div className="rounded-2xl bg-cyan-500/20 p-4 text-cyan-400 shadow-[0_0_15px_rgba(34,211,238,0.2)]">
                    <FileIcon size={40} />
                  </div>
                  <div className="text-center">
                    <p className="font-bold text-white">{file.name}</p>
                    <p className="mt-1 text-xs text-cyan-200">{fmtSize(file.size)}</p>
                  </div>
                </div>
              ) : (
                <div className="flex flex-col items-center gap-3 text-slate-400">
                  <UploadCloud className="text-cyan-400 opacity-80" size={48} />
                  <p className="font-medium text-white">Click to browse or drag a file here</p>
                  <p className="text-xs">Maximum upload size: Unlimited (PFCE Streaming)</p>
                </div>
              )}
            </div>
          </label>
          <button className="mt-4 flex w-full items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-500 px-6 py-4 text-sm font-bold text-white shadow-[0_0_20px_rgba(34,211,238,0.4)] transition-all hover:scale-[1.02] hover:shadow-[0_0_30px_rgba(34,211,238,0.6)] focus:outline-none focus:ring-2 focus:ring-cyan-400 focus:ring-offset-2 focus:ring-offset-slate-900 disabled:opacity-70 disabled:hover:scale-100 disabled:hover:shadow-none" disabled={loading || !receiverId || !file}>
            {loading ? <Loader2 className="animate-spin" size={20} /> : <Send size={20} />}
            {loading ? (uploadProgress > 0 && uploadProgress < 100 ? `Uploading chunk ${uploadProgress}%...` : 'Processing and encrypting...') : 'Upload, Encrypt and Send'}
          </button>
          {loading && uploadProgress > 0 && uploadProgress < 100 && (
            <div className="mt-2 h-2 w-full overflow-hidden rounded-full bg-slate-800">
              <div 
                className="h-full bg-cyan-400 transition-all duration-300" 
                style={{ width: `${uploadProgress}%` }}
              />
            </div>
          )}
        </form>
      </section>
      <section className="rounded-2xl border border-white/10 bg-slate-900/40 p-6 shadow-xl backdrop-blur-md flex flex-col">
        <h3 className="text-2xl font-bold tracking-tight text-white mb-6">Security & Telemetry Report</h3>
        
        {isBlocked ? (
          <div className="flex flex-1 flex-col items-center justify-center text-center p-10 animate-in fade-in zoom-in duration-500 bg-red-500/10 rounded-2xl border border-red-500/30 shadow-[0_0_40px_rgba(239,68,68,0.15)]">
            <div className="mb-6 rounded-full border border-red-500/40 bg-red-500/20 p-6 text-red-500 shadow-[0_0_30px_rgba(239,68,68,0.4)]">
              <AlertTriangle size={64} />
            </div>
            <p className="text-3xl font-black text-red-500 mb-3 tracking-tight">Transfer Blocked</p>
            <p className="text-xl font-bold text-red-400 mb-4">Malware / Intrusion Detected</p>
            {blockedScore !== null && (
              <div className="mb-4 inline-flex items-center gap-2 rounded-full border border-red-500/50 bg-red-950/60 px-4 py-1.5">
                <span className="text-sm font-semibold uppercase tracking-wider text-red-300">AI Threat Score</span>
                <span className="text-lg font-black text-red-400">{Number(blockedScore).toFixed(4)}</span>
              </div>
            )}
            <div className="bg-red-950/50 p-4 rounded-xl border border-red-500/20 max-w-md w-full">
              <p className="text-sm font-mono text-red-300 break-words">{error}</p>
            </div>
            <p className="mt-6 text-sm text-slate-400 max-w-md">Your connection has been logged and the security operations center has been notified. This action was aborted to protect the network.</p>
          </div>
        ) : (
          <>
        {!result && (
          <div className="flex flex-1 flex-col items-center justify-center text-center p-10 opacity-70">
            <div className="mb-6 animate-pulse rounded-full border border-cyan-500/20 bg-cyan-500/10 p-6 text-cyan-400 shadow-[0_0_30px_rgba(34,211,238,0.2)]">
              <Shield size={48} />
            </div>
            <p className="text-lg font-semibold text-slate-300">System Ready</p>
            <p className="mt-2 text-sm text-slate-500">Awaiting file transfer. The secure cryptographic pipeline will activate upon upload.</p>
          </div>
        )}

        {result && result.status === 'processing' && (
          <div className="flex flex-1 flex-col items-center justify-center text-center p-10 animate-in fade-in zoom-in duration-500">
            <div className="mb-6 rounded-full border border-cyan-500/30 bg-cyan-500/10 p-6 text-cyan-400 shadow-[0_0_30px_rgba(34,211,238,0.3)]">
              <Loader2 size={48} className="animate-spin" />
            </div>
            <p className="text-2xl font-bold text-white mb-2">
              {progressData 
                ? `Encrypting: ${progressData.processed_mb} MB / ${progressData.total_mb} MB (${progressData.percentage}%)` 
                : 'Encrypting in Background...'}
            </p>
            <p className="text-sm text-slate-400 max-w-md">Your file has been safely uploaded and is now being encrypted, scanned by AI, and logged to the blockchain. Please wait...</p>
            
            {progressData && (
              <div className="w-full max-w-md mt-6">
                <div className="h-3 w-full overflow-hidden rounded-full bg-slate-800 shadow-inner">
                  <div 
                    className="h-full rounded-full bg-gradient-to-r from-cyan-500 to-blue-500 shadow-[0_0_12px_rgba(34,211,238,0.8)] transition-all duration-300" 
                    style={{ width: `${progressData.percentage}%` }}
                  />
                </div>
              </div>
            )}
          </div>
        )}

        {result && result.status !== 'processing' && (
          <div className="flex flex-col gap-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
            {/* Header Row: Classification & Encryption */}
            <div className="flex flex-col sm:flex-row gap-4">
              {/* Classification Badge */}
              <div className={`flex flex-1 items-center gap-3 rounded-xl border p-4 backdrop-blur-md ${result.classification_type === 'Sensitive' ? 'text-orange-400 bg-orange-500/10 border-orange-500/30 shadow-[0_0_20px_rgba(249,115,22,0.15)]' : 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30 shadow-[0_0_20px_rgba(16,185,129,0.15)]'}`}>
                {result.classification_type === 'Sensitive' ? <AlertTriangle size={32} className="text-orange-400" /> : <CheckCircle size={32} className="text-emerald-400" />}
                <div>
                  <p className="text-xs font-semibold uppercase tracking-wider opacity-80">Data Classification</p>
                  <p className="text-xl font-black tracking-tight">{result.classification_type || 'Normal'}</p>
                </div>
              </div>
              
              {/* Encryption Engine */}
              <div className="flex flex-1 items-center gap-3 rounded-xl border border-cyan-500/30 bg-cyan-500/10 p-4 shadow-[0_0_20px_rgba(34,211,238,0.15)] backdrop-blur-md">
                <Shield size={32} className="text-cyan-400" />
                <div>
                  <p className="text-xs font-semibold uppercase tracking-wider text-cyan-200/70">Encryption Engine</p>
                  <p className="text-xl font-black tracking-tight text-cyan-50">{result.encryption_mechanism_used || (result.encryption && result.encryption.algorithm) || 'AES-128'}</p>
                </div>
              </div>
            </div>

            {/* Metrics Grid */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              {/* CPU Usage */}
              <div className="relative overflow-hidden rounded-xl border border-white/10 bg-slate-900/60 p-5 shadow-xl backdrop-blur-md group hover:bg-slate-800/80 hover:border-white/20 transition-all">
                <div className="absolute -right-4 -top-4 opacity-5 group-hover:opacity-10 transition-opacity">
                  <Cpu size={80} />
                </div>
                <div className="flex items-center gap-2 text-slate-400 mb-2">
                  <Cpu size={16} className="text-blue-400" />
                  <span className="text-xs font-bold uppercase tracking-wider text-slate-300">CPU Usage</span>
                </div>
                <div className="flex items-baseline gap-1 mt-1">
                  <span className="text-3xl font-black tracking-tighter text-white drop-shadow-md">{result.cpu_usage_percent || 0}</span>
                  <span className="text-sm font-bold text-slate-500">%</span>
                </div>
                <div className="mt-4 h-1.5 w-full overflow-hidden rounded-full bg-slate-800 shadow-inner">
                  <div 
                    className="h-full rounded-full bg-gradient-to-r from-blue-500 to-cyan-400 shadow-[0_0_12px_rgba(56,189,248,0.8)]" 
                    style={{ width: `${Math.min(100, Math.max(0, result.cpu_usage_percent || 0))}%` }}
                  />
                </div>
              </div>

              {/* Execution Time */}
              <div className="relative overflow-hidden rounded-xl border border-white/10 bg-slate-900/60 p-5 shadow-xl backdrop-blur-md group hover:bg-slate-800/80 hover:border-white/20 transition-all">
                <div className="absolute -right-4 -top-4 opacity-5 group-hover:opacity-10 transition-opacity">
                  <Clock size={80} />
                </div>
                <div className="flex items-center gap-2 text-slate-400 mb-2">
                  <Clock size={16} className="text-indigo-400" />
                  <span className="text-xs font-bold uppercase tracking-wider text-slate-300">Exec Time</span>
                </div>
                <div className="flex items-baseline gap-1 mt-1">
                  <span className="text-3xl font-black tracking-tighter text-white drop-shadow-md">{result.execution_time_ms || 0}</span>
                  <span className="text-sm font-bold text-slate-500">ms</span>
                </div>
                <div className="mt-4 h-1.5 w-full overflow-hidden rounded-full bg-slate-800 shadow-inner">
                  <div className="h-full w-full rounded-full bg-gradient-to-r from-indigo-500 to-purple-500 shadow-[0_0_12px_rgba(99,102,241,0.6)] opacity-70" />
                </div>
              </div>

              {/* Bandwidth */}
              <div className="relative overflow-hidden rounded-xl border border-white/10 bg-slate-900/60 p-5 shadow-xl backdrop-blur-md group hover:bg-slate-800/80 hover:border-white/20 transition-all">
                <div className="absolute -right-4 -top-4 opacity-5 group-hover:opacity-10 transition-opacity">
                  <Activity size={80} />
                </div>
                <div className="flex items-center gap-2 text-slate-400 mb-2">
                  <Activity size={16} className="text-fuchsia-400" />
                  <span className="text-xs font-bold uppercase tracking-wider text-slate-300">Bandwidth</span>
                </div>
                <div className="flex items-baseline gap-1 mt-1">
                  <span className="text-3xl font-black tracking-tighter text-white drop-shadow-md">{result.processing_bandwidth_mbps || 0}</span>
                  <span className="text-sm font-bold text-slate-500">MB/s</span>
                </div>
                <div className="mt-4 h-1.5 w-full overflow-hidden rounded-full bg-slate-800 shadow-inner">
                  <div 
                    className="h-full rounded-full bg-gradient-to-r from-fuchsia-500 to-pink-500 shadow-[0_0_12px_rgba(217,70,239,0.8)]"
                    style={{ width: `${Math.min(100, (result.processing_bandwidth_mbps || 0) / 10)}%` }}
                  />
                </div>
              </div>
            </div>

            {/* Detailed Cryptographic Logs */}
            <div className="mt-4 grid gap-4 text-sm pt-6 border-t border-white/10 opacity-90">
              <h4 className="text-sm font-bold text-slate-400 uppercase tracking-widest mb-1">Cryptographic Pipeline Logs</h4>
              <div className="rounded-xl border border-white/5 bg-slate-950/50 p-4"><b>Transfer #{result.transfer?.id}</b><p className="break-words text-slate-300">{result.transfer?.file_name} → {result.transfer?.receiver?.full_name}</p></div>
              <div className="rounded-xl border border-white/5 bg-slate-950/50 p-4"><b>Encryption</b><p className="mt-1 text-slate-300">{result.encryption?.algorithm}; {result.encryption?.rsa_key_protection}; {result.encryption?.ecdh_forward_secrecy}</p><p className="mt-2 text-slate-400">AES {result.encryption?.aes_time_ms}ms · RSA wrap {result.encryption?.rsa_key_wrap_time_ms}ms · ECDH {result.encryption?.ecdh_time_ms}ms</p></div>
              <div className="rounded-xl border border-white/5 bg-slate-950/50 p-4"><b>SHA-256 Integrity</b><p className="mt-1 break-all text-slate-300">{result.integrity?.sha256_original_hash}</p><p className="mt-2 text-slate-400">{result.integrity?.status}</p></div>
              <div className={`rounded-xl p-4 ${result.ai?.is_anomaly ? 'bg-red-500/10 border border-red-400/20' : 'bg-emerald-500/10 border border-emerald-400/20'}`}><b>AI Detection: {result.ai?.level}</b><p className="mt-1 text-slate-200">Score {result.ai?.anomaly_score} — {result.ai?.reason}</p><p className="mt-2 text-xs text-slate-400">ML: {result.ai?.ml_prediction} · decision score {result.ai?.ml_decision_score}</p>{result.ai?.triggered_rules?.length ? <p className="mt-2 text-xs text-red-100/80">Rules: {result.ai?.triggered_rules.join('; ')}</p> : null}</div>
              <div className="rounded-xl border border-white/5 bg-slate-950/50 p-4"><b>Blockchain Block #{result.blockchain?.block_index}</b><p className="mt-1 break-all text-slate-300">Current hash: {result.blockchain?.current_hash}</p></div>
            </div>

            {/* Final Telemetry Data */}
            {telemetryData && (
              <div className="mt-4 grid gap-4 text-sm pt-6 border-t border-white/10 opacity-90">
                <h4 className="text-sm font-bold text-slate-400 uppercase tracking-widest mb-1">Final Telemetry Payload</h4>
                <div className="rounded-xl border border-cyan-500/30 bg-cyan-500/10 p-5 shadow-[0_0_20px_rgba(34,211,238,0.15)]">
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <div>
                      <p className="text-xs text-cyan-200/70 uppercase">Execution Time</p>
                      <p className="text-lg font-bold text-cyan-100">{telemetryData.exec_time_ms ? Number(telemetryData.exec_time_ms).toFixed(2) : 0} ms</p>
                    </div>
                    <div>
                      <p className="text-xs text-cyan-200/70 uppercase">Encryption Engine</p>
                      <p className="text-lg font-bold text-cyan-100">{telemetryData.encryption_type}</p>
                    </div>
                    <div>
                      <p className="text-xs text-cyan-200/70 uppercase">AI Threat Score</p>
                      <p className="text-lg font-bold text-cyan-100">{telemetryData.ai_score === "N/A" ? "Skipped" : typeof telemetryData.ai_score === 'number' ? telemetryData.ai_score.toFixed(4) : telemetryData.ai_score}</p>
                    </div>
                    <div>
                      <p className="text-xs text-cyan-200/70 uppercase">Blockchain Hash</p>
                      <p className="text-sm font-mono text-cyan-100 truncate break-all" title={telemetryData.blockchain_hash}>{telemetryData.blockchain_hash}</p>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}
          </>
        )}
      </section>
    </div>
  )
}
