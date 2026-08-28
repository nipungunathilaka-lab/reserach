import { useState, useEffect } from 'react'
import { Link2, ShieldAlert, FileKey2 } from 'lucide-react'
import api from '../api/client'

export default function BlockchainLogs() {
  const [logs, setLogs] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    fetchLogs()
  }, [])

  const fetchLogs = async () => {
    try {
      const res = await api.get('/blockchain/logs')
      setLogs(res.data)
    } catch (err) {
      setError('Failed to fetch blockchain ledger.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="flex-1 overflow-y-auto p-6 text-slate-300 lg:p-10">
      <div className="w-full">
        <header className="mb-10">
          <h1 className="text-4xl font-bold text-white tracking-tight">Blockchain Audit Ledger</h1>
          <p className="mt-2 text-slate-400">Cryptographically linked immutable event stream.</p>
        </header>

        {error && (
          <div className="mb-6 rounded-lg bg-red-500/10 p-4 text-red-400 border border-red-500/20">
            {error}
          </div>
        )}

        {loading ? (
          <div className="flex justify-center p-20">
            <div className="h-8 w-8 animate-spin rounded-full border-4 border-cyan-500 border-t-transparent"></div>
          </div>
        ) : logs.length === 0 ? (
          <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-12 text-center">
            <p className="text-slate-400">The blockchain is currently empty.</p>
          </div>
        ) : (
          <div className="relative border-l-2 border-slate-800 ml-6 pl-8 space-y-12">
            {logs.map((log, index) => {
              const isMalware = log.event_type === 'MALWARE_BLOCKED'
              const Icon = isMalware ? ShieldAlert : FileKey2
              
              let parsedDetails = {}
              try {
                parsedDetails = JSON.parse(log.details)
              } catch (e) {}

              return (
                <div key={log.id} className="relative">
                  {/* Timeline dot */}
                  <div className={`absolute -left-[41px] top-4 h-6 w-6 rounded-full border-4 border-slate-950 flex items-center justify-center ${isMalware ? 'bg-red-500 text-slate-900 shadow-[0_0_10px_rgba(239,68,68,0.5)]' : 'bg-cyan-400 text-slate-900 shadow-[0_0_10px_rgba(34,211,238,0.5)]'}`}>
                    <Link2 size={12} className="opacity-0" />
                  </div>

                  <div className="rounded-2xl border border-white/10 bg-slate-900/40 backdrop-blur-md overflow-hidden shadow-xl transition-all hover:border-white/20">
                    <div className="border-b border-white/10 bg-white/[0.02] px-6 py-4 flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <Icon size={20} className={isMalware ? 'text-red-400' : 'text-cyan-400'} />
                        <h3 className={`font-semibold ${isMalware ? 'text-red-400' : 'text-cyan-400'}`}>
                          {log.event_type}
                        </h3>
                      </div>
                      <span className="text-xs text-slate-500 font-mono">
                        {new Date(log.timestamp).toLocaleString()}
                      </span>
                    </div>

                    <div className="p-6 grid gap-6">
                      <div className="grid gap-2 text-sm">
                        <div className="grid grid-cols-[120px_1fr] gap-4">
                          <span className="text-slate-500 font-medium">Block Hash:</span>
                          <span className="font-mono text-cyan-200 break-all select-all">{log.block_hash}</span>
                        </div>
                        <div className="grid grid-cols-[120px_1fr] gap-4">
                          <span className="text-slate-500 font-medium">Previous Hash:</span>
                          <span className="font-mono text-slate-400 break-all select-all">
                            {log.previous_hash}
                            {index < logs.length - 1 && (
                              <span className="ml-2 text-xs text-slate-600">
                                (Matches Block #{logs[index + 1].id})
                              </span>
                            )}
                          </span>
                        </div>
                      </div>

                      <div className="rounded-xl bg-slate-950/50 p-4 border border-white/5">
                        <h4 className="text-xs font-semibold text-slate-500 mb-3 uppercase tracking-wider">Payload Details</h4>
                        <div className="grid gap-2 text-sm text-slate-300 font-mono">
                          {Object.entries(parsedDetails).map(([key, value]) => (
                            <div key={key} className="flex flex-col sm:flex-row sm:gap-2">
                              <span className="text-slate-500 w-32">{key}:</span>
                              <span className="text-white break-all">{String(value)}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </div>
    </div>
  )
}
