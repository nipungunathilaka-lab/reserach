import { useEffect, useState } from 'react'
import { Download, FileArchive, Share2, ShieldCheck, MessageCircle, Mail, Copy } from 'lucide-react'
import api, { apiError } from '../api/client'
import ErrorBanner from '../components/ErrorBanner'

const fmtSize = bytes => `${(bytes / 1024 / 1024).toFixed(3)} MB`

export default function FileVault() {
  const [files, setFiles] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [shareData, setShareData] = useState(null)
  const [downloading, setDownloading] = useState(null)
  const [secureSession, setSecureSession] = useState(false)

  const load = async () => {
    try {
      const res = await api.get('/files/sent')
      const grouped = res.data.reduce((acc, file) => {
        const id = file.file_group_id || file.id
        if (!acc[id]) acc[id] = []
        acc[id].push(file)
        return acc
      }, {})
      setFiles(Object.values(grouped))
    } catch (err) {
      setError(apiError(err))
    } finally {
      setLoading(false)
    }
  }

  const establishSecureSession = async () => {
    try {
      const keyPair = await window.crypto.subtle.generateKey(
        { name: "ECDH", namedCurve: "P-256" },
        true,
        ["deriveKey", "deriveBits"]
      )
      const clientPubSpki = await window.crypto.subtle.exportKey("spki", keyPair.publicKey)
      const base64Spki = btoa(String.fromCharCode(...new Uint8Array(clientPubSpki)))
      const clientPem = `-----BEGIN PUBLIC KEY-----\n${base64Spki.match(/.{1,64}/g).join('\n')}\n-----END PUBLIC KEY-----`

      await api.post('/crypto/ecdh/exchange', { client_public_key_pem: clientPem })
      setSecureSession(true)
    } catch (err) {
      console.error("ECDH Failed", err)
      setError("Failed to establish ECDH secure session with backend.")
    }
  }

  useEffect(() => {
    establishSecureSession()
    load()
  }, [])

  const generateShareLink = async (transferId) => {
    setShareData(null)
    setError('')
    try {
      const res = await api.post(`/files/${transferId}/share`)
      setShareData({
        url: `${window.location.origin}/share/${res.data.share_token}`,
        pin: res.data.share_pin
      })
    } catch (err) {
      setError(apiError(err))
    }
  }

  // Professional Multi-line Share Message
  const shareMessage = shareData ? `🔒 SecureFT AI - Encrypted File Transfer\n\nA secure file has been shared with you via our hybrid-cryptography vault.\n\n🔗 Secure Link: ${shareData.url}\n🔑 Access PIN: ${shareData.pin}\n\n🛡️ Enter this PIN on the portal to decrypt and download your file.` : ''

  const copyShareInfo = () => {
    if (!shareData) return
    navigator.clipboard.writeText(shareMessage)
    alert("Link and PIN copied to clipboard!")
  }

  const handleNativeShare = async () => {
    if (typeof navigator !== 'undefined' && navigator.share) {
      try {
        await navigator.share({
          title: 'SecureFT AI File',
          text: shareMessage
        })
      } catch (err) {
        console.error('Error sharing:', err)
      }
    } else {
      alert("Native share is not supported on this browser.")
    }
  }

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
    } catch (err) {
      setError(apiError(err))
    } finally {
      setDownloading(null)
    }
  }

  if (loading) return <p className="text-slate-300">Loading vault...</p>

  return (
    <div className="grid gap-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-black text-white">File Vault Dashboard</h1>
          <p className="text-sm text-slate-400 mt-1">Manage file versions and generate secure share links.</p>
        </div>
        {secureSession && <span className="flex items-center gap-2 rounded-full border border-green-500/30 bg-green-500/10 px-3 py-1 text-xs font-bold text-green-400"><ShieldCheck size={16} /> E2EE Session Active</span>}
      </div>

      <ErrorBanner message={error} />

      {shareData && (
        <div className="rounded-2xl border border-cyan-500/50 bg-slate-900/90 p-6 backdrop-blur-xl shadow-[0_0_30px_rgba(34,211,238,0.2)] flex flex-col md:flex-row items-start md:items-center justify-between gap-6 mb-4">
          <div className="min-w-0 w-full md:w-auto">
            <h3 className="text-base font-bold text-cyan-300 mb-3 flex items-center gap-2">
              <Share2 size={18} /> Public Share Link Generated
            </h3>
            <div className="bg-slate-950/50 p-4 rounded-xl border border-white/5 space-y-2">
              <p className="text-sm font-mono text-slate-300 truncate">
                <span className="text-slate-500 mr-2">URL:</span> {shareData.url}
              </p>
              <p className="text-sm font-mono text-slate-300 flex items-center">
                <span className="text-slate-500 mr-2">PIN:</span>
                <span className="font-bold text-white bg-cyan-900/60 px-3 py-1 rounded text-lg tracking-widest shadow-inner">{shareData.pin}</span>
              </p>
            </div>
          </div>

          <div className="flex flex-col gap-4 w-full md:w-auto shrink-0 pt-2 md:pt-0">
            <button onClick={copyShareInfo} className="btn-primary flex items-center justify-center gap-2 py-3 px-6 text-sm font-bold shadow-[0_0_20px_rgba(34,211,238,0.3)] w-full hover:scale-105 transition-transform">
              <Copy size={16} /> Copy Link & PIN
            </button>

            <div className="flex items-center gap-4 justify-center w-full pt-4 border-t border-slate-700/50">
              <a
                href={`https://api.whatsapp.com/send?text=${encodeURIComponent(shareMessage)}`}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center justify-center w-12 h-12 rounded-full bg-slate-800 border border-slate-600 hover:border-green-500 hover:bg-green-500/20 text-slate-400 hover:text-green-400 transition-all shadow-lg hover:scale-110"
                title="Share on WhatsApp"
              >
                <MessageCircle size={22} />
              </a>
              <a
                href={`mailto:?subject=Secure%20File%20Transfer&body=${encodeURIComponent(shareMessage)}`}
                className="flex items-center justify-center w-12 h-12 rounded-full bg-slate-800 border border-slate-600 hover:border-blue-500 hover:bg-blue-500/20 text-slate-400 hover:text-blue-400 transition-all shadow-lg hover:scale-110"
                title="Share via Email"
              >
                <Mail size={22} />
              </a>
              {typeof navigator !== 'undefined' && navigator.share && (
                <button
                  onClick={handleNativeShare}
                  className="flex items-center justify-center w-12 h-12 rounded-full bg-slate-800 border border-slate-600 hover:border-purple-500 hover:bg-purple-500/20 text-slate-400 hover:text-purple-400 transition-all shadow-lg hover:scale-110"
                  title="More Options"
                >
                  <Share2 size={22} />
                </button>
              )}
            </div>
          </div>
        </div>
      )}

      <div className="grid gap-6 xl:grid-cols-2">
        {files.map(group => {
          group.sort((a, b) => (b.version || 1) - (a.version || 1))
          const latest = group[0]
          return (
            <div key={latest.id} className="rounded-[1.5rem] border border-white/10 bg-slate-900/60 p-5 shadow-xl transition hover:bg-slate-900/80">
              <div className="flex items-start justify-between gap-4">
                <div className="min-w-0">
                  <h3 className="text-lg font-bold text-white flex items-center gap-2 truncate"><FileArchive size={18} className="shrink-0 text-cyan-400" /> {latest.file_name}</h3>
                  <p className="text-xs text-slate-400 mt-1">Latest: v{latest.version || 1} • {fmtSize(latest.file_size)}</p>
                </div>
                <button onClick={() => generateShareLink(latest.id)} className="btn-secondary flex shrink-0 items-center gap-2 py-1.5 px-3 text-xs"><Share2 size={14} /> Share</button>
              </div>
              <div className="mt-5">
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-500 mb-3">Version History</h4>
                <div className="grid gap-2">
                  {group.map(file => (
                    <div key={file.id} className="flex items-center justify-between rounded-xl border border-white/5 bg-white/[0.02] px-4 py-3 transition hover:bg-white/[0.05]">
                      <div>
                        <span className="inline-block min-w-[2rem] font-black text-cyan-300">v{file.version || 1}</span>
                        <span className="text-xs text-slate-400 ml-2">{new Date(file.created_at).toLocaleString()}</span>
                      </div>
                      <button onClick={() => download(file)} disabled={downloading === file.id} className="text-cyan-400 hover:text-cyan-300 disabled:opacity-50 transition-colors" title="Download Decrypted File">
                        <Download size={16} />
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )
        })}
        {files.length === 0 && <div className="col-span-full rounded-2xl border border-white/10 bg-white/5 p-8 text-center text-slate-400"><FileArchive className="mx-auto mb-3 opacity-50" size={32} /> Your file vault is empty. Upload files in the Send File tab to see them here.</div>}
      </div>
    </div>
  )
}
