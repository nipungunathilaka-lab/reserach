import { useState } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import { KeyRound, ArrowRight, ShieldCheck, Loader2 } from 'lucide-react'
import api from '../api/client'
import { useAuth } from '../auth/AuthContext'

export default function VerifyOTP() {
  const [otp, setOtp] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  
  const navigate = useNavigate()
  const location = useLocation()
  const { setToken } = useAuth()
  
  // The email should be passed from the login page via location state
  const email = location.state?.email || ''

  const handleVerify = async (e) => {
    e.preventDefault()
    if (!otp) {
      setError('Please enter the OTP.')
      return
    }

    setLoading(true)
    setError('')

    try {
      const response = await api.post('/auth/verify-otp', {
        email,
        otp
      })
      
      // Assume successful verification returns an access token
      if (response.data && response.data.access_token) {
        setToken(response.data.access_token)
        navigate('/dashboard')
      } else {
        setError('Invalid response from server.')
      }
    } catch (err) {
      setError(err.response?.data?.detail || 'Invalid OTP or OTP expired.')
    } finally {
      setLoading(false)
    }
  }

  // If there's no email in state, they shouldn't be on this page directly
  if (!email) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-slate-950 p-4">
        <div className="w-full max-w-md text-center">
          <p className="text-slate-400 mb-4">No email provided for verification.</p>
          <button 
            onClick={() => navigate('/login')}
            className="text-cyan-400 hover:text-cyan-300 transition"
          >
            Return to Login
          </button>
        </div>
      </div>
    )
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-slate-900 via-slate-950 to-black p-4 text-slate-300 selection:bg-cyan-500/30">
      <div className="w-full max-w-md relative">
        {/* Glow effect behind the card */}
        <div className="absolute -inset-1 rounded-2xl bg-gradient-to-r from-cyan-500 to-indigo-500 opacity-20 blur-xl"></div>
        
        <div className="relative rounded-2xl border border-slate-800 bg-slate-900/80 p-8 shadow-2xl backdrop-blur-xl">
          <div className="mb-8 text-center">
            <div className="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-slate-800 border border-slate-700 shadow-inner">
              <ShieldCheck className="h-8 w-8 text-cyan-400" />
            </div>
            <h1 className="text-2xl font-bold text-white tracking-tight">Authentication Required</h1>
            <p className="mt-2 text-sm text-slate-400">
              We've sent a one-time code to <br/>
              <strong className="text-slate-300">{email}</strong>
            </p>
          </div>

          {error && (
            <div className="mb-6 rounded-lg border border-red-500/20 bg-red-500/10 p-3 text-center text-sm text-red-400">
              {error}
            </div>
          )}

          <form onSubmit={handleVerify} className="space-y-6">
            <div className="space-y-2">
              <label htmlFor="otp" className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                Security Code
              </label>
              <div className="relative">
                <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-4">
                  <KeyRound className="h-5 w-5 text-slate-500" />
                </div>
                <input
                  id="otp"
                  type="text"
                  placeholder="Enter 6-digit code"
                  value={otp}
                  onChange={(e) => setOtp(e.target.value)}
                  className="w-full rounded-xl border border-slate-800 bg-slate-950/50 py-3 pl-12 pr-4 text-white placeholder:text-slate-600 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 transition-all font-mono tracking-widest text-lg"
                  autoComplete="one-time-code"
                  maxLength={6}
                  required
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={loading || !otp}
              className="group relative flex w-full items-center justify-center gap-2 overflow-hidden rounded-xl bg-cyan-500 px-4 py-3 font-semibold text-slate-950 transition-all hover:bg-cyan-400 disabled:opacity-50 disabled:cursor-not-allowed shadow-[0_0_20px_rgba(34,211,238,0.2)] hover:shadow-[0_0_25px_rgba(34,211,238,0.4)]"
            >
              {loading ? (
                <Loader2 className="h-5 w-5 animate-spin" />
              ) : (
                <>
                  Verify Identity
                  <ArrowRight className="h-4 w-4 transition-transform group-hover:translate-x-1" />
                </>
              )}
            </button>
          </form>

          <div className="mt-8 text-center text-sm">
            <button 
              onClick={() => navigate('/login')}
              className="text-slate-500 hover:text-cyan-400 transition-colors"
            >
              Cancel and return to login
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
