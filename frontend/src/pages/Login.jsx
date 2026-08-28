import { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { ShieldCheck, ArrowRight, Lock, Brain, Link as LinkIcon, CheckCircle2, Mail } from 'lucide-react'
import { useAuth } from '../auth/AuthContext'

export default function Login() {
  const navigate = useNavigate()
  const { startLogin, verifyMfa } = useAuth()
  const [step, setStep] = useState('password')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [otp, setOtp] = useState('')
  const [challenge, setChallenge] = useState(null)
  const [loading, setLoading] = useState(false)
  const [apiError, setApiError] = useState('')
  const [fieldErrors, setFieldErrors] = useState({})

  const validatePasswordStep = () => {
    const errors = {}
    if (!email.includes('@')) errors.email = "Please enter a valid email address."
    if (!password) errors.password = "Password is required."
    setFieldErrors(errors)
    return Object.keys(errors).length === 0
  }

  const submitPassword = async (e) => {
    e.preventDefault()
    setApiError('')
    if (!validatePasswordStep()) return

    setLoading(true)
    try {
      const data = await startLogin(email.trim(), password)
      if (data.access_token) {
        navigate('/')
      } else {
        setChallenge(data)
        setOtp('')
        setStep('mfa')
      }
    } catch (err) {
      setApiError(err.message || 'Invalid credentials. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  const submitMfa = async (e) => {
    e.preventDefault()
    setApiError('')
    if (otp.length !== 6) return

    setLoading(true)
    try {
      await verifyMfa(challenge.challenge_id, otp)
      navigate('/')
    } catch (err) {
      setApiError(err.message || 'Invalid code. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="flex min-h-screen w-full flex-col lg:flex-row">
      {/* Left Panel - Auth Form (Solid Dark Background) */}
      <div className="flex w-full flex-col justify-center bg-slate-950 px-6 py-12 lg:w-1/2 lg:px-20 xl:px-32 relative z-10">
        <div className="mb-10 flex items-center gap-3 lg:hidden">
          <div className="grid h-10 w-10 place-items-center rounded-xl bg-cyan-400 text-slate-950 shadow-[0_0_20px_rgba(34,211,238,0.5)]">
            <ShieldCheck size={20} />
          </div>
          <span className="text-xl font-bold tracking-tight text-white">UPCE</span>
        </div>

        <div className="w-full max-w-md mx-auto lg:mx-0">
          <h2 className="text-3xl font-bold tracking-tight text-white sm:text-4xl">
            {step === 'password' ? 'Welcome back' : 'Verify Identity'}
          </h2>
          <p className="mt-2 text-sm text-slate-400">
            {step === 'password' 
              ? 'Enter your credentials to access your secure vault.' 
              : 'Open your Authenticator app and enter the 6-digit code.'}
          </p>

          {apiError && (
            <div className="mt-6 rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-400">
              {apiError}
            </div>
          )}

          {step === 'password' ? (
            <form onSubmit={submitPassword} className="mt-8 grid gap-5">
              <div className="grid gap-1.5">
                <label className="text-xs font-semibold text-slate-300">Email Address</label>
                <div className="relative">
                  <Mail className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-500" size={18} />
                  <input 
                    type="email" 
                    value={email} 
                    onChange={e => {setEmail(e.target.value); setFieldErrors(p => ({...p, email: null}))}}
                    className={`w-full rounded-xl border bg-slate-950/50 py-3 pl-10 pr-4 text-sm text-white outline-none transition focus:border-cyan-400 focus:bg-slate-950 focus:ring-1 focus:ring-cyan-400 focus:shadow-[0_0_15px_-3px_rgba(34,211,238,0.3)] ${fieldErrors.email ? 'border-red-500/50 focus:border-red-500 focus:ring-red-500 focus:shadow-[0_0_15px_-3px_rgba(239,68,68,0.3)]' : 'border-white/10 hover:border-white/20'}`} 
                    placeholder="name@example.com" 
                  />
                </div>
                {fieldErrors.email && <p className="text-xs text-red-400">{fieldErrors.email}</p>}
              </div>

              <div className="grid gap-1.5">
                <div className="flex items-center justify-between">
                  <label className="text-xs font-semibold text-slate-300">Password</label>
                </div>
                <div className="relative">
                  <Lock className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-500" size={18} />
                  <input 
                    type="password" 
                    value={password} 
                    onChange={e => {setPassword(e.target.value); setFieldErrors(p => ({...p, password: null}))}}
                    className={`w-full rounded-xl border bg-slate-950/50 py-3 pl-10 pr-4 text-sm text-white outline-none transition focus:border-cyan-400 focus:bg-slate-950 focus:ring-1 focus:ring-cyan-400 focus:shadow-[0_0_15px_-3px_rgba(34,211,238,0.3)] ${fieldErrors.password ? 'border-red-500/50 focus:border-red-500 focus:ring-red-500 focus:shadow-[0_0_15px_-3px_rgba(239,68,68,0.3)]' : 'border-white/10 hover:border-white/20'}`} 
                    placeholder="••••••••" 
                  />
                </div>
                {fieldErrors.password && <p className="text-xs text-red-400">{fieldErrors.password}</p>}
              </div>

              <button 
                type="submit" 
                disabled={loading}
                className="mt-4 flex w-full items-center justify-center rounded-xl bg-gradient-to-r from-cyan-500 to-blue-500 px-4 py-3 text-sm font-bold text-white transition-all hover:scale-[1.02] shadow-[0_0_20px_rgba(34,211,238,0.4)] hover:shadow-[0_0_30px_rgba(34,211,238,0.6)] focus:outline-none focus:ring-2 focus:ring-cyan-400 focus:ring-offset-2 focus:ring-offset-slate-900 disabled:opacity-70 disabled:hover:scale-100 disabled:hover:shadow-none"
              >
                {loading ? 'Authenticating...' : 'Sign In'}
              </button>
            </form>
          ) : (
            <form onSubmit={submitMfa} className="mt-8 grid gap-6 animate-in slide-in-from-right-4 fade-in duration-300">
              <div className="grid gap-2">
                <label className="text-xs font-semibold text-slate-300 text-center">Authenticator Code</label>
                <input 
                  type="text" 
                  value={otp} 
                  onChange={e => setOtp(e.target.value.replace(/\D/g, '').slice(0, 6))}
                  maxLength={6} 
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  className="mx-auto w-full max-w-[240px] rounded-xl border border-white/10 bg-slate-950/50 px-4 py-4 text-center text-3xl tracking-[0.5em] text-white outline-none transition focus:border-cyan-400 focus:bg-slate-950 focus:ring-1 focus:ring-cyan-400 focus:shadow-[0_0_15px_-3px_rgba(34,211,238,0.3)] hover:border-white/20" 
                  placeholder="000000" 
                />
              </div>

              <button 
                type="submit" 
                disabled={loading || otp.length !== 6}
                className="mt-2 flex w-full items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-500 px-4 py-3 text-sm font-bold text-white transition-all hover:scale-[1.02] shadow-[0_0_20px_rgba(34,211,238,0.4)] hover:shadow-[0_0_30px_rgba(34,211,238,0.6)] focus:outline-none focus:ring-2 focus:ring-cyan-400 focus:ring-offset-2 focus:ring-offset-slate-900 disabled:opacity-70 disabled:hover:scale-100 disabled:hover:shadow-none"
              >
                {loading ? 'Verifying...' : 'Verify Identity'} <ArrowRight size={16} />
              </button>

              <button 
                type="button" 
                onClick={() => {setStep('password'); setChallenge(null); setOtp(''); setApiError('')}}
                className="text-xs text-slate-400 hover:text-white transition underline underline-offset-4 decoration-slate-600"
              >
                Use a different account
              </button>
            </form>
          )}

          {step === 'password' && (
            <p className="mt-8 text-center text-sm text-slate-400">
              Don't have an account?{' '}
              <Link to="/register" className="font-semibold text-white hover:text-cyan-300 transition">
                Create one
              </Link>
            </p>
          )}

        </div>
      </div>

      {/* Right Panel - Branding / Marketing (Rich Background) */}
      <div className="hidden lg:flex relative flex-col justify-center items-center w-full lg:w-1/2 overflow-hidden bg-slate-950 p-16 xl:p-24">
        {/* Background Gradients & Grid */}
        <div className="absolute inset-0 bg-[linear-gradient(to_right,#80808012_1px,transparent_1px),linear-gradient(to_bottom,#80808012_1px,transparent_1px)] bg-[size:24px_24px] pointer-events-none" />
        <div className="absolute -top-40 -right-40 h-[600px] w-[600px] rounded-full bg-cyan-500/10 blur-[150px] pointer-events-none" />
        <div className="absolute -bottom-40 -left-40 h-[600px] w-[600px] rounded-full bg-blue-600/10 blur-[150px] pointer-events-none" />
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 h-[500px] w-[500px] rounded-full bg-indigo-500/10 blur-[150px] pointer-events-none" />

        <div className="relative z-10 flex flex-col items-center max-w-xl w-full">
          <div className="flex flex-col items-center gap-4 mb-10">
            <div className="grid h-16 w-16 place-items-center rounded-2xl bg-cyan-400 text-slate-950 shadow-[0_0_30px_-5px_rgba(34,211,238,0.5)]">
              <ShieldCheck size={32} />
            </div>
          </div>

          <h3 className="text-4xl md:text-5xl font-bold leading-tight text-white text-center tracking-tight mb-12">
            Universal Polymorphic Cryptographic Engine (UPCE).
          </h3>
          
          {/* Glassmorphism Feature Card */}
          <div className="w-full rounded-2xl border border-white/10 bg-white/5 p-8 backdrop-blur-md shadow-2xl text-left">
            <div className="grid gap-8">
              <div className="flex gap-5 items-start">
                <div className="mt-1 grid h-10 w-10 shrink-0 place-items-center rounded-lg bg-cyan-500/20 text-cyan-400 border border-cyan-500/20">
                  <Lock size={20} />
                </div>
                <div>
                  <h4 className="text-base font-semibold text-white">Hybrid Cryptography</h4>
                  <p className="mt-1.5 text-sm text-slate-400 leading-relaxed">Powered by AES-256, ChaCha20, Hybrid PQC (Kyber), and Blockchain Auditing.</p>
                </div>
              </div>
              <div className="flex gap-5 items-start">
                <div className="mt-1 grid h-10 w-10 shrink-0 place-items-center rounded-lg bg-indigo-500/20 text-indigo-400 border border-indigo-500/20">
                  <Brain size={20} />
                </div>
                <div>
                  <h4 className="text-base font-semibold text-white">AI Threat Detection</h4>
                  <p className="mt-1.5 text-sm text-slate-400 leading-relaxed">Real-time isolation forest models detecting anomalous transfer behaviors and preventing breaches.</p>
                </div>
              </div>
              <div className="flex gap-5 items-start">
                <div className="mt-1 grid h-10 w-10 shrink-0 place-items-center rounded-lg bg-emerald-500/20 text-emerald-400 border border-emerald-500/20">
                  <LinkIcon size={20} />
                </div>
                <div>
                  <h4 className="text-base font-semibold text-white">Tamper-Evident Ledgers</h4>
                  <p className="mt-1.5 text-sm text-slate-400 leading-relaxed">Blockchain-inspired cryptographic chains securing audit logs indefinitely against modification.</p>
                </div>
              </div>
            </div>
          </div>

          {/* Trust Elements */}
          <div className="mt-16 flex flex-wrap justify-center gap-8 opacity-60">
            <div className="flex items-center gap-2 text-sm font-medium text-slate-300">
              <CheckCircle2 size={16} className="text-cyan-400" /> SOC2 Compliant
            </div>
            <div className="flex items-center gap-2 text-sm font-medium text-slate-300">
              <CheckCircle2 size={16} className="text-cyan-400" /> ISO 27001
            </div>
            <div className="flex items-center gap-2 text-sm font-medium text-slate-300">
              <CheckCircle2 size={16} className="text-cyan-400" /> GDPR Ready
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
