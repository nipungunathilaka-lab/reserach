import { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { ShieldCheck, ChevronRight, CheckCircle2 } from 'lucide-react'
import { QRCodeSVG } from 'qrcode.react'
import { useAuth } from '../auth/AuthContext'

export default function Register() {
  const navigate = useNavigate()
  const { startRegister } = useAuth()
  const [fullName, setFullName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [role, setRole] = useState('user')
  const [companyName, setCompanyName] = useState('')
  const [jobRole, setJobRole] = useState('')
  const [loading, setLoading] = useState(false)
  const [apiError, setApiError] = useState('')
  const [fieldErrors, setFieldErrors] = useState({})
  const [provisioningUri, setProvisioningUri] = useState('')

  const validate = () => {
    const errors = {}
    if (!fullName.trim() || fullName.length < 2) errors.fullName = "Name must be at least 2 characters."
    if (!email.includes('@')) errors.email = "Please enter a valid email address."
    if (password.length < 8) errors.password = "Password must be at least 8 characters."
    setFieldErrors(errors)
    return Object.keys(errors).length === 0
  }

  const submitRegister = async (e) => {
    e.preventDefault()
    setApiError('')
    if (!validate()) return

    setLoading(true)
    try {
      const res = await startRegister(fullName.trim(), email.trim(), password, role, companyName.trim(), jobRole)
      setProvisioningUri(res.provisioning_uri)
    } catch (err) {
      setApiError(err.message || 'Failed to create account. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="flex min-h-screen w-full bg-slate-950 text-slate-300">
      {/* Left Panel - Auth Form */}
      <div className="flex w-full flex-col justify-center px-6 py-12 lg:w-1/2 lg:px-20 xl:px-32 relative z-10 bg-slate-950 shadow-2xl">
        
        {/* Mobile Branding (Hidden on Desktop) */}
        <div className="mb-10 flex items-center gap-3 lg:hidden">
          <div className="grid h-10 w-10 place-items-center rounded-xl bg-cyan-400 text-slate-950 shadow-glow">
            <ShieldCheck size={20} />
          </div>
          <span className="text-xl font-bold tracking-tight text-white">SecureFT</span>
        </div>

        <div className="w-full max-w-md mx-auto lg:mx-0">
          {!provisioningUri ? (
            <>
              <h2 className="text-3xl font-semibold tracking-tight text-white sm:text-4xl">Join the Private Beta for Enterprise File Security</h2>
              <p className="mt-2 text-sm text-slate-400">Help us evaluate next-generation ECDH encryption & AI anomaly detection.</p>

              {apiError && (
                <div className="mt-6 rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-400">
                  {apiError}
                </div>
              )}

              <form onSubmit={submitRegister} className="mt-8 grid gap-5">
                <div className="grid gap-1.5">
                  <label className="text-xs font-semibold text-slate-300">Full Name</label>
                  <input 
                    type="text" 
                    value={fullName} 
                    onChange={e => {setFullName(e.target.value); setFieldErrors(p => ({...p, fullName: null}))}}
                    className={`w-full rounded-lg border bg-slate-900/50 px-4 py-2.5 text-sm text-white outline-none transition focus:border-cyan-400 focus:bg-slate-900 focus:ring-1 focus:ring-cyan-400 ${fieldErrors.fullName ? 'border-red-500/50 focus:border-red-500 focus:ring-red-500' : 'border-white/10'}`} 
                    placeholder="Jane Doe" 
                  />
                  {fieldErrors.fullName && <p className="text-xs text-red-400">{fieldErrors.fullName}</p>}
                </div>

                <div className="grid gap-1.5">
                  <label className="text-xs font-semibold text-slate-300">Email Address</label>
                  <input 
                    type="email" 
                    value={email} 
                    onChange={e => {setEmail(e.target.value); setFieldErrors(p => ({...p, email: null}))}}
                    className={`w-full rounded-lg border bg-slate-900/50 px-4 py-2.5 text-sm text-white outline-none transition focus:border-cyan-400 focus:bg-slate-900 focus:ring-1 focus:ring-cyan-400 ${fieldErrors.email ? 'border-red-500/50 focus:border-red-500 focus:ring-red-500' : 'border-white/10'}`} 
                    placeholder="jane@example.com" 
                  />
                  {fieldErrors.email && <p className="text-xs text-red-400">{fieldErrors.email}</p>}
                </div>

                <div className="grid gap-4 sm:grid-cols-2">
                  <div className="grid gap-1.5">
                    <label className="text-xs font-semibold text-slate-300">Company / University Name</label>
                    <input 
                      type="text" 
                      value={companyName} 
                      onChange={e => setCompanyName(e.target.value)}
                      className="w-full rounded-lg border border-white/10 bg-slate-900/50 px-4 py-2.5 text-sm text-white outline-none transition focus:border-cyan-400 focus:bg-slate-900 focus:ring-1 focus:ring-cyan-400" 
                      placeholder="Acme Corp" 
                    />
                  </div>

                  <div className="grid gap-1.5">
                    <label className="text-xs font-semibold text-slate-300">Job Role</label>
                    <select 
                      value={jobRole} 
                      onChange={e => setJobRole(e.target.value)}
                      className="w-full rounded-lg border border-white/10 bg-slate-900/50 px-4 py-2.5 text-sm text-white outline-none transition focus:border-cyan-400 focus:bg-slate-900 focus:ring-1 focus:ring-cyan-400 appearance-none"
                    >
                      <option value="" disabled>Select a role...</option>
                      <option value="Developer">Developer</option>
                      <option value="Manager">Manager</option>
                      <option value="IT Admin">IT Admin</option>
                      <option value="Researcher">Researcher</option>
                      <option value="Student">Student</option>
                      <option value="Other">Other</option>
                    </select>
                  </div>
                </div>

                <div className="grid gap-4 sm:grid-cols-2">
                  <div className="grid gap-1.5">
                    <label className="text-xs font-semibold text-slate-300">Password</label>
                    <input 
                      type="password" 
                      value={password} 
                      onChange={e => {setPassword(e.target.value); setFieldErrors(p => ({...p, password: null}))}}
                      className={`w-full rounded-lg border bg-slate-900/50 px-4 py-2.5 text-sm text-white outline-none transition focus:border-cyan-400 focus:bg-slate-900 focus:ring-1 focus:ring-cyan-400 ${fieldErrors.password ? 'border-red-500/50 focus:border-red-500 focus:ring-red-500' : 'border-white/10'}`} 
                      placeholder="••••••••" 
                    />
                    {fieldErrors.password && <p className="text-xs text-red-400">{fieldErrors.password}</p>}
                  </div>

                  <div className="grid gap-1.5">
                    <label className="text-xs font-semibold text-slate-300">Account Role</label>
                    <select 
                      value={role} 
                      onChange={e => setRole(e.target.value)}
                      className="w-full rounded-lg border border-white/10 bg-slate-900/50 px-4 py-2.5 text-sm text-white outline-none transition focus:border-cyan-400 focus:bg-slate-900 focus:ring-1 focus:ring-cyan-400 appearance-none"
                    >
                      <option value="user">User</option>
                      <option value="manager">Manager</option>
                      <option value="admin">Administrator</option>
                    </select>
                  </div>
                </div>

                <button 
                  type="submit" 
                  disabled={loading}
                  className="mt-2 flex w-full items-center justify-center rounded-lg bg-white px-4 py-2.5 text-sm font-semibold text-slate-900 transition hover:bg-slate-200 focus:outline-none focus:ring-2 focus:ring-white focus:ring-offset-2 focus:ring-offset-slate-950 disabled:opacity-70 shadow-md"
                >
                  {loading ? 'Creating account...' : 'Create Account'}
                </button>
              </form>

              <p className="mt-8 text-center text-sm text-slate-400">
                Already have an account?{' '}
                <Link to="/login" className="font-semibold text-white hover:text-cyan-300 transition">
                  Sign in
                </Link>
              </p>
            </>
          ) : (
            <div className="flex flex-col items-center text-center animate-in fade-in zoom-in duration-500">
              <div className="mb-6 flex h-16 w-16 items-center justify-center rounded-full bg-green-500/10 text-green-400">
                <CheckCircle2 size={32} />
              </div>
              <h2 className="text-2xl font-bold text-white">Account Created!</h2>
              <p className="mt-2 text-sm text-slate-400">Scan this QR code with your preferred Authenticator app to enable Two-Factor Authentication.</p>
              
              <div className="mt-8 rounded-2xl bg-white p-6 shadow-2xl">
                <QRCodeSVG value={provisioningUri} size={200} />
              </div>
              
              <p className="mt-6 text-xs text-slate-500">Required for first login.</p>
              
              <Link 
                to="/login" 
                className="mt-8 flex w-full items-center justify-center gap-2 rounded-lg bg-cyan-500 px-4 py-2.5 text-sm font-semibold text-slate-950 transition hover:bg-cyan-400"
              >
                Proceed to Sign In <ChevronRight size={16} />
              </Link>
            </div>
          )}
        </div>
      </div>

      {/* Right Panel - Branding / Marketing */}
      <div className="hidden lg:flex lg:w-1/2 relative flex-col justify-between overflow-hidden bg-slate-900 p-12">
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top_right,_var(--tw-gradient-stops))] from-cyan-900/40 via-slate-900/20 to-slate-950 z-0 opacity-80" />
        <div className="absolute -top-40 -right-40 h-96 w-96 rounded-full bg-cyan-500/10 blur-[100px] pointer-events-none" />
        <div className="absolute -bottom-40 -left-40 h-96 w-96 rounded-full bg-indigo-500/10 blur-[100px] pointer-events-none" />

        <div className="relative z-10 flex items-center gap-3">
          <div className="grid h-12 w-12 place-items-center rounded-xl bg-cyan-400 text-slate-950 shadow-glow">
            <ShieldCheck size={24} />
          </div>
          <span className="text-2xl font-bold tracking-tight text-white">SecureFT</span>
        </div>

        <div className="relative z-10 max-w-lg pb-20">
          <h3 className="text-3xl font-medium leading-snug text-white">
            "The industry standard for secure, immutable file transfers."
          </h3>
          
          <div className="mt-10 grid gap-6">
            <div className="flex gap-4">
              <div className="mt-1 h-2 w-2 rounded-full bg-cyan-400 shadow-glow" />
              <div>
                <h4 className="text-sm font-semibold text-white">Hybrid Cryptography</h4>
                <p className="mt-1 text-sm text-slate-400">P-256 ECDH Forward Secrecy combined with AES-256-GCM payload encryption.</p>
              </div>
            </div>
            <div className="flex gap-4">
              <div className="mt-1 h-2 w-2 rounded-full bg-cyan-400 shadow-glow" />
              <div>
                <h4 className="text-sm font-semibold text-white">AI Threat Detection</h4>
                <p className="mt-1 text-sm text-slate-400">Real-time isolation forest models detecting anomalous transfer behaviors.</p>
              </div>
            </div>
            <div className="flex gap-4">
              <div className="mt-1 h-2 w-2 rounded-full bg-cyan-400 shadow-glow" />
              <div>
                <h4 className="text-sm font-semibold text-white">Tamper-Evident Ledgers</h4>
                <p className="mt-1 text-sm text-slate-400">Blockchain-inspired cryptographic chains securing audit logs indefinitely.</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
