import { useState } from 'react'
import { NavLink, Outlet } from 'react-router-dom'
import { AlertTriangle, Blocks, FileClock, FileInput, Inbox, LayoutDashboard, LogOut, ShieldCheck, Users, Archive, Bell } from 'lucide-react'
import { Toaster } from 'react-hot-toast'
import { useAuth } from '../auth/AuthContext'

const links = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard },
  { to: '/vault', label: 'File Vault', icon: Archive },
  { to: '/send', label: 'Send File', icon: FileInput },
  { to: '/received', label: 'Received Files', icon: Inbox },
  { to: '/logs', label: 'Transfer Logs', icon: FileClock },
  { to: '/blockchain', label: 'Blockchain Logs', icon: Blocks },
  { to: '/alerts', label: 'AI Alerts', icon: AlertTriangle },
]

export default function Layout() {
  const { user, logout } = useAuth()
  const allLinks = user?.role === 'admin' ? [...links, { to: '/users', label: 'Users', icon: Users }] : links

  const [showNotifications, setShowNotifications] = useState(false)
  const [hasUnread, setHasUnread] = useState(true)
  const [notifications] = useState([
    { id: 1, title: 'Transfer Complete', message: 'File encrypted and sent to Alice', time: 'Just now', unread: true },
    { id: 2, title: 'AI Scan', message: 'Scan completed successfully: Normal', time: '2 mins ago', unread: false },
  ])


  return (
    <div className="relative min-h-screen overflow-x-hidden bg-slate-950 font-sans text-white">
      {/* Background Gradients & Grid */}
      <div className="fixed inset-0 z-0 bg-[linear-gradient(to_right,#80808012_1px,transparent_1px),linear-gradient(to_bottom,#80808012_1px,transparent_1px)] bg-[size:24px_24px] pointer-events-none" />
      <div className="fixed -top-40 -right-40 z-0 h-[600px] w-[600px] rounded-full bg-cyan-500/10 blur-[150px] pointer-events-none" />
      <div className="fixed -bottom-40 -left-40 z-0 h-[600px] w-[600px] rounded-full bg-blue-600/10 blur-[150px] pointer-events-none" />
      <div className="fixed top-1/2 left-1/2 z-0 -translate-x-1/2 -translate-y-1/2 h-[500px] w-[500px] rounded-full bg-indigo-500/10 blur-[150px] pointer-events-none" />
      <Toaster
        position="top-right"
        toastOptions={{
          style: {
            background: '#0f172a',
            color: '#fff',
            border: '1px solid rgba(34,211,238,0.3)',
            boxShadow: '0 0 20px rgba(34,211,238,0.15)',
            backdropFilter: 'blur(12px)',
          }
        }}
      />

      <div className="relative z-10 flex min-h-screen w-full flex-col lg:flex-row">
        <aside className="border-b border-white/5 bg-slate-900/40 p-4 backdrop-blur-md lg:sticky lg:top-0 lg:h-screen lg:w-72 lg:shrink-0 lg:border-b-0 lg:border-r">
          <div className="mb-6 flex items-center justify-between gap-3 lg:mb-10 lg:block">
            <div className="flex min-w-0 items-center gap-4">
              <div className="grid h-12 w-12 shrink-0 place-items-center rounded-2xl bg-cyan-400 text-slate-950 shadow-[0_0_20px_-5px_rgba(34,211,238,0.5)]">
                <ShieldCheck size={24} />
              </div>
              <div className="min-w-0">
                <h1 className="truncate text-lg font-black tracking-tight">UPCE</h1>
                <p className="truncate text-xs text-slate-400">Universal Polymorphic Cryptographic Engine</p>
              </div>
            </div>
            <button onClick={logout} className="rounded-xl border border-white/10 bg-white/5 p-2.5 text-slate-400 transition hover:bg-white/10 hover:text-white lg:hidden"><LogOut size={18} /></button>
          </div>
          <nav className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-1">
            {allLinks.map(({ to, label, icon: Icon }) => (
              <NavLink key={to} to={to} end={to === '/'} className={({ isActive }) =>
                `flex min-w-0 items-center gap-3 rounded-xl px-4 py-3.5 text-sm font-semibold transition-all duration-200 ${isActive ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 shadow-[0_0_15px_-3px_rgba(34,211,238,0.15)]' : 'border border-transparent text-slate-400 hover:bg-white/5 hover:text-slate-200'}`
              }>
                <Icon className="shrink-0" size={18} /> <span className="truncate">{label}</span>
              </NavLink>
            ))}
          </nav>
        </aside>
        <main className="min-w-0 flex-1 p-4 sm:p-6 lg:p-10">
          <header className="mb-6 flex flex-col justify-between gap-4 rounded-2xl border border-white/10 bg-slate-900/40 p-5 shadow-xl backdrop-blur-md md:mb-10 md:flex-row md:items-center">
            <div className="min-w-0">
              <p className="text-xs font-semibold uppercase tracking-wider text-cyan-400">AES-256 · ChaCha20 · Hybrid PQC (Kyber) · Blockchain</p>
              <h2 className="mt-1 text-2xl font-bold tracking-tight text-white">Universal Polymorphic Cryptographic Engine (UPCE)</h2>
            </div>
            <div className="flex items-center justify-between gap-4 md:justify-end">
              <div className="relative">
                <button
                  onClick={() => {
                    setShowNotifications(!showNotifications)
                    if (!showNotifications) setHasUnread(false)
                  }}
                  className="relative rounded-xl border border-white/10 bg-white/5 p-2.5 text-slate-300 transition hover:bg-white/10 hover:text-white focus:outline-none"
                >
                  <Bell size={18} />
                  {hasUnread && (
                    <span className="absolute -top-1 -right-1 flex h-3 w-3">
                      <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-cyan-400 opacity-75"></span>
                      <span className="relative inline-flex h-3 w-3 rounded-full bg-cyan-500 shadow-[0_0_10px_rgba(34,211,238,0.8)]"></span>
                    </span>
                  )}
                </button>

                {/* Notification Dropdown */}
                {showNotifications && (
                  <div className="absolute right-0 mt-3 w-80 overflow-hidden rounded-2xl border border-white/10 bg-slate-900/95 p-2 shadow-2xl backdrop-blur-xl animate-in fade-in slide-in-from-top-2 z-50">
                    <div className="mb-2 px-3 py-2 border-b border-white/10">
                      <h3 className="text-sm font-bold tracking-tight text-white">Notifications</h3>
                    </div>
                    <div className="flex max-h-80 flex-col gap-1 overflow-y-auto">
                      {notifications.length === 0 ? (
                        <div className="p-4 text-center text-sm text-slate-400">No new notifications</div>
                      ) : (
                        notifications.map(n => (
                          <div key={n.id} className={`flex flex-col gap-1 rounded-xl p-3 transition hover:bg-white/5 cursor-pointer ${n.unread ? 'bg-cyan-500/5' : ''}`}>
                            <div className="flex justify-between items-center">
                              <span className={`text-xs font-bold ${n.unread ? 'text-cyan-400' : 'text-slate-300'}`}>{n.title}</span>
                              <span className="text-[10px] text-slate-500">{n.time}</span>
                            </div>
                            <p className="text-xs text-slate-400 leading-snug">{n.message}</p>
                          </div>
                        ))
                      )}
                    </div>
                  </div>
                )}
              </div>
              <div className="h-8 w-px bg-white/10 hidden md:block"></div>
              <div className="min-w-0 text-left md:text-right hidden sm:block">
                <p className="truncate text-sm font-bold text-slate-200">{user?.full_name}</p>
                <p className="text-xs uppercase tracking-widest text-slate-500">{user?.role}</p>
              </div>
              <button onClick={logout} className="hidden shrink-0 items-center gap-2 rounded-xl border border-white/10 bg-white/5 px-4 py-2 text-sm font-semibold text-slate-300 transition hover:bg-white/10 hover:text-white md:inline-flex"><LogOut size={16} /> Logout</button>
            </div>
          </header>
          <Outlet />
        </main>
      </div>
    </div>
  )
}
