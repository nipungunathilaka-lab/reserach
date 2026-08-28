import { useEffect, useState } from 'react'
import { Plus, RefreshCw, Trash2 } from 'lucide-react'
import api, { apiError } from '../api/client'
import ErrorBanner from '../components/ErrorBanner'

const blankUser = { full_name: '', email: '', password: '', role: 'user' }

export default function Users() {
  const [users, setUsers] = useState([])
  const [form, setForm] = useState(blankUser)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')

  const load = () => {
    setLoading(true)
    setError('')
    api.get('/users')
      .then(res => setUsers(res.data))
      .catch(err => setError(apiError(err)))
      .finally(() => setLoading(false))
  }

  useEffect(() => { load() }, [])

  const createUser = async (e) => {
    e.preventDefault()
    setSaving(true)
    setError('')
    setNotice('')
    try {
      await api.post('/users', { ...form, email: form.email.trim(), full_name: form.full_name.trim() })
      setForm(blankUser)
      setNotice('User created successfully. RSA/ECDH key pairs were generated automatically.')
      load()
    } catch (err) {
      setError(apiError(err))
    } finally {
      setSaving(false)
    }
  }

  const updateUser = async (id, payload) => {
    setError('')
    setNotice('')
    try {
      await api.patch(`/users/${id}`, payload)
      setNotice('User updated successfully.')
      load()
    } catch (err) {
      setError(apiError(err))
    }
  }

  const deleteUser = async (id) => {
    if (!window.confirm('Delete this user? Users with transfer history cannot be deleted.')) return
    setError('')
    setNotice('')
    try {
      await api.delete(`/users/${id}`)
      setNotice('User deleted successfully.')
      load()
    } catch (err) {
      setError(apiError(err))
    }
  }

  if (loading) return <p className="text-slate-300">Loading users...</p>
  return (
    <div className="grid gap-6 xl:grid-cols-[.8fr_1.2fr]">
      <section className="card p-4 sm:p-5">
        <h3 className="text-2xl font-black">Create User</h3>
        <p className="mt-1 text-sm text-slate-400">Admin-created users use password + email OTP MFA. Passwords must contain letters and numbers. Key pairs are generated automatically.</p>
        <form onSubmit={createUser} className="mt-5 grid gap-4">
          <ErrorBanner message={error} />
          {notice && <p className="rounded-2xl border border-emerald-400/20 bg-emerald-500/10 p-4 text-sm text-emerald-100">{notice}</p>}
          <label className="grid gap-2 text-sm text-slate-300">Full name
            <input className="input" value={form.full_name} onChange={e => setForm({...form, full_name: e.target.value})} required minLength={2} />
          </label>
          <label className="grid gap-2 text-sm text-slate-300">Email
            <input className="input" type="email" value={form.email} onChange={e => setForm({...form, email: e.target.value})} required />
          </label>
          <label className="grid gap-2 text-sm text-slate-300">Temporary password
            <span className="text-xs text-slate-500">Minimum 10 characters with letters and numbers.</span>
            <input className="input" type="password" value={form.password} onChange={e => setForm({...form, password: e.target.value})} required minLength={10} />
          </label>
          <label className="grid gap-2 text-sm text-slate-300">Role
            <select className="input" value={form.role} onChange={e => setForm({...form, role: e.target.value})}>
              <option value="user">User</option>
              <option value="admin">Admin</option>
            </select>
          </label>
          <button className="btn-primary" disabled={saving}><Plus size={16}/>{saving ? 'Creating...' : 'Create user'}</button>
        </form>
      </section>

      <section className="card p-4 sm:p-5">
        <div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-center">
          <div>
            <h3 className="text-2xl font-black">Users</h3>
            <p className="mt-1 text-sm text-slate-400">Admin-only management. Transfer history is preserved for audit integrity.</p>
          </div>
          <button className="btn-secondary" onClick={load}><RefreshCw size={16}/>Refresh</button>
        </div>

        <div className="mt-4 grid gap-3 md:hidden">
          {users.map(u => <article key={u.id} className="rounded-3xl border border-white/10 bg-white/5 p-4">
            <div className="flex items-start justify-between gap-3"><div className="min-w-0"><p className="truncate font-bold">{u.full_name}</p><p className="truncate text-xs text-slate-400">{u.email}</p></div><span className="rounded-xl border border-emerald-400/20 bg-emerald-500/10 px-2 py-1 text-xs text-emerald-100">MFA</span></div>
            <div className="mt-4 grid gap-3 sm:grid-cols-2"><select className="input py-2" value={u.role} onChange={e => updateUser(u.id, { role: e.target.value })}><option value="user">User</option><option value="admin">Admin</option></select><button className="btn-secondary py-2" onClick={() => deleteUser(u.id)}><Trash2 size={15}/>Delete</button></div>
            <p className="mt-3 text-xs text-slate-500">Created {new Date(u.created_at).toLocaleString()}</p><p className="mt-1 text-xs text-slate-500">Failed logins: {u.failed_login_attempts || 0}{u.locked_until ? ` · Locked until ${new Date(u.locked_until).toLocaleString()}` : ""}</p>
          </article>)}
          {!users.length && <p className="rounded-2xl bg-white/5 p-5 text-center text-sm text-slate-400">No users found.</p>}
        </div>

        <div className="mt-4 hidden overflow-x-auto md:block">
          <table className="w-full min-w-[900px] text-left text-sm">
            <thead className="text-slate-400"><tr><th className="py-3">Name</th><th>Email</th><th>Role</th><th>MFA</th><th>Login security</th><th>Created</th><th>Actions</th></tr></thead>
            <tbody>
              {users.map(u => <tr key={u.id} className="border-t border-white/10">
                <td className="py-3 font-semibold">{u.full_name}</td>
                <td>{u.email}</td>
                <td><select className="input py-2" value={u.role} onChange={e => updateUser(u.id, { role: e.target.value })}><option value="user">User</option><option value="admin">Admin</option></select></td>
                <td><span className="rounded-xl border border-emerald-400/20 bg-emerald-500/10 px-3 py-2 text-emerald-100">Enabled</span></td>
                <td><span className={u.locked_until ? "text-red-200" : "text-slate-300"}>{u.locked_until ? `Locked until ${new Date(u.locked_until).toLocaleString()}` : `Failed: ${u.failed_login_attempts || 0}`}</span></td>
                <td>{new Date(u.created_at).toLocaleString()}</td>
                <td className="py-2"><button className="btn-secondary py-2" onClick={() => deleteUser(u.id)}><Trash2 size={15}/>Delete</button></td>
              </tr>)}
              {!users.length && <tr><td colSpan="7" className="py-6 text-center text-slate-400">No users found.</td></tr>}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  )
}
