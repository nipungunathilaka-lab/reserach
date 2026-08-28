export default function StatCard({ icon: Icon, label, value, helper }) {
  return (
    <div className="rounded-2xl border border-white/10 bg-slate-900/40 p-6 shadow-xl backdrop-blur-md transition-all hover:border-white/20">
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="text-sm font-medium text-slate-400">{label}</p>
          <p className="mt-2 text-3xl font-bold tracking-tight text-white">{value}</p>
          {helper && <p className="mt-2 text-xs text-slate-500">{helper}</p>}
        </div>
        {Icon && <div className="rounded-xl border border-cyan-500/20 bg-cyan-500/10 p-3 text-cyan-400 shadow-[0_0_15px_-3px_rgba(34,211,238,0.2)]"><Icon size={22} /></div>}
      </div>
    </div>
  )
}
