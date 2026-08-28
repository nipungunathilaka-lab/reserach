import { Navigate, Route, Routes } from 'react-router-dom'
import ProtectedRoute from './components/ProtectedRoute'
import Layout from './components/Layout'
import Login from './pages/Login'
import Register from './pages/Register'
import VerifyOTP from './pages/VerifyOTP'
import Dashboard from './pages/Dashboard'
import FileVault from './pages/FileVault'
import SendFile from './pages/SendFile'
import ReceivedFiles from './pages/ReceivedFiles'
import TransferLogs from './pages/TransferLogs'
import BlockchainLogs from './pages/BlockchainLogs'
import AIAlerts from './pages/AIAlerts'
import Users from './pages/Users'
import DownloadFile from './pages/DownloadFile'

export default function App() {
  return (
    <div className="relative min-h-screen overflow-x-hidden bg-slate-950 font-sans text-slate-300">
      <div className="relative z-10 flex min-h-screen w-full flex-col">
        <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/register" element={<Register />} />
      <Route path="/verify-otp" element={<VerifyOTP />} />
      <Route path="/share/:token" element={<DownloadFile />} />
      <Route element={<ProtectedRoute><Layout /></ProtectedRoute>}>
        <Route index element={<Dashboard />} />
        <Route path="vault" element={<FileVault />} />
        <Route path="send" element={<SendFile />} />
        <Route path="received" element={<ReceivedFiles />} />
        <Route path="logs" element={<TransferLogs />} />
        <Route path="blockchain" element={<BlockchainLogs />} />
        <Route path="alerts" element={<AIAlerts />} />
        <Route path="users" element={<ProtectedRoute adminOnly><Users /></ProtectedRoute>} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </div>
    </div>
  )
}
