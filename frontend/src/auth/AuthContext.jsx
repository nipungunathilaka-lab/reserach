import { createContext, useContext, useEffect, useMemo, useState } from 'react'
import api, { apiError } from '../api/client'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    const token = localStorage.getItem('secureft_token')
    if (!token) {
      setLoading(false)
      return
    }
    api.get('/auth/me')
      .then((res) => setUser(res.data))
      .catch(() => localStorage.removeItem('secureft_token'))
      .finally(() => setLoading(false))
  }, [])

  const startLogin = async (email, password) => {
    setError('')
    try {
      const res = await api.post('/auth/login', { email, password })
      if (res.data.access_token) {
        localStorage.setItem('secureft_token', res.data.access_token)
        setUser(res.data.user)
      }
      return res.data
    } catch (err) {
      const message = apiError(err)
      setError(message)
      throw new Error(message)
    }
  }

  const startRegister = async (fullName, email, password, role = 'user', companyName = '', jobRole = '') => {
    setError('')
    try {
      const res = await api.post('/auth/register', { 
        full_name: fullName, 
        email, 
        password, 
        role,
        company_name: companyName,
        job_role: jobRole
      })
      return res.data
    } catch (err) {
      const message = apiError(err)
      setError(message)
      throw new Error(message)
    }
  }

  const verifyMfa = async (challengeId, otp) => {
    setError('')
    try {
      const res = await api.post('/auth/verify-mfa', { challenge_id: challengeId, otp })
      localStorage.setItem('secureft_token', res.data.access_token)
      setUser(res.data.user)
      return res.data.user
    } catch (err) {
      const message = apiError(err)
      setError(message)
      throw new Error(message)
    }
  }

  const resendMfa = async (challengeId) => {
    setError('')
    try {
      const res = await api.post('/auth/resend-mfa', { challenge_id: challengeId })
      return res.data
    } catch (err) {
      const message = apiError(err)
      setError(message)
      throw new Error(message)
    }
  }

  const logout = () => {
    localStorage.removeItem('secureft_token')
    setUser(null)
  }

  const value = useMemo(() => ({ user, loading, error, startLogin, startRegister, verifyMfa, resendMfa, logout }), [user, loading, error])
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export const useAuth = () => useContext(AuthContext)
