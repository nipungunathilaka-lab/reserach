import axios from 'axios'

export const API_BASE_URL = import.meta.env.VITE_API_URL ? `${import.meta.env.VITE_API_URL}/api` : 'http://localhost:8000/api'

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 0,
})

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('secureft_token')
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

export const apiError = (error) => {
  if (error?.response?.data?.detail) return error.response.data.detail
  if (error?.message) return error.message
  return 'Something went wrong'
}

export default api
