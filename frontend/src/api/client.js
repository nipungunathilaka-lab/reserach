import axios from 'axios'

export const API_BASE_URL = import.meta.env.VITE_API_URL ? `${import.meta.env.VITE_API_URL}/api` : 'http://localhost:5000/api'

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 0,
})

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('secureft_token')
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

// Automatically unwrap { success: true, data: [...] } responses
api.interceptors.response.use(
  (response) => {
    if (response.data && response.data.success !== undefined && response.data.data !== undefined) {
      // Replace the axios response data with the unwrapped inner data
      response.data = response.data.data;
    }
    return response;
  },
  (error) => Promise.reject(error)
)

export const apiError = (error) => {
  if (error?.response?.data?.detail) return error.response.data.detail
  if (error?.response?.data?.error) return error.response.data.error
  if (error?.message) return error.message
  return 'Something went wrong'
}

export default api
