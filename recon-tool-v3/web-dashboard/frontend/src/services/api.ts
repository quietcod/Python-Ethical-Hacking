import axios from 'axios'

// Create axios instance with base configuration
export const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || 'http://localhost:8000',
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
})

// Request interceptor to add auth token
api.interceptors.request.use(
  (config) => {
    // Token will be added by AuthContext when available
    return config
  },
  (error) => {
    return Promise.reject(error)
  }
)

// Response interceptor for error handling
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      // Token expired or invalid - will be handled by AuthContext
      window.location.href = '/auth/login'
    }
    return Promise.reject(error)
  }
)

// API service functions
export const authApi = {
  login: (credentials: { username: string; password: string }) =>
    api.post('/api/v1/users/login', credentials),
  
  register: (userData: { username: string; email: string; password: string; full_name?: string }) =>
    api.post('/api/v1/users/register', userData),
  
  getProfile: () =>
    api.get('/api/v1/users/me'),
  
  updateProfile: (data: { full_name?: string; email?: string }) =>
    api.put('/api/v1/users/me', data),
}

export const scansApi = {
  getScans: () =>
    api.get('/api/v1/scans'),
  
  getScan: (id: number) =>
    api.get(`/api/v1/scans/${id}`),
  
  createScan: (data: { target: string; scan_type: string; options?: Record<string, any> }) =>
    api.post('/api/v1/scans', data),
  
  updateScan: (id: number, data: { status?: string }) =>
    api.put(`/api/v1/scans/${id}`, data),
  
  deleteScan: (id: number) =>
    api.delete(`/api/v1/scans/${id}`),
  
  getScanResults: (id: number) =>
    api.get(`/api/v1/scans/${id}/results`),
}

export const reportsApi = {
  getReports: () =>
    api.get('/api/v1/reports'),
  
  getReport: (id: number) =>
    api.get(`/api/v1/reports/${id}`),
  
  createReport: (data: { scan_id: number; title: string; report_type: string; format: string }) =>
    api.post('/api/v1/reports', data),
  
  deleteReport: (id: number) =>
    api.delete(`/api/v1/reports/${id}`),
  
  downloadReport: (id: number) =>
    api.get(`/api/v1/reports/${id}/download`, { responseType: 'blob' }),
}

export const systemApi = {
  getHealth: () =>
    api.get('/health'),
  
  getVersion: () =>
    api.get('/'),
}
