import React, { createContext, useContext, useEffect, useState } from 'react'
import Cookies from 'js-cookie'
import { api } from '../services/api'
import type { User } from '../types/auth'

interface AuthContextType {
  user: User | null
  token: string | null
  isAuthenticated: boolean
  isLoading: boolean
  login: (email: string, password: string) => Promise<void>
  register: (userData: RegisterData) => Promise<void>
  logout: () => void
  refreshUser: () => Promise<void>
}

interface RegisterData {
  username: string
  email: string
  password: string
  full_name?: string
}

export const AuthContext = createContext<AuthContextType | undefined>(undefined)

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [token, setToken] = useState<string | null>(null)
  const [isLoading, setIsLoading] = useState(true)

  const isAuthenticated = Boolean(user && token)

  // Initialize auth state from stored token
  useEffect(() => {
    const initializeAuth = async () => {
      try {
        const storedToken = Cookies.get('auth_token')
        if (storedToken) {
          setToken(storedToken)
          api.defaults.headers.common['Authorization'] = `Bearer ${storedToken}`
          
          // Verify token and get user data
          const response = await api.get('/api/v1/users/me')
          setUser(response.data)
        }
      } catch (error) {
        // Token is invalid, clear it
        Cookies.remove('auth_token')
        delete api.defaults.headers.common['Authorization']
      } finally {
        setIsLoading(false)
      }
    }

    initializeAuth()
  }, [])

  const login = async (email: string, password: string) => {
    try {
      setIsLoading(true)
      
      // Login request
      const loginResponse = await api.post('/api/v1/users/login', {
        username: email, // Backend expects username field
        password,
      })

      const { access_token } = loginResponse.data
      
      // Store token
      Cookies.set('auth_token', access_token, { expires: 7 }) // 7 days
      setToken(access_token)
      api.defaults.headers.common['Authorization'] = `Bearer ${access_token}`

      // Get user profile
      const userResponse = await api.get('/api/v1/users/me')
      setUser(userResponse.data)
    } catch (error) {
      // Clear any partial state
      Cookies.remove('auth_token')
      delete api.defaults.headers.common['Authorization']
      setToken(null)
      setUser(null)
      throw error
    } finally {
      setIsLoading(false)
    }
  }

  const register = async (userData: RegisterData) => {
    try {
      setIsLoading(true)
      
      // Register user
      await api.post('/api/v1/users/register', userData)
      
      // Auto-login after registration
      await login(userData.email, userData.password)
    } catch (error) {
      setIsLoading(false)
      throw error
    }
  }

  const logout = () => {
    Cookies.remove('auth_token')
    delete api.defaults.headers.common['Authorization']
    setToken(null)
    setUser(null)
  }

  const refreshUser = async () => {
    if (!token) return
    
    try {
      const response = await api.get('/api/v1/users/me')
      setUser(response.data)
    } catch (error) {
      // Token might be expired, logout
      logout()
      throw error
    }
  }

  const value: AuthContextType = {
    user,
    token,
    isAuthenticated,
    isLoading,
    login,
    register,
    logout,
    refreshUser,
  }

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const context = useContext(AuthContext)
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}
