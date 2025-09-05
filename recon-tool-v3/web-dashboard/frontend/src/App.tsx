import React from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import { useAuth } from './hooks/useAuth'

// Layout Components
import { AppLayout } from './components/layout/AppLayout'
import { AuthLayout } from './components/layout/AuthLayout'

// Pages
import { LoginPage } from './pages/auth/LoginPage'
import { RegisterPage } from './pages/auth/RegisterPage'
import { DashboardPage } from './pages/dashboard/DashboardPage'
import { ScansPage } from './pages/scans/ScansPage'
import { ScanDetailPage } from './pages/scans/ScanDetailPage'
import { ReportsPage } from './pages/reports/ReportsPage'
import { ReportDetailPage } from './pages/reports/ReportDetailPage'
import { SettingsPage } from './pages/settings/SettingsPage'
import { NotFoundPage } from './pages/error/NotFoundPage'

// Loading Components
import { LoadingSpinner } from './components/ui/LoadingSpinner'

function App() {
  const { isAuthenticated, isLoading } = useAuth()

  if (isLoading) {
    return (
      <div className="min-h-screen center bg-secondary-50">
        <LoadingSpinner size="lg" />
      </div>
    )
  }

  return (
    <Routes>
      {/* Authentication Routes */}
      <Route
        path="/auth/*"
        element={
          isAuthenticated ? (
            <Navigate to="/dashboard" replace />
          ) : (
            <AuthLayout>
              <Routes>
                <Route path="login" element={<LoginPage />} />
                <Route path="register" element={<RegisterPage />} />
                <Route path="*" element={<Navigate to="/auth/login" replace />} />
              </Routes>
            </AuthLayout>
          )
        }
      />

      {/* Protected Routes */}
      <Route
        path="/*"
        element={
          isAuthenticated ? (
            <AppLayout>
              <Routes>
                <Route path="/" element={<Navigate to="/dashboard" replace />} />
                <Route path="/dashboard" element={<DashboardPage />} />
                <Route path="/scans" element={<ScansPage />} />
                <Route path="/scans/:id" element={<ScanDetailPage />} />
                <Route path="/reports" element={<ReportsPage />} />
                <Route path="/reports/:id" element={<ReportDetailPage />} />
                <Route path="/settings" element={<SettingsPage />} />
                <Route path="*" element={<NotFoundPage />} />
              </Routes>
            </AppLayout>
          ) : (
            <Navigate to="/auth/login" replace />
          )
        }
      />
    </Routes>
  )
}

export default App
