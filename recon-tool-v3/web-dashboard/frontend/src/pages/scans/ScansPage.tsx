import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { PlusIcon, PlayIcon, StopIcon, ClockIcon, CheckCircleIcon, XCircleIcon, CogIcon } from '@heroicons/react/24/outline'
import { useWebSocket } from '../../hooks/useWebSocket'
import { apiClient } from '../../lib/api'
import { ScanConfiguration, ScanTemplates } from '../../components/scans'
import { LoadingSpinner } from '../../components/ui/LoadingSpinner'

interface Scan {
  id: string
  name: string
  target: string
  profile: string
  tools: string[]
  status: 'pending' | 'running' | 'completed' | 'failed' | 'stopped'
  progress: number
  startTime: string
  endTime?: string
  duration?: number
  results?: any
}

export function ScansPage() {
  const [scans, setScans] = useState<Scan[]>([])
  const [loading, setLoading] = useState(true)
  const [showNewScan, setShowNewScan] = useState(false)
  const [showTemplates, setShowTemplates] = useState(false)
  const navigate = useNavigate()
  const { socket, connected } = useWebSocket()

  useEffect(() => {
    loadScans()
  }, [])

  useEffect(() => {
    if (socket) {
      socket.on('scan_progress', handleScanProgress)
      socket.on('scan_completed', handleScanCompleted)
      socket.on('scan_failed', handleScanFailed)

      return () => {
        socket.off('scan_progress')
        socket.off('scan_completed')
        socket.off('scan_failed')
      }
    }
  }, [socket])

  const loadScans = async () => {
    try {
      const response = await apiClient.get('/scans')
      setScans(response.data)
    } catch (error) {
      console.error('Failed to load scans:', error)
    } finally {
      setLoading(false)
    }
  }

  const handleScanProgress = (data: { scanId: string, progress: number, stage: string }) => {
    setScans(prev => prev.map(scan => 
      scan.id === data.scanId 
        ? { ...scan, progress: data.progress, status: 'running' }
        : scan
    ))
  }

  const handleScanCompleted = (data: { scanId: string, results: any }) => {
    setScans(prev => prev.map(scan => 
      scan.id === data.scanId 
        ? { ...scan, status: 'completed', progress: 100, results: data.results, endTime: new Date().toISOString() }
        : scan
    ))
  }

  const handleScanFailed = (data: { scanId: string, error: string }) => {
    setScans(prev => prev.map(scan => 
      scan.id === data.scanId 
        ? { ...scan, status: 'failed', endTime: new Date().toISOString() }
        : scan
    ))
  }

  const startScan = async (scanConfig: any) => {
    try {
      const response = await apiClient.post('/scans', scanConfig)
      const newScan = response.data
      setScans(prev => [newScan, ...prev])
      setShowNewScan(false)
    } catch (error) {
      console.error('Failed to start scan:', error)
    }
  }

  const stopScan = async (scanId: string) => {
    try {
      await apiClient.post(`/scans/${scanId}/stop`)
      setScans(prev => prev.map(scan => 
        scan.id === scanId ? { ...scan, status: 'stopped' } : scan
      ))
    } catch (error) {
      console.error('Failed to stop scan:', error)
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'pending': return 'text-yellow-600 bg-yellow-100'
      case 'running': return 'text-blue-600 bg-blue-100'
      case 'completed': return 'text-green-600 bg-green-100'
      case 'failed': return 'text-red-600 bg-red-100'
      case 'stopped': return 'text-gray-600 bg-gray-100'
      default: return 'text-gray-600 bg-gray-100'
    }
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'pending': return <ClockIcon className="h-4 w-4" />
      case 'running': return <PlayIcon className="h-4 w-4" />
      case 'completed': return <CheckCircleIcon className="h-4 w-4" />
      case 'failed': return <XCircleIcon className="h-4 w-4" />
      case 'stopped': return <StopIcon className="h-4 w-4" />
      default: return <ClockIcon className="h-4 w-4" />
    }
  }

  const formatDuration = (startTime: string, endTime?: string) => {
    const start = new Date(startTime)
    const end = endTime ? new Date(endTime) : new Date()
    const diff = end.getTime() - start.getTime()
    const minutes = Math.floor(diff / 60000)
    const seconds = Math.floor((diff % 60000) / 1000)
    return `${minutes}m ${seconds}s`
  }

  if (loading) {
    return <LoadingSpinner />
  }

  return (
    <div className="space-y-8">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold text-secondary-900">Reconnaissance Scans</h1>
          <p className="text-secondary-600 mt-1">
            Configure, execute, and monitor reconnaissance scans
          </p>
        </div>
        
        <div className="flex gap-3">
          <button
            onClick={() => setShowTemplates(true)}
            className="btn-secondary flex items-center gap-2"
          >
            <CogIcon className="h-4 w-4" />
            Templates
          </button>
          <button
            onClick={() => setShowNewScan(true)}
            className="btn-primary flex items-center gap-2"
          >
            <PlusIcon className="h-4 w-4" />
            New Scan
          </button>
        </div>
      </div>

      {/* Connection Status */}
      <div className={`card ${connected ? 'border-green-200 bg-green-50' : 'border-red-200 bg-red-50'}`}>
        <div className="card-body py-3">
          <div className="flex items-center gap-2">
            <div className={`w-2 h-2 rounded-full ${connected ? 'bg-green-500' : 'bg-red-500'}`} />
            <span className={`text-sm ${connected ? 'text-green-700' : 'text-red-700'}`}>
              {connected ? 'Connected to scan engine' : 'Disconnected from scan engine'}
            </span>
          </div>
        </div>
      </div>

      {/* Scans List */}
      <div className="card">
        <div className="card-header">
          <h2 className="text-xl font-semibold text-secondary-900">Recent Scans</h2>
        </div>
        <div className="card-body p-0">
          {scans.length === 0 ? (
            <div className="text-center py-16">
              <PlayIcon className="h-12 w-12 text-secondary-400 mx-auto mb-4" />
              <p className="text-secondary-600 mb-4">No scans yet</p>
              <button
                onClick={() => setShowNewScan(true)}
                className="btn-primary"
              >
                Start your first scan
              </button>
            </div>
          ) : (
            <div className="divide-y divide-secondary-200">
              {scans.map((scan) => (
                <div key={scan.id} className="p-6 hover:bg-secondary-50 transition-colors">
                  <div className="flex items-center justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-3 mb-2">
                        <h3 className="font-medium text-secondary-900">{scan.name}</h3>
                        <span className={`inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(scan.status)}`}>
                          {getStatusIcon(scan.status)}
                          {scan.status.charAt(0).toUpperCase() + scan.status.slice(1)}
                        </span>
                      </div>
                      
                      <div className="text-sm text-secondary-600 space-y-1">
                        <p><span className="font-medium">Target:</span> {scan.target}</p>
                        <p><span className="font-medium">Profile:</span> {scan.profile}</p>
                        <p><span className="font-medium">Tools:</span> {scan.tools.join(', ')}</p>
                        <p><span className="font-medium">Duration:</span> {formatDuration(scan.startTime, scan.endTime)}</p>
                      </div>

                      {scan.status === 'running' && (
                        <div className="mt-3">
                          <div className="flex justify-between text-xs text-secondary-600 mb-1">
                            <span>Progress</span>
                            <span>{scan.progress}%</span>
                          </div>
                          <div className="w-full bg-secondary-200 rounded-full h-2">
                            <div 
                              className="bg-primary-600 h-2 rounded-full transition-all duration-300"
                              style={{ width: `${scan.progress}%` }}
                            />
                          </div>
                        </div>
                      )}
                    </div>

                    <div className="flex items-center gap-2">
                      {scan.status === 'running' && (
                        <button
                          onClick={() => stopScan(scan.id)}
                          className="btn-secondary text-red-600 hover:bg-red-50"
                        >
                          <StopIcon className="h-4 w-4" />
                        </button>
                      )}
                      <button
                        onClick={() => navigate(`/scans/${scan.id}`)}
                        className="btn-secondary"
                      >
                        View Details
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* New Scan Modal */}
      {showNewScan && (
        <ScanConfiguration
          onClose={() => setShowNewScan(false)}
          onSubmit={startScan}
        />
      )}

      {/* Templates Modal */}
      {showTemplates && (
        <ScanTemplates
          onClose={() => setShowTemplates(false)}
          onSelectTemplate={(_template: any) => {
            setShowTemplates(false)
            setShowNewScan(true)
          }}
        />
      )}
    </div>
  )
}
