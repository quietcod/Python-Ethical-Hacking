import { useState, useEffect } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { ArrowLeftIcon, PlayIcon, StopIcon, ClockIcon, CheckCircleIcon, XCircleIcon, DocumentArrowDownIcon } from '@heroicons/react/24/outline'
import { useWebSocket } from '../../hooks/useWebSocket'
import { apiClient } from '../../lib/api'
import { LoadingSpinner } from '../../components/ui/LoadingSpinner'

interface ScanDetail {
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
  logs?: string[]
  toolResults?: Record<string, any>
}

export function ScanDetailPage() {
  const { id } = useParams<{ id: string }>()
  const [scan, setScan] = useState<ScanDetail | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const navigate = useNavigate()
  const { socket, connected } = useWebSocket()

  useEffect(() => {
    if (id) {
      loadScan(id)
    }
  }, [id])

  useEffect(() => {
    if (socket && scan) {
      socket.on('scan_progress', handleScanProgress)
      socket.on('scan_completed', handleScanCompleted)
      socket.on('scan_failed', handleScanFailed)

      return () => {
        socket.off('scan_progress')
        socket.off('scan_completed')
        socket.off('scan_failed')
      }
    }
  }, [socket, scan])

  const loadScan = async (scanId: string) => {
    try {
      const response = await apiClient.get(`/scans/${scanId}`)
      setScan(response.data)
    } catch (error) {
      console.error('Failed to load scan:', error)
      setError('Failed to load scan details')
    } finally {
      setLoading(false)
    }
  }

  const handleScanProgress = (data: { scanId: string, progress: number, stage: string }) => {
    if (scan && scan.id === data.scanId) {
      setScan(prev => prev ? { ...prev, progress: data.progress, status: 'running' } : null)
    }
  }

  const handleScanCompleted = (data: { scanId: string, results: any }) => {
    if (scan && scan.id === data.scanId) {
      setScan(prev => prev ? { 
        ...prev, 
        status: 'completed', 
        progress: 100, 
        results: data.results, 
        endTime: new Date().toISOString() 
      } : null)
    }
  }

  const handleScanFailed = (data: { scanId: string, error: string }) => {
    if (scan && scan.id === data.scanId) {
      setScan(prev => prev ? { 
        ...prev, 
        status: 'failed', 
        endTime: new Date().toISOString() 
      } : null)
    }
  }

  const stopScan = async () => {
    if (!scan) return
    
    try {
      await apiClient.post(`/scans/${scan.id}/stop`)
      setScan(prev => prev ? { ...prev, status: 'stopped' } : null)
    } catch (error) {
      console.error('Failed to stop scan:', error)
    }
  }

  const downloadResults = async () => {
    if (!scan || !scan.results) return

    try {
      const response = await apiClient.get(`/scans/${scan.id}/export`, {
        responseType: 'blob'
      })
      
      const blob = new Blob([response.data], { type: 'application/json' })
      const url = window.URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = `scan-${scan.id}-results.json`
      document.body.appendChild(link)
      link.click()
      document.body.removeChild(link)
      window.URL.revokeObjectURL(url)
    } catch (error) {
      console.error('Failed to download results:', error)
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
      case 'pending': return <ClockIcon className="h-5 w-5" />
      case 'running': return <PlayIcon className="h-5 w-5" />
      case 'completed': return <CheckCircleIcon className="h-5 w-5" />
      case 'failed': return <XCircleIcon className="h-5 w-5" />
      case 'stopped': return <StopIcon className="h-5 w-5" />
      default: return <ClockIcon className="h-5 w-5" />
    }
  }

  const formatDuration = (startTime: string, endTime?: string) => {
    const start = new Date(startTime)
    const end = endTime ? new Date(endTime) : new Date()
    const diff = end.getTime() - start.getTime()
    const hours = Math.floor(diff / 3600000)
    const minutes = Math.floor((diff % 3600000) / 60000)
    const seconds = Math.floor((diff % 60000) / 1000)
    
    if (hours > 0) {
      return `${hours}h ${minutes}m ${seconds}s`
    }
    return `${minutes}m ${seconds}s`
  }

  if (loading) {
    return <LoadingSpinner />
  }

  if (error || !scan) {
    return (
      <div className="space-y-8">
        <div className="flex items-center gap-4">
          <button
            onClick={() => navigate('/scans')}
            className="btn-secondary flex items-center gap-2"
          >
            <ArrowLeftIcon className="h-4 w-4" />
            Back to Scans
          </button>
        </div>
        
        <div className="card">
          <div className="card-body text-center py-16">
            <XCircleIcon className="h-12 w-12 text-red-400 mx-auto mb-4" />
            <p className="text-secondary-600">{error || 'Scan not found'}</p>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <button
            onClick={() => navigate('/scans')}
            className="btn-secondary flex items-center gap-2"
          >
            <ArrowLeftIcon className="h-4 w-4" />
            Back to Scans
          </button>
          
          <div>
            <h1 className="text-3xl font-bold text-secondary-900">{scan.name}</h1>
            <p className="text-secondary-600 mt-1">Scan Details and Results</p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          {scan.status === 'running' && (
            <button
              onClick={stopScan}
              className="btn-secondary text-red-600 hover:bg-red-50 flex items-center gap-2"
            >
              <StopIcon className="h-4 w-4" />
              Stop Scan
            </button>
          )}
          
          {scan.results && (
            <button
              onClick={downloadResults}
              className="btn-primary flex items-center gap-2"
            >
              <DocumentArrowDownIcon className="h-4 w-4" />
              Download Results
            </button>
          )}
        </div>
      </div>

      {/* Connection Status */}
      {scan.status === 'running' && (
        <div className={`card ${connected ? 'border-green-200 bg-green-50' : 'border-red-200 bg-red-50'}`}>
          <div className="card-body py-3">
            <div className="flex items-center gap-2">
              <div className={`w-2 h-2 rounded-full ${connected ? 'bg-green-500' : 'bg-red-500'}`} />
              <span className={`text-sm ${connected ? 'text-green-700' : 'text-red-700'}`}>
                {connected ? 'Connected - receiving live updates' : 'Disconnected - updates may be delayed'}
              </span>
            </div>
          </div>
        </div>
      )}

      {/* Scan Overview */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <div className="card">
            <div className="card-header">
              <h2 className="text-xl font-semibold text-secondary-900">Scan Overview</h2>
            </div>
            <div className="card-body space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="text-sm font-medium text-secondary-700">Target</label>
                  <p className="text-secondary-900 font-mono">{scan.target}</p>
                </div>
                <div>
                  <label className="text-sm font-medium text-secondary-700">Profile</label>
                  <p className="text-secondary-900">{scan.profile}</p>
                </div>
                <div>
                  <label className="text-sm font-medium text-secondary-700">Status</label>
                  <span className={`inline-flex items-center gap-2 px-3 py-1 rounded-full text-sm font-medium ${getStatusColor(scan.status)}`}>
                    {getStatusIcon(scan.status)}
                    {scan.status.charAt(0).toUpperCase() + scan.status.slice(1)}
                  </span>
                </div>
                <div>
                  <label className="text-sm font-medium text-secondary-700">Duration</label>
                  <p className="text-secondary-900">{formatDuration(scan.startTime, scan.endTime)}</p>
                </div>
              </div>

              <div>
                <label className="text-sm font-medium text-secondary-700">Tools Used</label>
                <div className="flex flex-wrap gap-2 mt-1">
                  {scan.tools.map((tool) => (
                    <span
                      key={tool}
                      className="inline-block px-3 py-1 bg-primary-100 text-primary-800 text-sm rounded-full"
                    >
                      {tool}
                    </span>
                  ))}
                </div>
              </div>

              {scan.status === 'running' && (
                <div>
                  <div className="flex justify-between text-sm text-secondary-700 mb-2">
                    <span>Progress</span>
                    <span>{scan.progress}%</span>
                  </div>
                  <div className="w-full bg-secondary-200 rounded-full h-3">
                    <div 
                      className="bg-primary-600 h-3 rounded-full transition-all duration-300"
                      style={{ width: `${scan.progress}%` }}
                    />
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>

        <div>
          <div className="card">
            <div className="card-header">
              <h3 className="text-lg font-semibold text-secondary-900">Timestamps</h3>
            </div>
            <div className="card-body space-y-3">
              <div>
                <label className="text-sm font-medium text-secondary-700">Started</label>
                <p className="text-secondary-900 text-sm">
                  {new Date(scan.startTime).toLocaleString()}
                </p>
              </div>
              {scan.endTime && (
                <div>
                  <label className="text-sm font-medium text-secondary-700">
                    {scan.status === 'completed' ? 'Completed' : 'Ended'}
                  </label>
                  <p className="text-secondary-900 text-sm">
                    {new Date(scan.endTime).toLocaleString()}
                  </p>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Results */}
      {scan.results && (
        <div className="card">
          <div className="card-header">
            <h2 className="text-xl font-semibold text-secondary-900">Scan Results</h2>
          </div>
          <div className="card-body">
            <div className="bg-secondary-50 border border-secondary-200 rounded-lg p-4">
              <pre className="text-sm text-secondary-800 whitespace-pre-wrap overflow-x-auto">
                {JSON.stringify(scan.results, null, 2)}
              </pre>
            </div>
          </div>
        </div>
      )}

      {/* Tool Results */}
      {scan.toolResults && Object.keys(scan.toolResults).length > 0 && (
        <div className="space-y-4">
          <h2 className="text-xl font-semibold text-secondary-900">Tool Results</h2>
          {Object.entries(scan.toolResults).map(([tool, result]) => (
            <div key={tool} className="card">
              <div className="card-header">
                <h3 className="text-lg font-semibold text-secondary-900 capitalize">{tool}</h3>
              </div>
              <div className="card-body">
                <div className="bg-secondary-50 border border-secondary-200 rounded-lg p-4">
                  <pre className="text-sm text-secondary-800 whitespace-pre-wrap overflow-x-auto">
                    {JSON.stringify(result, null, 2)}
                  </pre>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Logs */}
      {scan.logs && scan.logs.length > 0 && (
        <div className="card">
          <div className="card-header">
            <h2 className="text-xl font-semibold text-secondary-900">Scan Logs</h2>
          </div>
          <div className="card-body">
            <div className="bg-black text-green-400 font-mono text-sm p-4 rounded-lg max-h-96 overflow-y-auto">
              {scan.logs.map((log, index) => (
                <div key={index} className="whitespace-pre-wrap">
                  {log}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
