export interface Scan {
  id: number
  user_id: number
  target: string
  scan_type: string
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled'
  progress: number
  results?: Record<string, any>
  error_message?: string
  created_at: string
  updated_at: string
  started_at?: string
  completed_at?: string
}

export interface ScanRequest {
  target: string
  scan_type: string
  options?: Record<string, any>
}

export interface ScanResults {
  scan_id: number
  target: string
  scan_type: string
  results: Record<string, any>
  metadata: {
    duration: number
    tools_used: string[]
    timestamp: string
  }
}

export interface ScanProgress {
  scan_id: number
  progress: number
  status: string
  current_stage?: string
  message?: string
}
