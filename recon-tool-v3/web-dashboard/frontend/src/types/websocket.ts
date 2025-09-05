export interface WebSocketMessage {
  type: 'scan_progress' | 'scan_complete' | 'scan_error' | 'report_ready' | 'system_notification'
  data: any
  timestamp: string
}

export interface ScanProgressMessage {
  type: 'scan_progress'
  data: {
    scan_id: number
    progress: number
    status: string
    current_stage?: string
    message?: string
  }
}

export interface ScanCompleteMessage {
  type: 'scan_complete'
  data: {
    scan_id: number
    results: Record<string, any>
  }
}

export interface ScanErrorMessage {
  type: 'scan_error'
  data: {
    scan_id: number
    error: string
  }
}

export interface ReportReadyMessage {
  type: 'report_ready'
  data: {
    report_id: number
    file_path: string
  }
}

export interface SystemNotificationMessage {
  type: 'system_notification'
  data: {
    level: 'info' | 'warning' | 'error'
    message: string
  }
}
