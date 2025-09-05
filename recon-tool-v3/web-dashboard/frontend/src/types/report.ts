export interface Report {
  id: number
  user_id: number
  scan_id: number
  title: string
  report_type: 'executive' | 'technical' | 'comprehensive'
  format: 'html' | 'json' | 'pdf'
  status: 'pending' | 'generating' | 'completed' | 'failed'
  file_path?: string
  metadata?: Record<string, any>
  created_at: string
  updated_at: string
}

export interface ReportRequest {
  scan_id: number
  title: string
  report_type: 'executive' | 'technical' | 'comprehensive'
  format: 'html' | 'json' | 'pdf'
  options?: Record<string, any>
}

export interface ReportMetadata {
  page_count?: number
  file_size?: number
  generated_by: string
  generation_time: number
}
