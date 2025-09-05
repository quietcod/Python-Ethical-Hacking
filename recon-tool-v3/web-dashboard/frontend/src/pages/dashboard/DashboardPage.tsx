import { Activity, Search, FileText, Clock } from 'lucide-react'

export function DashboardPage() {
  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-3xl font-bold text-secondary-900">Dashboard</h1>
        <p className="text-secondary-600 mt-1">
          Welcome to Recon-Tool-v3 - Your cybersecurity reconnaissance platform
        </p>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="card">
          <div className="card-body">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-secondary-600">Total Scans</p>
                <p className="text-3xl font-bold text-secondary-900">0</p>
              </div>
              <div className="p-3 bg-primary-100 rounded-lg">
                <Search className="h-6 w-6 text-primary-600" />
              </div>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="card-body">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-secondary-600">Active Scans</p>
                <p className="text-3xl font-bold text-secondary-900">0</p>
              </div>
              <div className="p-3 bg-warning-100 rounded-lg">
                <Activity className="h-6 w-6 text-warning-600" />
              </div>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="card-body">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-secondary-600">Reports</p>
                <p className="text-3xl font-bold text-secondary-900">0</p>
              </div>
              <div className="p-3 bg-success-100 rounded-lg">
                <FileText className="h-6 w-6 text-success-600" />
              </div>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="card-body">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-secondary-600">Last Scan</p>
                <p className="text-lg font-semibold text-secondary-900">Never</p>
              </div>
              <div className="p-3 bg-secondary-100 rounded-lg">
                <Clock className="h-6 w-6 text-secondary-600" />
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Quick Actions */}
      <div className="card">
        <div className="card-header">
          <h2 className="text-xl font-semibold text-secondary-900">Quick Actions</h2>
        </div>
        <div className="card-body">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <button className="btn-primary">
              Start New Scan
            </button>
            <button className="btn-secondary">
              View Reports
            </button>
            <button className="btn-secondary">
              System Settings
            </button>
          </div>
        </div>
      </div>

      {/* Recent Activity */}
      <div className="card">
        <div className="card-header">
          <h2 className="text-xl font-semibold text-secondary-900">Recent Activity</h2>
        </div>
        <div className="card-body">
          <div className="text-center py-8">
            <div className="text-secondary-400 mb-2">
              <Activity className="h-12 w-12 mx-auto" />
            </div>
            <p className="text-secondary-600">No recent activity</p>
            <p className="text-sm text-secondary-500 mt-1">
              Start your first scan to see activity here
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}
