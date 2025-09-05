import { Link } from 'react-router-dom'
import { Home } from 'lucide-react'

export function NotFoundPage() {
  return (
    <div className="min-h-screen center bg-secondary-50">
      <div className="text-center">
        <h1 className="text-9xl font-bold text-primary-600">404</h1>
        <h2 className="text-3xl font-semibold text-secondary-900 mt-4">Page Not Found</h2>
        <p className="text-secondary-600 mt-2 mb-8">
          The page you're looking for doesn't exist or has been moved.
        </p>
        <Link to="/dashboard" className="btn-primary">
          <Home className="h-4 w-4 mr-2" />
          Back to Dashboard
        </Link>
      </div>
    </div>
  )
}
