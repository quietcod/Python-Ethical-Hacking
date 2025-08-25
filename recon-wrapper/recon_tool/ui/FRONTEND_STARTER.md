# ReconTool Frontend Starter

## Quick Setup Guide

### 1. Initialize React Project
```bash
cd recon_tool/ui/
npx create-react-app reconTool-dashboard --template typescript
cd reconTool-dashboard
```

### 2. Install Required Dependencies
```bash
npm install axios @types/axios
npm install @headlessui/react @heroicons/react
npm install tailwindcss @tailwindcss/forms
npm install recharts  # For charts
npm install react-router-dom @types/react-router-dom
```

### 3. Setup Tailwind CSS
```bash
npx tailwindcss init -p
```

Add to `tailwind.config.js`:
```javascript
module.exports = {
  content: [
    "./src/**/*.{js,jsx,ts,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        primary: '#667eea',
        secondary: '#764ba2',
        success: '#48bb78',
        warning: '#ed8936',
        danger: '#f56565',
      }
    },
  },
  plugins: [
    require('@tailwindcss/forms'),
  ],
}
```

### 4. Project Structure
```
src/
├── components/
│   ├── Dashboard/
│   │   ├── ScanInput.tsx
│   │   ├── ScanProgress.tsx
│   │   ├── ResultsOverview.tsx
│   │   └── ResultsDetail.tsx
│   ├── Layout/
│   │   ├── Header.tsx
│   │   ├── Sidebar.tsx
│   │   └── Layout.tsx
│   └── UI/
│       ├── Button.tsx
│       ├── StatusBadge.tsx
│       └── LoadingSpinner.tsx
├── services/
│   └── api.ts
├── types/
│   └── index.ts
├── hooks/
│   ├── useScan.ts
│   └── useWebSocket.ts
└── pages/
    ├── Dashboard.tsx
    ├── ScanHistory.tsx
    └── ScanResults.tsx
```

### 5. Start Development
```bash
npm start  # Frontend (port 3000)
```

In another terminal:
```bash
cd ../api/
python3 -m uvicorn main:app --reload  # Backend API (port 8000)
```

## Code Templates

### API Service (`src/services/api.ts`)
```typescript
import axios from 'axios';

const API_BASE_URL = 'http://localhost:8000';

export interface ScanRequest {
  target: string;
  scan_type: 'quick' | 'full' | 'custom';
  tools: string[];
  options?: Record<string, any>;
}

export interface ScanResponse {
  scan_id: string;
  status: string;
  message: string;
  estimated_duration: number;
}

export interface ScanResults {
  scan_id: string;
  target: string;
  status: string;
  start_time: string;
  end_time?: string;
  results: {
    port_scan?: any;
    subdomains?: any;
    web_scan?: any;
    ssl_scan?: any;
    osint?: any;
  };
  summary: {
    total_ports: number;
    total_subdomains: number;
    vulnerabilities: number;
    scan_duration: number;
  };
}

class ReconToolAPI {
  private api = axios.create({
    baseURL: API_BASE_URL,
    timeout: 30000,
  });

  async startScan(request: ScanRequest): Promise<ScanResponse> {
    const response = await this.api.post('/api/scans', request);
    return response.data;
  }

  async getScanStatus(scanId: string) {
    const response = await this.api.get(`/api/scans/${scanId}/status`);
    return response.data;
  }

  async getScanResults(scanId: string): Promise<ScanResults> {
    const response = await this.api.get(`/api/scans/${scanId}/results`);
    return response.data;
  }

  async getScans(limit = 50, status?: string) {
    const params = new URLSearchParams();
    params.append('limit', limit.toString());
    if (status) params.append('status', status);
    
    const response = await this.api.get(`/api/scans?${params}`);
    return response.data;
  }

  async generateReport(scanId: string, format = 'html') {
    const response = await this.api.post(`/api/scans/${scanId}/reports`, {
      format,
      template: 'professional'
    });
    return response.data;
  }
}

export const api = new ReconToolAPI();
```

### Scan Input Component (`src/components/Dashboard/ScanInput.tsx`)
```typescript
import React, { useState } from 'react';
import { api, ScanRequest } from '../../services/api';

interface ScanInputProps {
  onScanStarted: (scanId: string) => void;
}

export const ScanInput: React.FC<ScanInputProps> = ({ onScanStarted }) => {
  const [target, setTarget] = useState('');
  const [scanType, setScanType] = useState<'quick' | 'full' | 'custom'>('quick');
  const [selectedTools, setSelectedTools] = useState(['port', 'subdomain', 'web']);
  const [isLoading, setIsLoading] = useState(false);

  const tools = [
    { id: 'port', name: 'Port Scanner', description: 'Scan for open ports' },
    { id: 'subdomain', name: 'Subdomain Enum', description: 'Find subdomains' },
    { id: 'web', name: 'Web Scanner', description: 'Analyze web technologies' },
    { id: 'ssl', name: 'SSL Analyzer', description: 'Check SSL/TLS configuration' },
    { id: 'osint', name: 'OSINT Gatherer', description: 'Collect public information' },
  ];

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!target.trim()) return;

    setIsLoading(true);
    try {
      const request: ScanRequest = {
        target: target.trim(),
        scan_type: scanType,
        tools: selectedTools,
      };

      const response = await api.startScan(request);
      onScanStarted(response.scan_id);
      setTarget('');
    } catch (error) {
      console.error('Failed to start scan:', error);
      alert('Failed to start scan. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  const toggleTool = (toolId: string) => {
    setSelectedTools(prev => 
      prev.includes(toolId) 
        ? prev.filter(id => id !== toolId)
        : [...prev, toolId]
    );
  };

  return (
    <div className="bg-white rounded-lg shadow-md p-6">
      <h2 className="text-xl font-semibold mb-4">Start New Scan</h2>
      
      <form onSubmit={handleSubmit} className="space-y-4">
        {/* Target Input */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">
            Target Domain or IP
          </label>
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="example.com or 192.168.1.1"
            className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-primary"
            required
          />
        </div>

        {/* Scan Type */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">
            Scan Type
          </label>
          <select
            value={scanType}
            onChange={(e) => setScanType(e.target.value as any)}
            className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-primary"
          >
            <option value="quick">Quick Scan (1-2 min)</option>
            <option value="full">Full Scan (5-10 min)</option>
            <option value="custom">Custom Scan</option>
          </select>
        </div>

        {/* Tools Selection */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Select Tools
          </label>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
            {tools.map(tool => (
              <label key={tool.id} className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  checked={selectedTools.includes(tool.id)}
                  onChange={() => toggleTool(tool.id)}
                  className="rounded border-gray-300 text-primary focus:ring-primary"
                />
                <div>
                  <div className="font-medium text-sm">{tool.name}</div>
                  <div className="text-xs text-gray-500">{tool.description}</div>
                </div>
              </label>
            ))}
          </div>
        </div>

        {/* Submit Button */}
        <button
          type="submit"
          disabled={isLoading || !target.trim() || selectedTools.length === 0}
          className="w-full bg-primary text-white py-2 px-4 rounded-md hover:bg-primary/90 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {isLoading ? 'Starting Scan...' : 'Start Scan'}
        </button>
      </form>
    </div>
  );
};
```

### Results Overview Component (`src/components/Dashboard/ResultsOverview.tsx`)
```typescript
import React from 'react';
import { ScanResults } from '../../services/api';

interface ResultsOverviewProps {
  results: ScanResults;
}

export const ResultsOverview: React.FC<ResultsOverviewProps> = ({ results }) => {
  const { summary } = results;

  const stats = [
    {
      label: 'Open Ports',
      value: summary.total_ports,
      color: 'bg-blue-500',
      icon: '🔌'
    },
    {
      label: 'Subdomains',
      value: summary.total_subdomains,
      color: 'bg-green-500',
      icon: '🌐'
    },
    {
      label: 'Vulnerabilities',
      value: summary.vulnerabilities,
      color: summary.vulnerabilities > 0 ? 'bg-red-500' : 'bg-gray-500',
      icon: '⚠️'
    },
    {
      label: 'Scan Duration',
      value: `${Math.floor(summary.scan_duration / 60)}m ${summary.scan_duration % 60}s`,
      color: 'bg-purple-500',
      icon: '⏱️'
    }
  ];

  return (
    <div className="bg-white rounded-lg shadow-md p-6">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-xl font-semibold">Scan Results Overview</h2>
        <div className="text-sm text-gray-500">
          Target: {results.target}
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {stats.map((stat, index) => (
          <div key={index} className="text-center">
            <div className={`${stat.color} text-white rounded-lg p-4 mb-2`}>
              <div className="text-2xl mb-1">{stat.icon}</div>
              <div className="text-2xl font-bold">{stat.value}</div>
            </div>
            <div className="text-sm font-medium text-gray-700">{stat.label}</div>
          </div>
        ))}
      </div>

      {/* Quick Actions */}
      <div className="mt-6 flex space-x-3">
        <button className="bg-primary text-white px-4 py-2 rounded-md hover:bg-primary/90">
          Download Report
        </button>
        <button className="border border-gray-300 text-gray-700 px-4 py-2 rounded-md hover:bg-gray-50">
          View Details
        </button>
        <button className="border border-gray-300 text-gray-700 px-4 py-2 rounded-md hover:bg-gray-50">
          Share Results
        </button>
      </div>
    </div>
  );
};
```

### Port Scan Results Component (`src/components/Dashboard/PortScanResults.tsx`)
```typescript
import React from 'react';

interface PortScanResultsProps {
  portScan: {
    open_ports: number[];
    services: Array<{
      port: number;
      service: string;
      version: string;
      state: string;
    }>;
  };
}

export const PortScanResults: React.FC<PortScanResultsProps> = ({ portScan }) => {
  const getStatusColor = (state: string) => {
    switch (state.toLowerCase()) {
      case 'open': return 'bg-green-100 text-green-800';
      case 'closed': return 'bg-red-100 text-red-800';
      case 'filtered': return 'bg-yellow-100 text-yellow-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  return (
    <div className="bg-white rounded-lg shadow-md p-6">
      <h3 className="text-lg font-semibold mb-4">Port Scan Results</h3>
      
      <div className="overflow-x-auto">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Port
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Service
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Version
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Status
              </th>
            </tr>
          </thead>
          <tbody className="bg-white divide-y divide-gray-200">
            {portScan.services.map((service, index) => (
              <tr key={index} className="hover:bg-gray-50">
                <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                  {service.port}
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                  {service.service}
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                  {service.version}
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <span className={`px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(service.state)}`}>
                    {service.state.toUpperCase()}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
```

## Next Steps

1. **Setup the project structure** as shown above
2. **Start with basic components** - ScanInput and simple results display
3. **Test API integration** - Make sure frontend can communicate with backend
4. **Add real-time updates** - WebSocket integration for live progress
5. **Enhance UI/UX** - Charts, better styling, responsive design
6. **Add advanced features** - Report generation, scan history, filtering

## Testing the Setup

1. Start the backend API:
   ```bash
   cd recon_tool/api/
   python3 -m uvicorn main:app --reload
   ```

2. Start the frontend:
   ```bash
   cd recon_tool/ui/reconTool-dashboard/
   npm start
   ```

3. Test API connection:
   - Visit http://localhost:3000 (frontend)
   - Visit http://localhost:8000/docs (API docs)
   - Try starting a scan from the frontend

The API will use sample data for testing until you integrate it with the actual ReconTool backend.
