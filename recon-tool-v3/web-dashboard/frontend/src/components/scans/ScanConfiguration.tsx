import React, { useState, useEffect } from 'react'
import { XMarkIcon, InformationCircleIcon, PlayIcon, CogIcon } from '@heroicons/react/24/outline'

interface Tool {
  id: string
  name: string
  description: string
  category: string
  enabled: boolean
  parameters?: Record<string, any>
}

interface ScanProfile {
  id: string
  name: string
  description: string
  tools: string[]
  estimatedTime: string
}

interface ScanConfigurationProps {
  onClose: () => void
  onSubmit: (config: any) => void
  initialTemplate?: ScanProfile
}

const SCAN_PROFILES: ScanProfile[] = [
  {
    id: 'quick',
    name: 'Quick Scan',
    description: 'Fast reconnaissance (5-10 minutes)',
    tools: ['nmap', 'subfinder', 'curl_probe'],
    estimatedTime: '5-10 min'
  },
  {
    id: 'full',
    name: 'Full Assessment',
    description: 'Comprehensive assessment (15-30 minutes)',
    tools: ['nmap', 'masscan', 'subfinder', 'amass', 'nikto', 'gobuster', 'sslscan', 'nuclei', 'httpx'],
    estimatedTime: '15-30 min'
  },
  {
    id: 'passive',
    name: 'Passive OSINT',
    description: 'OSINT-only, no direct target contact',
    tools: ['subfinder', 'amass', 'theharvester', 'waybackurls', 'shodan', 'censys'],
    estimatedTime: '10-15 min'
  },
  {
    id: 'web_focused',
    name: 'Web Application',
    description: 'Web application security assessment',
    tools: ['httpx', 'nikto', 'gobuster', 'katana', 'wfuzz', 'sslscan', 'nuclei'],
    estimatedTime: '20-40 min'
  },
  {
    id: 'network_focused',
    name: 'Network Infrastructure',
    description: 'Network infrastructure assessment',
    tools: ['nmap', 'masscan', 'dnsrecon'],
    estimatedTime: '10-20 min'
  }
]

const AVAILABLE_TOOLS: Tool[] = [
  { id: 'nmap', name: 'Nmap', description: 'Network discovery and security auditing', category: 'network', enabled: false },
  { id: 'masscan', name: 'Masscan', description: 'High-performance port scanner', category: 'network', enabled: false },
  { id: 'subfinder', name: 'Subfinder', description: 'Subdomain discovery tool', category: 'subdomain', enabled: false },
  { id: 'amass', name: 'Amass', description: 'Advanced subdomain enumeration', category: 'subdomain', enabled: false },
  { id: 'gobuster', name: 'Gobuster', description: 'Directory and file brute-forcer', category: 'web', enabled: false },
  { id: 'nikto', name: 'Nikto', description: 'Web server scanner', category: 'web', enabled: false },
  { id: 'httpx', name: 'Httpx', description: 'Fast HTTP probe and analysis', category: 'web', enabled: false },
  { id: 'sslscan', name: 'SSLScan', description: 'SSL/TLS configuration scanner', category: 'ssl', enabled: false },
  { id: 'nuclei', name: 'Nuclei', description: 'Template-based vulnerability scanner', category: 'vulnerability', enabled: false },
  { id: 'theharvester', name: 'TheHarvester', description: 'Email and subdomain harvester', category: 'osint', enabled: false }
]

export function ScanConfiguration({ onClose, onSubmit, initialTemplate }: ScanConfigurationProps) {
  const [scanName, setScanName] = useState('')
  const [target, setTarget] = useState('')
  const [selectedProfile, setSelectedProfile] = useState<string>('')
  const [tools, setTools] = useState<Tool[]>(AVAILABLE_TOOLS)
  const [customMode, setCustomMode] = useState(false)
  const [isSubmitting, setIsSubmitting] = useState(false)

  useEffect(() => {
    if (initialTemplate) {
      setSelectedProfile(initialTemplate.id)
      setScanName(initialTemplate.name)
      applyProfile(initialTemplate.id)
    }
  }, [initialTemplate])

  const applyProfile = (profileId: string) => {
    const profile = SCAN_PROFILES.find(p => p.id === profileId)
    if (profile) {
      setTools(prev => prev.map(tool => ({
        ...tool,
        enabled: profile.tools.includes(tool.id)
      })))
      setCustomMode(false)
    }
  }

  const handleProfileChange = (profileId: string) => {
    setSelectedProfile(profileId)
    if (profileId) {
      applyProfile(profileId)
    }
  }

  const handleToolToggle = (toolId: string) => {
    setTools(prev => prev.map(tool => 
      tool.id === toolId ? { ...tool, enabled: !tool.enabled } : tool
    ))
    setCustomMode(true)
    setSelectedProfile('')
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsSubmitting(true)

    try {
      const enabledTools = tools.filter(t => t.enabled)
      const profile = selectedProfile || 'custom'
      
      const config = {
        name: scanName || `${profile} scan`,
        target: target.trim(),
        profile,
        tools: enabledTools.map(t => t.id),
        parameters: {
          // Add any additional parameters here
        }
      }

      await onSubmit(config)
    } catch (error) {
      console.error('Failed to start scan:', error)
    } finally {
      setIsSubmitting(false)
    }
  }

  const isValid = target.trim().length > 0 && tools.some(t => t.enabled)
  const enabledTools = tools.filter(t => t.enabled)
  const selectedProfileData = SCAN_PROFILES.find(p => p.id === selectedProfile)

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg shadow-xl max-w-4xl w-full max-h-[90vh] overflow-y-auto m-4">
        <div className="flex items-center justify-between p-6 border-b border-secondary-200">
          <h2 className="text-xl font-semibold text-secondary-900">Configure New Scan</h2>
          <button
            onClick={onClose}
            className="text-secondary-400 hover:text-secondary-600"
          >
            <XMarkIcon className="h-6 w-6" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-6 space-y-6">
          {/* Basic Configuration */}
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-secondary-700 mb-2">
                Scan Name (optional)
              </label>
              <input
                type="text"
                value={scanName}
                onChange={(e) => setScanName(e.target.value)}
                className="input"
                placeholder="My reconnaissance scan"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-secondary-700 mb-2">
                Target <span className="text-red-500">*</span>
              </label>
              <input
                type="text"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                className="input"
                placeholder="example.com or 192.168.1.0/24"
                required
              />
              <p className="text-xs text-secondary-500 mt-1">
                Enter a domain name, IP address, or CIDR range
              </p>
            </div>
          </div>

          {/* Scan Profiles */}
          <div>
            <label className="block text-sm font-medium text-secondary-700 mb-3">
              Scan Profile
            </label>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
              {SCAN_PROFILES.map((profile) => (
                <div
                  key={profile.id}
                  className={`border-2 rounded-lg p-4 cursor-pointer transition-all ${
                    selectedProfile === profile.id
                      ? 'border-primary-500 bg-primary-50'
                      : 'border-secondary-200 hover:border-secondary-300'
                  }`}
                  onClick={() => handleProfileChange(profile.id)}
                >
                  <div className="flex items-center gap-2 mb-2">
                    <input
                      type="radio"
                      name="profile"
                      value={profile.id}
                      checked={selectedProfile === profile.id}
                      onChange={() => handleProfileChange(profile.id)}
                      className="text-primary-600"
                    />
                    <h3 className="font-medium text-secondary-900">{profile.name}</h3>
                  </div>
                  <p className="text-sm text-secondary-600 mb-2">{profile.description}</p>
                  <p className="text-xs text-secondary-500">⏱️ {profile.estimatedTime}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Tool Selection */}
          <div>
            <div className="flex items-center justify-between mb-3">
              <label className="block text-sm font-medium text-secondary-700">
                Tools Selection
              </label>
              <button
                type="button"
                onClick={() => setCustomMode(!customMode)}
                className="text-sm text-primary-600 hover:text-primary-700 flex items-center gap-1"
              >
                <CogIcon className="h-4 w-4" />
                {customMode ? 'Use Profile' : 'Custom Selection'}
              </button>
            </div>

            {selectedProfileData && !customMode && (
              <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 mb-4">
                <div className="flex items-start gap-2">
                  <InformationCircleIcon className="h-5 w-5 text-blue-500 mt-0.5" />
                  <div>
                    <p className="text-sm text-blue-800 font-medium">{selectedProfileData.name}</p>
                    <p className="text-sm text-blue-700">{selectedProfileData.description}</p>
                    <p className="text-xs text-blue-600 mt-1">
                      Tools: {selectedProfileData.tools.join(', ')}
                    </p>
                  </div>
                </div>
              </div>
            )}

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {tools.map((tool) => (
                <div
                  key={tool.id}
                  className={`border rounded-lg p-3 transition-all ${
                    tool.enabled
                      ? 'border-primary-300 bg-primary-50'
                      : 'border-secondary-200 hover:border-secondary-300'
                  } ${!customMode ? 'opacity-60' : ''}`}
                >
                  <div className="flex items-center gap-3">
                    <input
                      type="checkbox"
                      checked={tool.enabled}
                      onChange={() => handleToolToggle(tool.id)}
                      disabled={!customMode}
                      className="text-primary-600"
                    />
                    <div className="flex-1">
                      <h4 className="font-medium text-secondary-900">{tool.name}</h4>
                      <p className="text-sm text-secondary-600">{tool.description}</p>
                      <span className="inline-block px-2 py-1 bg-secondary-100 text-secondary-700 text-xs rounded mt-1">
                        {tool.category}
                      </span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Summary */}
          {enabledTools.length > 0 && (
            <div className="bg-secondary-50 rounded-lg p-4">
              <h3 className="font-medium text-secondary-900 mb-2">Scan Summary</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                <div>
                  <p className="text-secondary-600">
                    <span className="font-medium">Target:</span> {target || 'Not specified'}
                  </p>
                  <p className="text-secondary-600">
                    <span className="font-medium">Profile:</span> {selectedProfile || 'Custom'}
                  </p>
                </div>
                <div>
                  <p className="text-secondary-600">
                    <span className="font-medium">Tools:</span> {enabledTools.length} selected
                  </p>
                  <p className="text-secondary-600">
                    <span className="font-medium">Estimated time:</span> {selectedProfileData?.estimatedTime || 'Variable'}
                  </p>
                </div>
              </div>
            </div>
          )}

          {/* Actions */}
          <div className="flex justify-end gap-3 pt-4 border-t border-secondary-200">
            <button
              type="button"
              onClick={onClose}
              className="btn-secondary"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={!isValid || isSubmitting}
              className="btn-primary flex items-center gap-2"
            >
              <PlayIcon className="h-4 w-4" />
              {isSubmitting ? 'Starting...' : 'Start Scan'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
