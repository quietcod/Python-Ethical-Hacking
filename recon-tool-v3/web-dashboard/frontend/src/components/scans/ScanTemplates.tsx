import { XMarkIcon, PlayIcon, ClockIcon, WrenchScrewdriverIcon } from '@heroicons/react/24/outline'

interface ScanTemplate {
  id: string
  name: string
  description: string
  tools: string[]
  estimatedTime: string
  category: string
  useCase: string
}

interface ScanTemplatesProps {
  onClose: () => void
  onSelectTemplate: (template: ScanTemplate) => void
}

const SCAN_TEMPLATES: ScanTemplate[] = [
  {
    id: 'quick',
    name: 'Quick Reconnaissance',
    description: 'Fast discovery for initial assessment',
    tools: ['nmap', 'subfinder', 'curl_probe'],
    estimatedTime: '5-10 minutes',
    category: 'Basic',
    useCase: 'Quick overview of target infrastructure'
  },
  {
    id: 'full',
    name: 'Comprehensive Assessment',
    description: 'Complete reconnaissance with all tools',
    tools: ['nmap', 'masscan', 'subfinder', 'amass', 'nikto', 'gobuster', 'sslscan', 'nuclei', 'httpx'],
    estimatedTime: '15-30 minutes',
    category: 'Advanced',
    useCase: 'Thorough security assessment and penetration testing'
  },
  {
    id: 'passive',
    name: 'Passive OSINT',
    description: 'Information gathering without direct contact',
    tools: ['subfinder', 'amass', 'theharvester', 'waybackurls', 'shodan', 'censys'],
    estimatedTime: '10-15 minutes',
    category: 'OSINT',
    useCase: 'Stealth reconnaissance and threat intelligence'
  },
  {
    id: 'web_focused',
    name: 'Web Application Security',
    description: 'Focused on web application testing',
    tools: ['httpx', 'nikto', 'gobuster', 'katana', 'wfuzz', 'sslscan', 'nuclei'],
    estimatedTime: '20-40 minutes',
    category: 'Web Security',
    useCase: 'Web application vulnerability assessment'
  },
  {
    id: 'network_focused',
    name: 'Network Infrastructure',
    description: 'Network discovery and port scanning',
    tools: ['nmap', 'masscan', 'dnsrecon'],
    estimatedTime: '10-20 minutes',
    category: 'Network',
    useCase: 'Network topology and service discovery'
  },
  {
    id: 'osint_focused',
    name: 'Advanced OSINT',
    description: 'Comprehensive open source intelligence',
    tools: ['subfinder', 'amass', 'theharvester', 'waybackurls', 'shodan', 'censys', 'fierce'],
    estimatedTime: '15-25 minutes',
    category: 'OSINT',
    useCase: 'Intelligence gathering and reconnaissance'
  },
  {
    id: 'subdomain_enum',
    name: 'Subdomain Enumeration',
    description: 'Comprehensive subdomain discovery',
    tools: ['subfinder', 'amass', 'assetfinder', 'findomain'],
    estimatedTime: '10-15 minutes',
    category: 'Discovery',
    useCase: 'Attack surface mapping and subdomain discovery'
  },
  {
    id: 'vulnerability_scan',
    name: 'Vulnerability Assessment',
    description: 'Focus on vulnerability identification',
    tools: ['nuclei', 'nikto', 'nmap', 'sslscan'],
    estimatedTime: '15-30 minutes',
    category: 'Vulnerability',
    useCase: 'Security vulnerability identification and assessment'
  }
]

const getCategoryColor = (category: string) => {
  switch (category) {
    case 'Basic': return 'bg-green-100 text-green-800'
    case 'Advanced': return 'bg-red-100 text-red-800'
    case 'OSINT': return 'bg-blue-100 text-blue-800'
    case 'Web Security': return 'bg-purple-100 text-purple-800'
    case 'Network': return 'bg-orange-100 text-orange-800'
    case 'Discovery': return 'bg-teal-100 text-teal-800'
    case 'Vulnerability': return 'bg-pink-100 text-pink-800'
    default: return 'bg-gray-100 text-gray-800'
  }
}

export function ScanTemplates({ onClose, onSelectTemplate }: ScanTemplatesProps) {
  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg shadow-xl max-w-6xl w-full max-h-[90vh] overflow-y-auto m-4">
        <div className="flex items-center justify-between p-6 border-b border-secondary-200">
          <div>
            <h2 className="text-xl font-semibold text-secondary-900">Scan Templates</h2>
            <p className="text-sm text-secondary-600 mt-1">
              Choose a pre-configured scan template to get started quickly
            </p>
          </div>
          <button
            onClick={onClose}
            className="text-secondary-400 hover:text-secondary-600"
          >
            <XMarkIcon className="h-6 w-6" />
          </button>
        </div>

        <div className="p-6">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {SCAN_TEMPLATES.map((template) => (
              <div
                key={template.id}
                className="border border-secondary-200 rounded-lg hover:border-primary-300 hover:shadow-md transition-all cursor-pointer"
                onClick={() => onSelectTemplate(template)}
              >
                <div className="p-5">
                  <div className="flex items-start justify-between mb-3">
                    <h3 className="font-semibold text-secondary-900 text-lg">{template.name}</h3>
                    <span className={`px-2 py-1 rounded-full text-xs font-medium ${getCategoryColor(template.category)}`}>
                      {template.category}
                    </span>
                  </div>

                  <p className="text-secondary-600 text-sm mb-4">{template.description}</p>

                  <div className="space-y-3">
                    <div className="flex items-center gap-2 text-sm text-secondary-600">
                      <ClockIcon className="h-4 w-4" />
                      <span>{template.estimatedTime}</span>
                    </div>

                    <div className="flex items-start gap-2 text-sm text-secondary-600">
                      <WrenchScrewdriverIcon className="h-4 w-4 mt-0.5" />
                      <div>
                        <span className="font-medium">{template.tools.length} tools:</span>
                        <div className="flex flex-wrap gap-1 mt-1">
                          {template.tools.slice(0, 4).map((tool) => (
                            <span
                              key={tool}
                              className="inline-block px-2 py-1 bg-secondary-100 text-secondary-700 text-xs rounded"
                            >
                              {tool}
                            </span>
                          ))}
                          {template.tools.length > 4 && (
                            <span className="inline-block px-2 py-1 bg-secondary-100 text-secondary-700 text-xs rounded">
                              +{template.tools.length - 4} more
                            </span>
                          )}
                        </div>
                      </div>
                    </div>

                    <div className="pt-2 border-t border-secondary-100">
                      <p className="text-xs text-secondary-500 italic">
                        {template.useCase}
                      </p>
                    </div>
                  </div>

                  <div className="mt-5 pt-4 border-t border-secondary-100">
                    <button
                      onClick={(e) => {
                        e.stopPropagation()
                        onSelectTemplate(template)
                      }}
                      className="w-full btn-primary flex items-center justify-center gap-2"
                    >
                      <PlayIcon className="h-4 w-4" />
                      Use Template
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>

          <div className="mt-8 pt-6 border-t border-secondary-200">
            <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
              <h4 className="font-medium text-blue-900 mb-2">💡 Pro Tips</h4>
              <ul className="text-sm text-blue-800 space-y-1">
                <li>• Start with "Quick Reconnaissance" for fast results</li>
                <li>• Use "Passive OSINT" when stealth is important</li>
                <li>• "Comprehensive Assessment" provides the most thorough results</li>
                <li>• Templates can be customized after selection</li>
              </ul>
            </div>
          </div>
        </div>

        <div className="flex justify-end gap-3 p-6 border-t border-secondary-200">
          <button
            onClick={onClose}
            className="btn-secondary"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  )
}
