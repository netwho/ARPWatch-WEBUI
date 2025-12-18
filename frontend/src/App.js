import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip, BarChart, Bar, XAxis, YAxis, CartesianGrid } from 'recharts';
import './App.css';

// Use relative URLs in production (nginx proxy), absolute in development
const API_URL = process.env.REACT_APP_API_URL || (process.env.NODE_ENV === 'production' ? '' : 'http://localhost:8000');

function App() {
  const [hosts, setHosts] = useState([]);
  const [events, setEvents] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [activeTab, setActiveTab] = useState('hosts');
  const [autoRefresh, setAutoRefresh] = useState(false);
  const [scanResults, setScanResults] = useState({});
  const [scanning, setScanning] = useState({});
  const [showTooltip, setShowTooltip] = useState({});
  const [config, setConfig] = useState({ os_fingerprinting_enabled: true, port_scanning_enabled: true });
  const [errors, setErrors] = useState([]);
  const [rescanStatus, setRescanStatus] = useState('idle');
  const [rescanError, setRescanError] = useState(null);
  const [sortConfig, setSortConfig] = useState({ column: 'ip_address', direction: 'asc' });
  const [fingerprintSortConfig, setFingerprintSortConfig] = useState({ column: 'ip_address', direction: 'asc' });
  const [osFilter, setOsFilter] = useState(null);
  const [fingerprints, setFingerprints] = useState([]);
  const [fingerprintsLoading, setFingerprintsLoading] = useState(false);
  const [fingerprintInputs, setFingerprintInputs] = useState({});
  const [fingerprintError, setFingerprintError] = useState(null);
  const [showAllFingerprints, setShowAllFingerprints] = useState(false);
  const [editingFingerprint, setEditingFingerprint] = useState(null);
  const [fingerprintSuccess, setFingerprintSuccess] = useState(null);
  const [showLogs, setShowLogs] = useState(false);
  const [logs, setLogs] = useState([]);
  const [logsLoading, setLogsLoading] = useState(false);
  const [darkMode, setDarkMode] = useState(() => {
    // Check localStorage for saved theme preference
    const saved = localStorage.getItem('darkMode');
    return saved ? JSON.parse(saved) : false;
  });
  const [chartType, setChartType] = useState(() => {
    // Check localStorage for saved chart type preference
    const saved = localStorage.getItem('chartType');
    return saved || 'bar'; // 'bar' or 'pie'
  });

  useEffect(() => {
    // Apply theme to document body
    if (darkMode) {
      document.body.classList.add('dark-theme');
    } else {
      document.body.classList.remove('dark-theme');
    }
    // Save preference to localStorage
    localStorage.setItem('darkMode', JSON.stringify(darkMode));
  }, [darkMode]);

  useEffect(() => {
    // Save chart type preference to localStorage
    localStorage.setItem('chartType', chartType);
  }, [chartType]);

  useEffect(() => {
    fetchData();
    if (autoRefresh) {
      const interval = setInterval(fetchData, 5000); // Refresh every 5 seconds
      return () => clearInterval(interval);
    }
  }, [autoRefresh]);

  useEffect(() => {
    if (activeTab === 'fingerprints') {
      fetchFingerprints();
    }
  }, [activeTab, showAllFingerprints]);

  const fetchData = async () => {
    setLoading(true);
    const newErrors = [];
    const fallbackConfig = { os_fingerprinting_enabled: true, port_scanning_enabled: true };

    const safeFetch = async (label, fn) => {
      try {
        const res = await fn();
        return res.data;
      } catch (err) {
        console.error(`Error fetching ${label}:`, err);
        const status = err?.response?.status;
        newErrors.push(`${label} failed${status ? ` (${status})` : ''}`);
        return null;
      }
    };

    // Fetch all data in parallel for faster loading
    const [hostsData, eventsData, statsData, configData] = await Promise.all([
      safeFetch('hosts', () => axios.get(`${API_URL}/api/hosts`)),
      safeFetch('events', () => axios.get(`${API_URL}/api/events?limit=50`)),
      safeFetch('stats', () => axios.get(`${API_URL}/api/stats`)),
      safeFetch('config', () => axios.get(`${API_URL}/api/config`))
    ]);

    // Update state
    if (hostsData) setHosts(hostsData);
    if (eventsData) setEvents(eventsData);
    if (statsData) setStats(statsData);
    setConfig(configData || fallbackConfig);
    setErrors(newErrors);
    setLoading(false);
  };

  const fetchFingerprints = async () => {
    setFingerprintsLoading(true);
    setFingerprintError(null);
    try {
      const endpoint = showAllFingerprints ? '/api/fingerprints/all' : '/api/fingerprints/unknown';
      const res = await axios.get(`${API_URL}${endpoint}`);
      setFingerprints(res.data || []);
    } catch (err) {
      setFingerprintError(err?.response?.data?.detail || err.message || 'Failed to load fingerprints');
    } finally {
      setFingerprintsLoading(false);
    }
  };

  const triggerFingerprintRescan = async () => {
    setRescanError(null);
    try {
      const res = await axios.post(`${API_URL}/api/os-fingerprint/rescan`);
      setRescanStatus(res.data?.status || 'started');
    } catch (err) {
      setRescanError(err?.response?.data?.detail || err.message || 'Failed to start rescan');
      setRescanStatus('idle');
    }
  };

  useEffect(() => {
    if (rescanStatus === 'started' || rescanStatus === 'in_progress') {
      const interval = setInterval(async () => {
        try {
          const res = await axios.get(`${API_URL}/api/os-fingerprint/status`);
          const status = res.data?.status || 'idle';
          setRescanStatus(status);
          if (status === 'idle') {
            clearInterval(interval);
            fetchData(); // Refresh data after rescan completes
          }
        } catch (err) {
          setRescanError(err?.response?.data?.detail || err.message || 'Rescan status failed');
          setRescanStatus('idle');
          clearInterval(interval);
        }
      }, 2000);
      return () => clearInterval(interval);
    }
  }, [rescanStatus]);

  const formatMacAddress = (mac) => {
    if (!mac) return mac;
    // Remove any existing colons, dashes, and dots
    const cleaned = mac.replace(/[:.\-]/g, '');
    if (cleaned.length === 12) {
      return cleaned.match(/.{2}/g).join(':');
    }
    return mac; // Return as-is if not a valid MAC format
  };

  const formatIpAddress = (ip) => {
    if (!ip) return ip;
    // Fix malformed IPs like "17:2.:28:.1:84:.4:" -> "172.28.184.41"
    if (ip.includes(':')) {
      // Remove all colons and dots, then reconstruct
      const cleaned = ip.replace(/[:.]/g, '');
      if (cleaned.length >= 7 && cleaned.length <= 12 && /^\d+$/.test(cleaned)) {
        // Reconstruct IP: take first 1-3 digits, then groups of 1-3
        // This is a heuristic - try common patterns
        if (cleaned.length === 11) {
          // Pattern like 1722818441 -> 172.28.184.41
          return `${cleaned.slice(0, 3)}.${cleaned.slice(3, 5)}.${cleaned.slice(5, 8)}.${cleaned.slice(8)}`;
        } else if (cleaned.length === 10) {
          // Pattern like 172281844 -> 172.28.184.4
          return `${cleaned.slice(0, 3)}.${cleaned.slice(3, 5)}.${cleaned.slice(5, 8)}.${cleaned.slice(8)}`;
        } else if (cleaned.length === 9) {
          // Pattern like 17228184 -> 172.28.18.4
          return `${cleaned.slice(0, 3)}.${cleaned.slice(3, 5)}.${cleaned.slice(5, 7)}.${cleaned.slice(7)}`;
        }
      }
      // Fallback: just replace colons with dots and clean up
      return ip.replace(/:/g, '.').replace(/\.+/g, '.').replace(/^\.|\.$/g, '');
    }
    return ip;
  };

  const filteredHosts = hosts.filter(host => {
    // Apply search query filter
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      const matchesSearch = (
        host.ip_address.toLowerCase().includes(query) ||
        host.mac_address.toLowerCase().includes(query) ||
        (host.hostname && host.hostname.toLowerCase().includes(query))
      );
      if (!matchesSearch) return false;
    }
    
    // Apply OS filter
    if (osFilter) {
      const hostOs = host.os_fingerprint || 'Unknown';
      // Normalize OS names for comparison (case-insensitive, handle variations)
      const normalizeOs = (os) => os.toLowerCase().trim();
      const normalizedFilter = normalizeOs(osFilter);
      const normalizedHostOs = normalizeOs(hostOs);
      
      // Check if host OS matches filter (exact match or contains)
      if (normalizedHostOs !== normalizedFilter && !normalizedHostOs.includes(normalizedFilter)) {
        return false;
      }
    }
    
    return true;
  });

  const ipToNum = (ip) => {
    if (!ip) return 0;
    const parts = String(ip).split('.').map(Number);
    if (parts.length !== 4 || parts.some((p) => Number.isNaN(p))) return 0;
    return parts.reduce((acc, part) => (acc << 8) + part, 0);
  };

  const sortedHosts = [...filteredHosts].sort((a, b) => {
    const { column, direction } = sortConfig;
    const dir = direction === 'asc' ? 1 : -1;
    const getVal = (host) => {
      switch (column) {
        case 'ip_address':
          return ipToNum(formatIpAddress(host.ip_address));
        case 'mac_address':
          return host.mac_address || '';
        case 'hostname':
          return host.hostname || '';
        case 'os_fingerprint':
          return host.os_fingerprint || '';
        case 'age':
          // Parse age string to comparable value (e.g., "2h 30m" -> minutes)
          const parseAge = (ageStr) => {
            if (!ageStr) return 0;
            let totalMinutes = 0;
            const hourMatch = ageStr.match(/(\d+)h/);
            const minMatch = ageStr.match(/(\d+)m/);
            const dayMatch = ageStr.match(/(\d+)d/);
            if (dayMatch) totalMinutes += parseInt(dayMatch[1]) * 24 * 60;
            if (hourMatch) totalMinutes += parseInt(hourMatch[1]) * 60;
            if (minMatch) totalMinutes += parseInt(minMatch[1]);
            return totalMinutes;
          };
          return parseAge(host.age);
        case 'status':
          // Status column is not sortable
          return '';
        default:
          return '';
      }
    };
    const valA = getVal(a) ?? '';
    const valB = getVal(b) ?? '';
    if (typeof valA === 'number' && typeof valB === 'number') {
      return (valA - valB) * dir;
    }
    return String(valA).localeCompare(String(valB)) * dir;
  });

  const toggleSort = (column) => {
    setSortConfig(prev => {
      if (prev.column === column) {
        return { column, direction: prev.direction === 'asc' ? 'desc' : 'asc' };
      }
      return { column, direction: 'asc' };
    });
  };

  const toggleFingerprintSort = (column) => {
    setFingerprintSortConfig(prev => {
      if (prev.column === column) {
        return { column, direction: prev.direction === 'asc' ? 'desc' : 'asc' };
      }
      return { column, direction: 'asc' };
    });
  };

  const sortedFingerprints = [...fingerprints].sort((a, b) => {
    const { column, direction } = fingerprintSortConfig;
    const dir = direction === 'asc' ? 1 : -1;
    const getVal = (host) => {
      switch (column) {
        case 'ip_address':
          return ipToNum(formatIpAddress(host.ip_address || host.ip));
        default:
          return '';
      }
    };
    const valA = getVal(a) ?? '';
    const valB = getVal(b) ?? '';
    if (typeof valA === 'number' && typeof valB === 'number') {
      return (valA - valB) * dir;
    }
    return String(valA).localeCompare(String(valB)) * dir;
  });

  const getEventBadgeClass = (eventType) => {
    switch (eventType) {
      case 'new':
        return 'badge-new';
      case 'changed':
        return 'badge-changed';
      case 'flip-flop':
        return 'badge-warning';
      default:
        return 'badge-info';
    }
  };

  const getStatusLabel = (status) => {
    if (!status) return 'active';
    if (status.includes('red')) return 'inactive';
    if (status.includes('orange')) return 'idle';
    return 'active';
  };

  const handlePortScan = async (ip) => {
    const formattedIp = formatIpAddress(ip);
    setScanning(prev => ({ ...prev, [formattedIp]: true }));
    setShowTooltip(prev => ({ ...prev, [formattedIp]: false }));
    
    try {
      const response = await axios.get(`${API_URL}/api/scan/${formattedIp}`);
      setScanResults(prev => ({ ...prev, [formattedIp]: response.data }));
      setShowTooltip(prev => ({ ...prev, [formattedIp]: true }));
    } catch (error) {
      setScanResults(prev => ({ 
        ...prev, 
        [formattedIp]: { 
          status: 'error', 
          error: error.response?.data?.detail || error.message,
          ports: []
        } 
      }));
      setShowTooltip(prev => ({ ...prev, [formattedIp]: true }));
    } finally {
      setScanning(prev => ({ ...prev, [formattedIp]: false }));
    }
  };

  const toggleTooltip = (ip) => {
    setShowTooltip(prev => ({ ...prev, [ip]: !prev[ip] }));
  };

  return (
    <div className="App">
      <header className="app-header">
        <div className="header-content">
          <h1>🔍 Arpwatch Monitor</h1>
          <div className="header-controls">
            <label className="switch">
              <input
                type="checkbox"
                checked={autoRefresh}
                onChange={(e) => setAutoRefresh(e.target.checked)}
              />
              <span className="slider">Auto-refresh</span>
            </label>
            <button onClick={fetchData} className="btn-refresh">
              🔄 Refresh
            </button>
            <button
              onClick={async () => {
                if (!showLogs) {
                  setShowLogs(true);
                  setLogsLoading(true);
                  try {
                    const res = await axios.get(`${API_URL}/api/logs`, { timeout: 5000 });
                    if (res.data && res.data.logs) {
                      setLogs(res.data.logs);
                    } else {
                      setLogs(['No logs data received from server']);
                    }
                  } catch (err) {
                    console.error('Error loading logs:', err);
                    setLogs([
                      `Error loading logs: ${err.message}`,
                      err.response ? `Status: ${err.response.status}` : '',
                      'Check browser console for details'
                    ].filter(Boolean));
                  } finally {
                    setLogsLoading(false);
                  }
                } else {
                  setShowLogs(false);
                }
              }}
              className="btn-refresh"
              title="View backend container logs"
            >
              📋 Logs
            </button>
            <button
              onClick={triggerFingerprintRescan}
              className="btn-refresh"
              disabled={rescanStatus === 'started' || rescanStatus === 'in_progress'}
              title="Re-run OS fingerprinting for all hosts"
            >
              🛰️ Rescan fingerprints
            </button>
            <button
              onClick={async () => {
                try {
                  const res = await axios.post(`${API_URL}/api/dns/lookup-missing`);
                  if (res.data) {
                    const { looked_up, found, failed } = res.data;
                    alert(`DNS Lookup Complete!\n\nLooked up: ${looked_up} IPs\nFound: ${found} hostnames\nFailed: ${failed}`);
                    // Refresh data to show new hostnames
                    fetchData();
                  }
                } catch (err) {
                  alert(`Error performing DNS lookups: ${err.response?.data?.detail || err.message}`);
                }
              }}
              className="btn-refresh"
              title="Perform reverse DNS lookups for IPs without hostnames"
            >
              🔍 Lookup Hostnames
            </button>
            <button
              onClick={() => setDarkMode(!darkMode)}
              className="btn-refresh"
              title={darkMode ? "Switch to light theme" : "Switch to dark theme"}
            >
              {darkMode ? "☀️ Light" : "🌙 Dark"}
            </button>
            {(rescanStatus === 'started' || rescanStatus === 'in_progress') && (
              <span className="rescan-status">Rescanning fingerprints…</span>
            )}
            {rescanError && <span className="rescan-error">Rescan error: {rescanError}</span>}
          </div>
        </div>
      </header>

      {showLogs && (
        <div className="log-viewer">
          <div className="log-viewer-wrapper">
            <div className="log-viewer-header">
              <h3>Backend Logs (Last 100 lines)</h3>
              <button className="log-close-btn" onClick={() => setShowLogs(false)}>×</button>
            </div>
            <div className="log-viewer-content">
              {logsLoading ? (
                <div className="loading" style={{color: '#d4d4d4'}}>Loading logs...</div>
              ) : (
                <pre className="log-content">
                  {logs.length > 0 ? logs.join('\n') : 'No logs available'}
                </pre>
              )}
            </div>
          </div>
        </div>
      )}

      {errors.length > 0 && (
        <div className="error-banner">
          <div className="error-title">Data refresh issues:</div>
          <div className="error-messages">
            {errors.map((err, idx) => (
              <span key={idx} className="error-chip">{err}</span>
            ))}
          </div>
        </div>
      )}

      {stats && (
        <div className="stats-section">
          <div className="stats-container">
            <div className="stat-card">
              <div className="stat-value">{stats.total_hosts}</div>
              <div className="stat-label">Total Hosts</div>
            </div>
            <div className="stat-card">
              <div className="stat-value">{stats.active_hosts}</div>
              <div className="stat-label">Active Hosts</div>
            </div>
            <div className="stat-card">
              <div className="stat-value stat-new">{stats.new_hosts}</div>
              <div className="stat-label">New Hosts</div>
            </div>
            <div className="stat-card">
              <div className="stat-value stat-changed">{stats.changed_hosts}</div>
              <div className="stat-label">Changed Hosts</div>
            </div>
          </div>
          {stats.os_distribution && Object.keys(stats.os_distribution).length > 0 && (
            <div className="os-chart-container">
              <div className="os-chart-card">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                  <h3 style={{ margin: 0 }}>OS Distribution {osFilter && <span className="filter-badge">Filtered: {osFilter}</span>}</h3>
                  <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                    <button
                      onClick={() => setChartType('bar')}
                      className="btn-refresh"
                      style={{ 
                        background: chartType === 'bar' ? '#667eea' : 'rgba(255, 255, 255, 0.2)',
                        fontSize: '0.85rem',
                        padding: '0.4rem 0.8rem'
                      }}
                      title="Bar Chart"
                    >
                      📊 Bar
                    </button>
                    <button
                      onClick={() => setChartType('pie')}
                      className="btn-refresh"
                      style={{ 
                        background: chartType === 'pie' ? '#667eea' : 'rgba(255, 255, 255, 0.2)',
                        fontSize: '0.85rem',
                        padding: '0.4rem 0.8rem'
                      }}
                      title="Pie Chart"
                    >
                      🥧 Pie
                    </button>
                  </div>
                </div>
                <ResponsiveContainer width="100%" height={300}>
                  {chartType === 'bar' ? (
                    <BarChart
                      layout="vertical"
                      data={Object.entries(stats.os_distribution)
                        .map(([name, value]) => ({ name, value }))
                        .sort((a, b) => b.value - a.value)}
                      margin={{ top: 5, right: 30, left: 60, bottom: 5 }}
                    >
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis type="number" />
                      <YAxis dataKey="name" type="category" width={100} />
                      <Tooltip />
                      <Bar 
                        dataKey="value" 
                        fill="#667eea" 
                        radius={[0, 8, 8, 0]}
                        onClick={(data) => {
                          if (data && data.name) {
                            setOsFilter(data.name);
                          }
                        }}
                        style={{ cursor: 'pointer' }}
                      >
                        {Object.entries(stats.os_distribution).map((entry, index) => (
                          <Cell 
                            key={`cell-${index}`} 
                            fill={['#667eea', '#764ba2', '#f093fb', '#4facfe', '#43e97b', '#fa709a'][index % 6]}
                            style={{ cursor: 'pointer' }}
                          />
                        ))}
                      </Bar>
                    </BarChart>
                  ) : (
                    <PieChart>
                      <Pie
                        data={Object.entries(stats.os_distribution)
                          .map(([name, value]) => ({ name, value }))
                          .sort((a, b) => b.value - a.value)}
                        cx="50%"
                        cy="50%"
                        labelLine={false}
                        label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                        outerRadius={100}
                        fill="#8884d8"
                        dataKey="value"
                        onClick={(data) => {
                          if (data && data.name) {
                            setOsFilter(data.name);
                          }
                        }}
                        style={{ cursor: 'pointer' }}
                      >
                        {Object.entries(stats.os_distribution).map((entry, index) => (
                          <Cell 
                            key={`cell-${index}`} 
                            fill={['#667eea', '#764ba2', '#f093fb', '#4facfe', '#43e97b', '#fa709a'][index % 6]}
                            style={{ cursor: 'pointer' }}
                          />
                        ))}
                      </Pie>
                      <Tooltip />
                      <Legend />
                    </PieChart>
                  )}
                </ResponsiveContainer>
              </div>
            </div>
          )}
        </div>
      )}

      <div className="main-container">
        <div className="tabs">
          <button
            className={activeTab === 'hosts' ? 'tab active' : 'tab'}
            onClick={() => setActiveTab('hosts')}
          >
            Hosts ({hosts.length})
          </button>
          <button
            className={activeTab === 'events' ? 'tab active' : 'tab'}
            onClick={() => setActiveTab('events')}
          >
            Events ({events.length})
          </button>
          <button
            className={activeTab === 'fingerprints' ? 'tab active' : 'tab'}
            onClick={() => setActiveTab('fingerprints')}
          >
            Fingerprints ({fingerprints.length})
          </button>
        </div>

        {activeTab === 'hosts' && (
          <div className="tab-content">
            <div className="search-bar">
              <input
                type="text"
                placeholder="Search by IP, MAC, or hostname..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="search-input"
              />
              {(searchQuery || osFilter) && (
                <button
                  onClick={() => {
                    setSearchQuery('');
                    setOsFilter(null);
                  }}
                  className="btn-clear-filters"
                  title="Clear all filters"
                >
                  ✕ Clear Filters
                </button>
              )}
            </div>
            {loading ? (
              <div className="loading">Loading...</div>
            ) : (
              <div className="table-container">
                <table className="hosts-table">
                  <thead>
                    <tr>
                      <th onClick={() => toggleSort('ip_address')} className="sortable">
                        IP Address {sortConfig.column === 'ip_address' ? (sortConfig.direction === 'asc' ? '▲' : '▼') : ''}
                      </th>
                      <th onClick={() => toggleSort('mac_address')} className="sortable">
                        MAC Address {sortConfig.column === 'mac_address' ? (sortConfig.direction === 'asc' ? '▲' : '▼') : ''}
                      </th>
                      <th onClick={() => toggleSort('hostname')} className="sortable">
                        Hostname {sortConfig.column === 'hostname' ? (sortConfig.direction === 'asc' ? '▲' : '▼') : ''}
                      </th>
                      {config.os_fingerprinting_enabled && (
                        <th onClick={() => toggleSort('os_fingerprint')} className="sortable">
                          OS Fingerprint {sortConfig.column === 'os_fingerprint' ? (sortConfig.direction === 'asc' ? '▲' : '▼') : ''}
                        </th>
                      )}
                      <th onClick={() => toggleSort('age')} className="sortable">
                        Age {sortConfig.column === 'age' ? (sortConfig.direction === 'asc' ? '▲' : '▼') : ''}
                      </th>
                      <th>
                        Status
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {sortedHosts.length === 0 ? (
                      <tr>
                        <td colSpan={config.os_fingerprinting_enabled ? "6" : "5"} className="no-data">
                          No hosts found
                        </td>
                      </tr>
                    ) : (
                      sortedHosts.map((host, index) => (
                        <tr key={index}>
                          <td className="ip-cell">{formatIpAddress(host.ip_address)}</td>
                          <td className="mac-cell">{formatMacAddress(host.mac_address)}</td>
                          <td className="hostname-cell">
                            {host.hostname || <span className="no-hostname">—</span>}
                          </td>
                          {config.os_fingerprinting_enabled && (
                            <td className="os-cell">
                              {host.os_fingerprint || <span className="no-os">Unknown</span>}
                            </td>
                          )}
                          <td className="age-cell">
                            {host.age || <span className="no-age">—</span>}
                          </td>
                          <td className="status-cell">
                            <div className="status-container">
                              <span className={`badge badge-${host.status}`}>
                                {getStatusLabel(host.status)}
                              </span>
                              {config.port_scanning_enabled && (
                                <button
                                  className="btn-scan"
                                  onClick={() => handlePortScan(host.ip_address)}
                                  disabled={scanning[formatIpAddress(host.ip_address)]}
                                  title={`Scan ports (${config.scan_ports ? config.scan_ports.join(', ') : '21, 22, 80, 443, 445'})`}
                                >
                                  {scanning[formatIpAddress(host.ip_address)] ? '⏳' : '🔍'}
                                </button>
                              )}
                              {showTooltip[formatIpAddress(host.ip_address)] && scanResults[formatIpAddress(host.ip_address)] && (
                                <div className="scan-tooltip">
                                  <div className="tooltip-header">
                                    <span>Port Scan Results - {formatIpAddress(host.ip_address)}</span>
                                    <button className="tooltip-close" onClick={() => toggleTooltip(formatIpAddress(host.ip_address))}>×</button>
                                  </div>
                                  <div className="tooltip-content">
                                    {scanResults[formatIpAddress(host.ip_address)].status === 'success' ? (
                                      scanResults[formatIpAddress(host.ip_address)].ports.length > 0 ? (
                                        <table className="port-table">
                                          <thead>
                                            <tr>
                                              <th>Port</th>
                                              <th>State</th>
                                              <th>Service</th>
                                              <th>Version</th>
                                            </tr>
                                          </thead>
                                          <tbody>
                                            {scanResults[formatIpAddress(host.ip_address)].ports.map((port, idx) => (
                                              <tr key={idx}>
                                                <td className="port-number">{port.port}</td>
                                                <td className={`port-state port-${port.state}`}>{port.state}</td>
                                                <td className="port-service">{port.service}</td>
                                                <td className="port-version">{port.version || '—'}</td>
                                              </tr>
                                            ))}
                                          </tbody>
                                        </table>
                                      ) : (
                                        <div className="no-ports">No open ports found</div>
                                      )
                                    ) : (
                                      <div className="scan-error">
                                        Error: {scanResults[formatIpAddress(host.ip_address)].error || 'Unknown error'}
                                      </div>
                                    )}
                                    <div className="tooltip-footer">
                                      Scanned at: {new Date(scanResults[formatIpAddress(host.ip_address)].scan_time).toLocaleString()}
                                    </div>
                                  </div>
                                </div>
                              )}
                            </div>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {activeTab === 'events' && (
          <div className="tab-content">
            {loading ? (
              <div className="loading">Loading...</div>
            ) : (
              <div className="events-list">
                {events.length === 0 ? (
                  <div className="no-data">No events found</div>
                ) : (
                  events.map((event, index) => (
                    <div key={index} className="event-card">
                      <div className="event-header">
                        <span className={`badge ${getEventBadgeClass(event.event_type)}`}>
                          {event.event_type}
                        </span>
                        <span className="event-time">{event.timestamp}</span>
                      </div>
                      <div className="event-body">
                        <div className="event-info">
                          <strong>IP:</strong> {event.ip_address}
                        </div>
                        <div className="event-info">
                          <strong>MAC:</strong> {formatMacAddress(event.mac_address)}
                        </div>
                        {event.hostname && (
                          <div className="event-info">
                            <strong>Hostname:</strong> {event.hostname}
                          </div>
                        )}
                        <div className="event-message">{event.message}</div>
                      </div>
                    </div>
                  ))
                )}
              </div>
            )}
          </div>
        )}

        {activeTab === 'fingerprints' && (
          <div className="tab-content">
            <div className="fingerprint-controls" style={{ marginBottom: '1rem', display: 'flex', gap: '1rem', alignItems: 'center', flexWrap: 'wrap' }}>
              <label className="switch" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <input
                  type="checkbox"
                  checked={showAllFingerprints}
                  onChange={(e) => setShowAllFingerprints(e.target.checked)}
                />
                <span>Show all records</span>
              </label>
              <button
                onClick={async () => {
                  try {
                    const res = await axios.get(`${API_URL}/api/fingerprints/export`);
                    const dataStr = JSON.stringify(res.data, null, 2);
                    const dataBlob = new Blob([dataStr], { type: 'application/json' });
                    const url = URL.createObjectURL(dataBlob);
                    const link = document.createElement('a');
                    link.href = url;
                    link.download = `fingerprints_export_${new Date().toISOString().split('T')[0]}.json`;
                    document.body.appendChild(link);
                    link.click();
                    document.body.removeChild(link);
                    URL.revokeObjectURL(url);
                    setFingerprintSuccess(`Exported ${res.data.count} fingerprints`);
                    setTimeout(() => setFingerprintSuccess(null), 3000);
                  } catch (err) {
                    setFingerprintError(err?.response?.data?.detail || err.message || 'Failed to export fingerprints');
                  }
                }}
                className="btn-refresh"
                title="Export manual fingerprints to JSON file"
              >
                📥 Export
              </button>
              <label className="btn-refresh" style={{ cursor: 'pointer', margin: 0 }}>
                📤 Import
                <input
                  type="file"
                  accept=".json"
                  style={{ display: 'none' }}
                  onChange={async (e) => {
                    const file = e.target.files[0];
                    if (!file) return;
                    try {
                      const formData = new FormData();
                      formData.append('file', file);
                      const res = await axios.post(`${API_URL}/api/fingerprints/import`, formData, {
                        headers: { 'Content-Type': 'multipart/form-data' }
                      });
                      setFingerprintSuccess(`${res.data.message}`);
                      fetchFingerprints();
                      fetchData();
                      setTimeout(() => setFingerprintSuccess(null), 5000);
                      e.target.value = ''; // Reset file input
                    } catch (err) {
                      setFingerprintError(err?.response?.data?.detail || err.message || 'Failed to import fingerprints');
                      e.target.value = ''; // Reset file input
                    }
                  }}
                />
              </label>
            </div>
            {fingerprintError && <div className="error-banner">Error: {fingerprintError}</div>}
            {fingerprintSuccess && <div className="success-banner">✓ {fingerprintSuccess}</div>}
            {fingerprintsLoading ? (
              <div className="loading">Loading fingerprints...</div>
            ) : fingerprints.length === 0 ? (
              <div className="no-data">{showAllFingerprints ? 'No fingerprints found' : 'No unknown fingerprints 🎉'}</div>
            ) : (
              <div className="table-container">
                <table className="hosts-table">
                  <thead>
                    <tr>
                      <th onClick={() => toggleFingerprintSort('ip_address')} className="sortable">
                        IP Address {fingerprintSortConfig.column === 'ip_address' ? (fingerprintSortConfig.direction === 'asc' ? '▲' : '▼') : ''}
                      </th>
                      <th>MAC Address</th>
                      <th>Hostname</th>
                      <th>OS Fingerprint</th>
                      <th>Status</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {sortedFingerprints.map((host, idx) => {
                      const ip = host.ip_address || host.ip;
                      const mac = host.mac_address || host.mac;
                      const os = host.os_fingerprint || host.os;
                      return (
                        <tr key={idx}>
                          <td className="ip-cell">{formatIpAddress(ip)}</td>
                          <td className="mac-cell">{formatMacAddress(mac)}</td>
                          <td className="hostname-cell">{host.hostname || <span className="no-hostname">—</span>}</td>
                          <td className="os-cell">
                            {editingFingerprint === ip ? (
                              <input
                                type="text"
                                defaultValue={os || ''}
                                onBlur={async (e) => {
                                  const newValue = e.target.value.trim();
                                  if (newValue && newValue !== os) {
                                    try {
                                      await axios.put(`${API_URL}/api/fingerprints/${ip}`, {
                                        os_fingerprint: newValue
                                      });
                                      setFingerprintSuccess(`Fingerprint updated for ${formatIpAddress(ip)}`);
                                      fetchFingerprints();
                                      setTimeout(() => setFingerprintSuccess(null), 3000);
                                    } catch (err) {
                                      setFingerprintError(err?.response?.data?.detail || err.message || 'Failed to update fingerprint');
                                    }
                                  }
                                  setEditingFingerprint(null);
                                }}
                                onKeyDown={(e) => {
                                  if (e.key === 'Enter') {
                                    e.target.blur();
                                  } else if (e.key === 'Escape') {
                                    setEditingFingerprint(null);
                                  }
                                }}
                                autoFocus
                                className="fingerprint-input"
                                style={{ width: '100%', maxWidth: '200px' }}
                              />
                            ) : (
                              <span>{os || <span className="no-os">Unknown</span>}</span>
                            )}
                          </td>
                          <td className="status-cell">
                            <span className={`badge badge-${host.status || 'active'}`}>{getStatusLabel(host.status || 'active')}</span>
                          </td>
                          <td>
                            <div style={{ display: 'flex', gap: '0.5rem' }}>
                              {!os || editingFingerprint === ip ? (
                                <button
                                  className="btn-scan"
                                  onClick={() => setEditingFingerprint(ip)}
                                  title="Edit fingerprint"
                                >
                                  ✏️
                                </button>
                              ) : (
                                <>
                                  <button
                                    className="btn-scan"
                                    onClick={() => setEditingFingerprint(ip)}
                                    title="Edit fingerprint"
                                  >
                                    ✏️
                                  </button>
                                  <button
                                    className="btn-scan"
                                    onClick={async () => {
                                      if (window.confirm(`Delete fingerprint for ${formatIpAddress(ip)}?`)) {
                                        try {
                                          await axios.delete(`${API_URL}/api/fingerprints/${ip}`);
                                          setFingerprintSuccess(`Fingerprint deleted for ${formatIpAddress(ip)}`);
                                          fetchFingerprints();
                                          setTimeout(() => setFingerprintSuccess(null), 3000);
                                        } catch (err) {
                                          setFingerprintError(err?.response?.data?.detail || err.message || 'Failed to delete fingerprint');
                                        }
                                      }
                                    }}
                                    title="Delete fingerprint"
                                    style={{ background: '#ef4444' }}
                                  >
                                    🗑️
                                  </button>
                                </>
                              )}
                              {!os && (
                                <div className="fingerprint-input-row" style={{ display: 'inline-flex', marginLeft: '0.5rem' }}>
                                  <input
                                    type="text"
                                    placeholder="Enter OS"
                                    value={fingerprintInputs[ip] ?? ''}
                                    onChange={(e) => setFingerprintInputs(prev => ({ ...prev, [ip]: e.target.value }))}
                                    className="fingerprint-input"
                                    style={{ width: '150px' }}
                                  />
                                  <button
                                    className="btn-scan"
                                    onClick={async () => {
                                      try {
                                        setFingerprintError(null);
                                        setFingerprintSuccess(null);
                                        await axios.post(`${API_URL}/api/fingerprints/${ip}`, {
                                          os_fingerprint: fingerprintInputs[ip] || ''
                                        });
                                        setFingerprintSuccess(`Fingerprint saved for ${formatIpAddress(ip)}`);
                                        setFingerprintInputs(prev => {
                                          const updated = { ...prev };
                                          delete updated[ip];
                                          return updated;
                                        });
                                        fetchFingerprints();
                                        setTimeout(() => {
                                          fetchData();
                                          setFingerprintSuccess(null);
                                        }, 2000);
                                      } catch (err) {
                                        setFingerprintError(err?.response?.data?.detail || err.message || 'Failed to save fingerprint');
                                        setFingerprintSuccess(null);
                                      }
                                    }}
                                    disabled={!fingerprintInputs[ip]}
                                    title="Save OS fingerprint"
                                  >
                                    💾
                                  </button>
                                </div>
                              )}
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}
      </div>

      <footer className="app-footer">
        <p>Arpwatch Web UI v0.3.1 | Network Monitoring Dashboard</p>
      </footer>
    </div>
  );
}

export default App;

