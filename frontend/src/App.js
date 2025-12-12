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
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [scanResults, setScanResults] = useState({});
  const [scanning, setScanning] = useState({});
  const [showTooltip, setShowTooltip] = useState({});
  const [config, setConfig] = useState({ os_fingerprinting_enabled: true, port_scanning_enabled: true });
  const [errors, setErrors] = useState([]);
  const [rescanStatus, setRescanStatus] = useState('idle');
  const [rescanError, setRescanError] = useState(null);

  useEffect(() => {
    fetchData();
    if (autoRefresh) {
      const interval = setInterval(fetchData, 5000); // Refresh every 5 seconds
      return () => clearInterval(interval);
    }
  }, [autoRefresh]);

  const fetchData = async () => {
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

    const [hostsData, eventsData, statsData, configData] = await Promise.all([
      safeFetch('hosts', () => axios.get(`${API_URL}/api/hosts`)),
      safeFetch('events', () => axios.get(`${API_URL}/api/events?limit=50`)),
      safeFetch('stats', () => axios.get(`${API_URL}/api/stats`)),
      safeFetch('config', () => axios.get(`${API_URL}/api/config`))
    ]);

    if (hostsData) setHosts(hostsData);
    if (eventsData) setEvents(eventsData);
    if (statsData) setStats(statsData);
    setConfig(configData || fallbackConfig);
    setErrors(newErrors);
    setLoading(false);
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

  const filteredHosts = hosts.filter(host => {
    if (!searchQuery) return true;
    const query = searchQuery.toLowerCase();
    return (
      host.ip_address.toLowerCase().includes(query) ||
      host.mac_address.toLowerCase().includes(query) ||
      (host.hostname && host.hostname.toLowerCase().includes(query))
    );
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
              onClick={triggerFingerprintRescan}
              className="btn-refresh"
              disabled={rescanStatus === 'started' || rescanStatus === 'in_progress'}
              title="Re-run OS fingerprinting for all hosts"
            >
              🛰️ Rescan fingerprints
            </button>
            {(rescanStatus === 'started' || rescanStatus === 'in_progress') && (
              <span className="rescan-status">Rescanning fingerprints…</span>
            )}
            {rescanError && <span className="rescan-error">Rescan error: {rescanError}</span>}
          </div>
        </div>
      </header>

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
                <h3>OS Distribution</h3>
                <ResponsiveContainer width="100%" height={300}>
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
                    <Bar dataKey="value" fill="#667eea" radius={[0, 8, 8, 0]}>
                      {Object.entries(stats.os_distribution).map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={['#667eea', '#764ba2', '#f093fb', '#4facfe', '#43e97b', '#fa709a'][index % 6]} />
                      ))}
                    </Bar>
                  </BarChart>
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
            </div>
            {loading ? (
              <div className="loading">Loading...</div>
            ) : (
              <div className="table-container">
                <table className="hosts-table">
                  <thead>
                    <tr>
                      <th>IP Address</th>
                      <th>MAC Address</th>
                      <th>Hostname</th>
                      {config.os_fingerprinting_enabled && <th>OS Fingerprint</th>}
                      <th>Age</th>
                      <th>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredHosts.length === 0 ? (
                      <tr>
                        <td colSpan={config.os_fingerprinting_enabled ? "6" : "5"} className="no-data">
                          No hosts found
                        </td>
                      </tr>
                    ) : (
                      filteredHosts.map((host, index) => (
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
      </div>

      <footer className="app-footer">
        <p>Arpwatch Web UI v0.2.3 | Network Monitoring Dashboard</p>
      </footer>
    </div>
  );
}

export default App;

