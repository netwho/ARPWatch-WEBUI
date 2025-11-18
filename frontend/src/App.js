import React, { useState, useEffect } from 'react';
import axios from 'axios';
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

  useEffect(() => {
    fetchData();
    if (autoRefresh) {
      const interval = setInterval(fetchData, 5000); // Refresh every 5 seconds
      return () => clearInterval(interval);
    }
  }, [autoRefresh]);

  const fetchData = async () => {
    try {
      const [hostsRes, eventsRes, statsRes] = await Promise.all([
        axios.get(`${API_URL}/api/hosts`),
        axios.get(`${API_URL}/api/events?limit=50`),
        axios.get(`${API_URL}/api/stats`)
      ]);
      setHosts(hostsRes.data);
      setEvents(eventsRes.data);
      setStats(statsRes.data);
      setLoading(false);
    } catch (error) {
      console.error('Error fetching data:', error);
      setLoading(false);
    }
  };

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
          </div>
        </div>
      </header>

      {stats && (
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
                      <th>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredHosts.length === 0 ? (
                      <tr>
                        <td colSpan="4" className="no-data">
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
                          <td>
                            <span className={`badge badge-${host.status}`}>
                              {host.status}
                            </span>
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
        <p>Arpwatch Web UI v0.1.0 | Network Monitoring Dashboard</p>
      </footer>
    </div>
  );
}

export default App;

