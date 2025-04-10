import React, { useEffect, useState } from 'react';
import { useSecurity } from '../context/SecurityContext';
import { 
  FaShieldAlt, 
  FaExclamationTriangle, 
  FaDesktop, 
  FaTerminal, 
  FaUserSecret,
  FaChartLine,
  FaHourglass
} from 'react-icons/fa';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import './Dashboard.css';

const Dashboard = () => {
  const { 
    connected, 
    monitoring, 
    stats, 
    alerts, 
    connectToElasticsearch, 
    startMonitoring, 
    stopMonitoring,
    fetchAlerts,
    loading,
    error,
    clearError,
    settings
  } = useSecurity();

  // State for monitoring duration
  const [monitoringDuration, setMonitoringDuration] = useState(0);
  // State for chart data
  const [chartData, setChartData] = useState([]);

  useEffect(() => {
    // Fetch alerts when component mounts
    if (connected) {
      fetchAlerts();
    }

    // Initialize the chart data
    updateChartData();

    // Setup monitoring duration timer
    let timer;
    if (monitoring) {
      timer = setInterval(() => {
        setMonitoringDuration(prev => prev + 1);
      }, 1000);
    } else {
      setMonitoringDuration(0);
    }

    return () => {
      if (timer) clearInterval(timer);
    };
  }, [connected, monitoring]);

  // Update chart data when stats change
  useEffect(() => {
    updateChartData();
  }, [stats]);

  const updateChartData = () => {
    setChartData([
      {
        name: 'UAC Bypass',
        count: stats.bypassuac,
        color: '#FF8042'
      },
      {
        name: 'Malicious Shell',
        count: stats.malicious_shell,
        color: '#0088FE'
      },
      {
        name: 'Credential Access',
        count: stats.credential_access,
        color: '#FF0000'
      }
    ]);
  };

  const handleConnect = async () => {
    if (!connected) {
      await connectToElasticsearch();
    }
  };

  const handleStartMonitoring = async () => {
    if (connected && !monitoring) {
      await startMonitoring();
    }
  };

  const handleStopMonitoring = async () => {
    if (monitoring) {
      await stopMonitoring();
    }
  };

  // Helper to get alert type icon
  const getAlertIcon = (type) => {
    switch (type) {
      case 'UAC Bypass':
        return <FaShieldAlt />;
      case 'Malicious PowerShell':
        return <FaTerminal />;
      case 'Credential Access':
        return <FaUserSecret />;
      default:
        return <FaExclamationTriangle />;
    }
  };

  // Format time display
  const formatMonitoringTime = (seconds) => {
    const hrs = Math.floor(seconds / 3600);
    const mins = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;
    return `${hrs.toString().padStart(2, '0')}:${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
  };

  return (
    <div className="dashboard">
      <div className="dashboard-header">
        <h2>Security Dashboard</h2>
        <div className="dashboard-actions">
          <button 
            className={`btn ${connected ? 'btn-disabled' : 'btn-primary'}`}
            onClick={handleConnect}
            disabled={connected || loading}
          >
            {loading && !connected ? 'Connecting...' : 'Connect to Elasticsearch'}
          </button>
          
          <button 
            className={`btn ${!connected || monitoring ? 'btn-disabled' : 'btn-success'}`}
            onClick={handleStartMonitoring}
            disabled={!connected || monitoring || loading}
          >
            {loading && !monitoring ? 'Starting...' : 'Start Monitoring'}
          </button>
          
          <button 
            className={`btn ${!monitoring ? 'btn-disabled' : 'btn-danger'}`}
            onClick={handleStopMonitoring}
            disabled={!monitoring || loading}
          >
            {loading && monitoring ? 'Stopping...' : 'Stop Monitoring'}
          </button>
        </div>
      </div>

      {error && (
        <div className="error-message">
          <p>{error}</p>
          <button className="btn btn-sm" onClick={clearError}>Dismiss</button>
        </div>
      )}

      <div className="monitoring-timer">
        {monitoring && (
          <div className="timer">
            <FaHourglass />
            <span>Monitoring Active: {formatMonitoringTime(monitoringDuration)}</span>
          </div>
        )}
      </div>

      <div className="status-summary">
        <div className="status-card">
          <div className="status-icon">
            <FaShieldAlt />
          </div>
          <div className="status-details">
            <h3>UAC Bypass</h3>
            <p className="status-value">{stats.bypassuac}</p>
            <p className="status-label">Detected Attempts</p>
          </div>
        </div>
        
        <div className="status-card">
          <div className="status-icon">
            <FaTerminal />
          </div>
          <div className="status-details">
            <h3>Malicious PowerShell</h3>
            <p className="status-value">{stats.malicious_shell}</p>
            <p className="status-label">Detected Activities</p>
          </div>
        </div>
        
        <div className="status-card">
          <div className="status-icon">
            <FaUserSecret />
          </div>
          <div className="status-details">
            <h3>Credential Access</h3>
            <p className="status-value">{stats.credential_access}</p>
            <p className="status-label">Detected Attempts</p>
          </div>
        </div>
        
        <div className="status-card">
          <div className="status-icon">
            <FaExclamationTriangle />
          </div>
          <div className="status-details">
            <h3>Total Alerts</h3>
            <p className="status-value">{stats.total}</p>
            <p className="status-label">Processed</p>
          </div>
        </div>
      </div>

      <div className="dashboard-charts">
        <div className="chart-container">
          <h3><FaChartLine /> Alert Distribution</h3>
          <div className="chart">
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={chartData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="name" />
                <YAxis />
                <Tooltip />
                <Legend />
                <Bar dataKey="count" name="Number of Alerts" fill="#8884d8" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="current-config">
          <h3><FaDesktop /> Current Configuration</h3>
          <div className="config-items">
            <div className="config-item">
              <span className="config-label">Elasticsearch Index:</span>
              <span className="config-value">{settings.index}</span>
            </div>
            <div className="config-item">
              <span className="config-label">Check Interval:</span>
              <span className="config-value">{settings.interval} seconds</span>
            </div>
            <div className="config-item">
              <span className="config-label">Window Size:</span>
              <span className="config-value">{settings.window_size} seconds</span>
            </div>
            {settings.agent_id && (
              <div className="config-item">
                <span className="config-label">Agent ID:</span>
                <span className="config-value">{settings.agent_id}</span>
              </div>
            )}
          </div>
        </div>
      </div>

      <div className="recent-alerts">
        <h3>Recent Alerts</h3>
        {alerts.length > 0 ? (
          <div className="alerts-list">
            {alerts.slice(0, 5).map((alert, index) => (
              <div className="alert-item" key={index}>
                <div className="alert-icon">
                  {getAlertIcon(alert.type)}
                </div>
                <div className="alert-details">
                  <h4>{alert.type}</h4>
                  <p className="alert-description">{alert.description}</p>
                  <p className="alert-meta">
                    <span>Agent: {alert.agent_id}</span>
                    <span>Time: {new Date(alert.timestamp).toLocaleString()}</span>
                  </p>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <p className="no-data">No recent alerts detected.</p>
        )}
        
        {alerts.length > 5 && (
          <div className="view-all">
            <a href="/alerts">View all alerts</a>
          </div>
        )}
      </div>

      <div className="system-status">
        <h3>System Status</h3>
        <div className="status-items">
          <div className="status-item">
            <div className="status-label">Connection Status</div>
            <div className={`status-value ${connected ? 'status-success' : 'status-danger'}`}>
              {connected ? 'Connected' : 'Disconnected'}
            </div>
          </div>
          
          <div className="status-item">
            <div className="status-label">Monitoring Status</div>
            <div className={`status-value ${monitoring ? 'status-success' : 'status-warning'}`}>
              {monitoring ? 'Active' : 'Inactive'}
            </div>
          </div>
          
          <div className="status-item">
            <div className="status-label">Elasticsearch Index</div>
            <div className="status-value">{settings.index}</div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;