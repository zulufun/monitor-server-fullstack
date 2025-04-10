import React from 'react';
import { useSecurity } from '../context/SecurityContext';
import './Header.css';

const Header = () => {
  const { connected, monitoring, stats } = useSecurity();

  return (
    <header className="header">
      <div className="header-logo">
        <h1>Security Monitor</h1>
      </div>
      <div className="header-status">
        <div className={`status-indicator ${connected ? 'connected' : 'disconnected'}`}>
          {connected ? 'Connected' : 'Disconnected'}
        </div>
        <div className={`status-indicator ${monitoring ? 'monitoring' : 'idle'}`}>
          {monitoring ? 'Monitoring' : 'Idle'}
        </div>
      </div>
      <div className="header-stats">
        <div className="stat-item">
          <span className="stat-label">Total Alerts:</span>
          <span className="stat-value">{stats.total}</span>
        </div>
        <div className="stat-item">
          <span className="stat-label">UAC Bypass:</span>
          <span className="stat-value">{stats.bypassuac}</span>
        </div>
        <div className="stat-item">
          <span className="stat-label">Malicious Shell:</span>
          <span className="stat-value">{stats.malicious_shell}</span>
        </div>
        <div className="stat-item">
          <span className="stat-label">Credential Access:</span>
          <span className="stat-value">{stats.credential_access}</span>
        </div>
      </div>
    </header>
  );
};

export default Header;