import React, { useState, useEffect } from 'react';
import { useSecurity } from '../context/SecurityContext';
import { FaShieldAlt, FaTerminal, FaUserSecret, FaExclamationTriangle, FaSearch } from 'react-icons/fa';
import './Alerts.css';

const Alerts = () => {
  const { alerts, fetchAlerts, loading } = useSecurity();
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [filterType, setFilterType] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');
  
  useEffect(() => {
    // Fetch alerts when component mounts
    fetchAlerts();
  }, []);
  
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
  
  // Filter alerts based on type and search term
  const filteredAlerts = alerts.filter(alert => {
    const matchesType = filterType === 'all' || alert.type === filterType;
    const matchesSearch = searchTerm === '' || 
      alert.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
      alert.agent_id.toLowerCase().includes(searchTerm.toLowerCase());
    
    return matchesType && matchesSearch;
  });
  
  // Handle alert selection
  const handleAlertClick = (alert) => {
    setSelectedAlert(alert);
  };
  
  // Close alert details
  const closeAlertDetails = () => {
    setSelectedAlert(null);
  };

  return (
    <div className="alerts-page">
      <div className="alerts-header">
        <h2>Security Alerts</h2>
        <div className="alerts-controls">
          <div className="filter-controls">
            <select 
              value={filterType} 
              onChange={(e) => setFilterType(e.target.value)}
              className="filter-dropdown"
            >
              <option value="all">All Alert Types</option>
              <option value="UAC Bypass">UAC Bypass</option>
              <option value="Malicious PowerShell">Malicious PowerShell</option>
              <option value="Credential Access">Credential Access</option>
            </select>
            
            <div className="search-box">
              <FaSearch className="search-icon" />
              <input
                type="text"
                placeholder="Search alerts..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
              />
            </div>
          </div>
          
          <button 
            className="btn btn-refresh" 
            onClick={fetchAlerts}
            disabled={loading}
          >
            {loading ? 'Loading...' : 'Refresh'}
          </button>
        </div>
      </div>
      
      <div className="alerts-container">
        {filteredAlerts.length > 0 ? (
          <div className="alerts-list">
            {filteredAlerts.map((alert, index) => (
              <div 
                className={`alert-item ${selectedAlert === alert ? 'selected' : ''}`} 
                key={index}
                onClick={() => handleAlertClick(alert)}
              >
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
          <div className="no-data">
            {loading ? 'Loading alerts...' : 'No alerts found matching your criteria.'}
          </div>
        )}
        
        {selectedAlert && (
          <div className="alert-details-panel">
            <div className="details-header">
              <h3>Alert Details</h3>
              <button className="btn-close" onClick={closeAlertDetails}>×</button>
            </div>
            
            <div className="details-content">
              <div className="details-section">
                <h4>Summary</h4>
                <div className="detail-item">
                  <span className="detail-label">Type:</span>
                  <span className="detail-value">{selectedAlert.type}</span>
                </div>
                <div className="detail-item">
                  <span className="detail-label">Agent ID:</span>
                  <span className="detail-value">{selectedAlert.agent_id}</span>
                </div>
                <div className="detail-item">
                  <span className="detail-label">Timestamp:</span>
                  <span className="detail-value">{new Date(selectedAlert.timestamp).toLocaleString()}</span>
                </div>
                <div className="detail-item">
                  <span className="detail-label">Description:</span>
                  <span className="detail-value">{selectedAlert.description}</span>
                </div>
              </div>
              
              {selectedAlert.full_alert && (
                <>
                  <div className="details-section">
                    <h4>Agent Details</h4>
                    {selectedAlert.full_alert.agent && (
                      <>
                        <div className="detail-item">
                          <span className="detail-label">Name:</span>
                          <span className="detail-value">{selectedAlert.full_alert.agent.name || 'N/A'}</span>
                        </div>
                        <div className="detail-item">
                          <span className="detail-label">IP:</span>
                          <span className="detail-value">{selectedAlert.full_alert.agent.ip || 'N/A'}</span>
                        </div>
                      </>
                    )}
                  </div>
                  
                  <div className="details-section">
                    <h4>Rule Details</h4>
                    {selectedAlert.full_alert.rule && (
                      <>
                        <div className="detail-item">
                          <span className="detail-label">Rule ID:</span>
                          <span className="detail-value">{selectedAlert.full_alert.rule.id || 'N/A'}</span>
                        </div>
                        <div className="detail-item">
                          <span className="detail-label">Level:</span>
                          <span className="detail-value">{selectedAlert.full_alert.rule.level || 'N/A'}</span>
                        </div>
                        <div className="detail-item">
                          <span className="detail-label">Description:</span>
                          <span className="detail-value">{selectedAlert.full_alert.rule.description || 'N/A'}</span>
                        </div>
                      </>
                    )}
                  </div>
                  
                  <div className="details-section">
                    <h4>Raw JSON</h4>
                    <div className="raw-json">
                      <pre>{JSON.stringify(selectedAlert.full_alert, null, 2)}</pre>
                    </div>
                  </div>
                </>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default Alerts;