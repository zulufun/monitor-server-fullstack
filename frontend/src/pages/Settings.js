import React, { useState } from 'react';
import { useSecurity } from '../context/SecurityContext';
import { FaSave, FaCog } from 'react-icons/fa';
import './Settings.css';

const Settings = () => {
  const { settings, updateSettings, connected, monitoring } = useSecurity();
  const [formData, setFormData] = useState({ ...settings });
  const [saveSuccess, setSaveSuccess] = useState(false);
  
  // Handle input changes
  const handleChange = (e) => {
    const { name, value, type } = e.target;
    
    // Convert to number if needed
    const processedValue = type === 'number' ? parseInt(value, 10) : value;
    
    setFormData({
      ...formData,
      [name]: processedValue
    });
  };
  
  // Handle form submission
  const handleSubmit = (e) => {
    e.preventDefault();
    
    // Update settings in context
    updateSettings(formData);
    
    // Show success message
    setSaveSuccess(true);
    setTimeout(() => setSaveSuccess(false), 3000);
  };
  
  return (
    <div className="settings-page">
      <div className="settings-header">
        <h2>System Settings</h2>
        {monitoring && (
          <div className="settings-warning">
            <p>
              <strong>Note:</strong> Some settings will not take effect until monitoring is restarted.
            </p>
          </div>
        )}
      </div>
      
      <form className="settings-form" onSubmit={handleSubmit}>
        <div className="settings-section">
          <h3><FaCog /> Elasticsearch Settings</h3>
          
          <div className="form-group">
            <label htmlFor="index">Elasticsearch Index</label>
            <input
              type="text"
              id="index"
              name="index"
              value={formData.index}
              onChange={handleChange}
              disabled={!connected}
            />
            <div className="form-help">The Elasticsearch index pattern to query for alerts.</div>
          </div>
          
          <div className="form-group">
            <label htmlFor="agent_id">Agent ID (Optional)</label>
            <input
              type="text"
              id="agent_id"
              name="agent_id"
              value={formData.agent_id}
              onChange={handleChange}
              placeholder="Filter by specific agent"
              disabled={!connected}
            />
            <div className="form-help">Limit monitoring to a specific agent by ID.</div>
          </div>
          
          <div className="form-group">
            <label htmlFor="alert_level">Minimum Alert Level</label>
            <input
              type="number"
              id="alert_level"
              name="alert_level"
              min="0"
              max="15"
              value={formData.alert_level}
              onChange={handleChange}
              disabled={!connected}
            />
            <div className="form-help">Only process alerts with a level at or above this value.</div>
          </div>
        </div>
        
        <div className="settings-section">
          <h3><FaCog /> Time Window Settings</h3>
          
          <div className="form-group">
            <label htmlFor="interval">Check Interval (seconds)</label>
            <input
              type="number"
              id="interval"
              name="interval"
              min="1"
              max="60"
              value={formData.interval}
              onChange={handleChange}
              disabled={!connected}
            />
            <div className="form-help">How often to check for new alerts (in seconds).</div>
          </div>
          
          <div className="form-group">
            <label htmlFor="window_size">Window Size (seconds)</label>
            <input
              type="number"
              id="window_size"
              name="window_size"
              min="1"
              value={formData.window_size}
              onChange={handleChange}
              disabled={!connected}
            />
            <div className="form-help">Size of each monitoring time window in seconds.</div>
          </div>
          
          <div className="form-group">
            <label htmlFor="start_time">Start Time (ISO format)</label>
            <input
              type="text"
              id="start_time"
              name="start_time"
              value={formData.start_time}
              onChange={handleChange}
              placeholder="YYYY-MM-DDTHH:MM:SS (leave empty for current time)"
              disabled={!connected}
            />
            <div className="form-help">
              Optional specific start time. Example: 2025-03-01T00:00:00
            </div>
          </div>
        </div>
        
        <div className="form-actions">
          <button
            type="submit"
            className="btn btn-primary"
            disabled={!connected || JSON.stringify(settings) === JSON.stringify(formData)}
          >
            <FaSave /> Save Settings
          </button>
          
          {saveSuccess && (
            <span className="save-success">Settings saved successfully!</span>
          )}
        </div>
      </form>
    </div>
  );
};

export default Settings;