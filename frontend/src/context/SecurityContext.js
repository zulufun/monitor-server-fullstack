import React, { createContext, useState, useEffect, useContext } from 'react';
import api from '../services/api';

// Create context
const SecurityContext = createContext();

// Custom hook to use the security context
export const useSecurity = () => useContext(SecurityContext);

export const SecurityProvider = ({ children }) => {
  // State for connection status
  const [connected, setConnected] = useState(false);
  const [monitoring, setMonitoring] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  
  // State for data
  const [alerts, setAlerts] = useState([]);
  const [logs, setLogs] = useState([]);
  const [stats, setStats] = useState({
    total: 0,
    bypassuac: 0,
    malicious_shell: 0,
    credential_access: 0
  });

  // State for event source
  const [eventSource, setEventSource] = useState(null);
  
  // State for settings
  const [settings, setSettings] = useState({
    index: "wazuh-alerts-*",
    interval: 5,
    agent_id: "",
    alert_level: 7,
    start_time: "",
    window_size: 5
  });

  // Check initial status
  useEffect(() => {
    checkStatus();
    
    // Cleanup function
    return () => {
      if (eventSource) {
        eventSource.close();
      }
    };
  }, []);

  // Check server status
  const checkStatus = async () => {
    try {
      setLoading(true);
      const response = await api.get('/api/status');
      
      setConnected(response.data.connected);
      setMonitoring(response.data.monitoring);
      setStats(response.data.stats);
      
      if (response.data.monitoring && !eventSource) {
        setupEventSource();
      }
      
      setError(null);
    } catch (err) {
      setError('Failed to connect to server: ' + (err.message || 'Unknown error'));
      setConnected(false);
      setMonitoring(false);
    } finally {
      setLoading(false);
    }
  };

  // Connect to Elasticsearch
  const connectToElasticsearch = async () => {
    try {
      setLoading(true);
      const response = await api.post('/api/connect');
      
      if (response.data.success) {
        setConnected(true);
        setError(null);
        return true;
      } else {
        setError('Failed to connect: ' + response.data.error);
        return false;
      }
    } catch (err) {
      setError('Failed to connect: ' + (err.message || 'Unknown error'));
      return false;
    } finally {
      setLoading(false);
    }
  };

  // Start monitoring
  const startMonitoring = async () => {
    try {
      setLoading(true);
      const response = await api.post('/api/start', settings);
      
      if (response.data.success) {
        setMonitoring(true);
        setError(null);
        setupEventSource();
        return true;
      } else {
        setError('Failed to start monitoring: ' + response.data.error);
        return false;
      }
    } catch (err) {
      setError('Failed to start monitoring: ' + (err.message || 'Unknown error'));
      return false;
    } finally {
      setLoading(false);
    }
  };

  // Stop monitoring
  const stopMonitoring = async () => {
    try {
      setLoading(true);
      const response = await api.post('/api/stop');
      
      if (response.data.success) {
        setMonitoring(false);
        if (eventSource) {
          eventSource.close();
          setEventSource(null);
        }
        setError(null);
        return true;
      } else {
        setError('Failed to stop monitoring: ' + response.data.error);
        return false;
      }
    } catch (err) {
      setError('Failed to stop monitoring: ' + (err.message || 'Unknown error'));
      return false;
    } finally {
      setLoading(false);
    }
  };

  // Fetch alerts
  const fetchAlerts = async () => {
    try {
      setLoading(true);
      const response = await api.get('/api/alerts');
      setAlerts(response.data);
      setError(null);
    } catch (err) {
      setError('Failed to fetch alerts: ' + (err.message || 'Unknown error'));
    } finally {
      setLoading(false);
    }
  };

  // Fetch logs
  const fetchLogs = async () => {
    try {
      setLoading(true);
      const response = await api.get('/api/logs');
      setLogs(response.data);
      setError(null);
    } catch (err) {
      setError('Failed to fetch logs: ' + (err.message || 'Unknown error'));
    } finally {
      setLoading(false);
    }
  };

  // Setup event source for real-time updates
  const setupEventSource = () => {
    if (eventSource) {
      eventSource.close();
    }

    const newEventSource = new EventSource(`${api.defaults.baseURL}/api/events`);
    
    newEventSource.addEventListener('log', (event) => {
      const logData = JSON.parse(event.data);
      setLogs(prevLogs => [logData, ...prevLogs.slice(0, 999)]);
    });

    newEventSource.addEventListener('alert', (event) => {
      const alertData = JSON.parse(event.data);
      setAlerts(prevAlerts => [alertData, ...prevAlerts.slice(0, 49)]);
    });

    newEventSource.addEventListener('stats', (event) => {
      const statsData = JSON.parse(event.data);
      setStats(statsData);
    });

    newEventSource.onerror = () => {
      console.error('EventSource failed, reconnecting...');
      setTimeout(() => {
        if (monitoring) {
          setupEventSource();
        }
      }, 5000);
    };

    setEventSource(newEventSource);
  };

  // Update settings
  const updateSettings = (newSettings) => {
    setSettings(prev => ({ ...prev, ...newSettings }));
  };

  const value = {
    connected,
    monitoring,
    loading,
    error,
    alerts,
    logs,
    stats,
    settings,
    checkStatus,
    connectToElasticsearch,
    startMonitoring,
    stopMonitoring,
    fetchAlerts,
    fetchLogs,
    updateSettings,
    clearError: () => setError(null)
  };

  return (
    <SecurityContext.Provider value={value}>
      {children}
    </SecurityContext.Provider>
  );
};