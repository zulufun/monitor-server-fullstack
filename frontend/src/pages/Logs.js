import React, { useEffect, useRef, useState } from 'react';
import { useSecurity } from '../context/SecurityContext';
import { FaDownload, FaSearch, FaFilter } from 'react-icons/fa';
import './Logs.css';

// ANSI color codes mapping to CSS classes
const COLOR_MAP = {
  // Regular colors
  '30': 'ansi-black',
  '31': 'ansi-red',
  '32': 'ansi-green',
  '33': 'ansi-yellow',
  '34': 'ansi-blue',
  '35': 'ansi-magenta',
  '36': 'ansi-cyan',
  '37': 'ansi-white',
  // Bright colors
  '90': 'ansi-bright-black',
  '91': 'ansi-bright-red',
  '92': 'ansi-bright-green',
  '93': 'ansi-bright-yellow',
  '94': 'ansi-bright-blue',
  '95': 'ansi-bright-magenta',
  '96': 'ansi-bright-cyan',
  '97': 'ansi-bright-white',
  // Background colors
  '40': 'ansi-bg-black',
  '41': 'ansi-bg-red',
  '42': 'ansi-bg-green',
  '43': 'ansi-bg-yellow',
  '44': 'ansi-bg-blue',
  '45': 'ansi-bg-magenta',
  '46': 'ansi-bg-cyan',
  '47': 'ansi-bg-white',
};

// Parse ANSI color codes and convert to HTML spans with appropriate CSS classes
const parseAnsiColors = (text) => {
  if (!text) return '';
  
  // Regular expression to match ANSI escape sequences
  const ansiRegex = /\u001b\[(3[0-7]|9[0-7]|4[0-7])m([^\u001b]*)\u001b\[0m/g;
  let result = [];
  let lastIndex = 0;
  let match;

  while ((match = ansiRegex.exec(text)) !== null) {
    // Add text before the match
    if (match.index > lastIndex) {
      result.push(<span key={`text-${lastIndex}`}>{text.substring(lastIndex, match.index)}</span>);
    }

    // Add the colored text
    const colorCode = match[1];
    const coloredText = match[2];
    const colorClass = COLOR_MAP[colorCode] || '';
    
    result.push(
      <span key={`colored-${match.index}`} className={colorClass}>
        {coloredText}
      </span>
    );

    lastIndex = match.index + match[0].length;
  }

  // Add remaining text after last match
  if (lastIndex < text.length) {
    result.push(<span key={`text-${lastIndex}`}>{text.substring(lastIndex)}</span>);
  }

  return result.length > 0 ? result : text;
};

const Logs = () => {
  const { logs, fetchLogs, loading } = useSecurity();
  const [filterLevel, setFilterLevel] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [autoScroll, setAutoScroll] = useState(true);
  const logsEndRef = useRef(null);
  
  useEffect(() => {
    // Fetch logs when component mounts
    fetchLogs();
  }, []);
  
  // Auto scroll to bottom when new logs arrive
  useEffect(() => {
    if (autoScroll && logsEndRef.current) {
      logsEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs, autoScroll]);
  
  // Filter logs based on level and search term
  const filteredLogs = logs.filter(log => {
    const matchesLevel = filterLevel === 'all' || log.level === filterLevel;
    const matchesSearch = searchTerm === '' || 
      log.message.toLowerCase().includes(searchTerm.toLowerCase());
    
    return matchesLevel && matchesSearch;
  });
  
  // Handle log export
  const handleExportLogs = () => {
    // Create text content
    const logText = logs
      .map(log => `${log.timestamp} - ${log.level.toUpperCase()} - ${log.message}`)
      .join('\n');
      
    // Create file and download
    const blob = new Blob([logText], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const filename = `security_monitor_logs_${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.log`;
    
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    
    setTimeout(() => {
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }, 100);
  };
  
  // Get class for log level
  const getLogLevelClass = (level) => {
    switch (level) {
      case 'error':
        return 'log-error';
      case 'warning':
        return 'log-warning';
      case 'info':
        return 'log-info';
      default:
        return '';
    }
  };

  return (
    <div className="logs-page">
      <div className="logs-header">
        <h2>System Logs</h2>
        <div className="logs-controls">
          <div className="filter-controls">
            <div className="filter-group">
              <FaFilter className="filter-icon" />
              <select 
                value={filterLevel} 
                onChange={(e) => setFilterLevel(e.target.value)}
                className="filter-dropdown"
              >
                <option value="all">All Levels</option>
                <option value="info">Info</option>
                <option value="warning">Warning</option>
                <option value="error">Error</option>
              </select>
            </div>
            
            <div className="search-box">
              <FaSearch className="search-icon" />
              <input
                type="text"
                placeholder="Search logs..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
              />
            </div>
          </div>
          
          <div className="action-controls">
            <label className="auto-scroll-toggle">
              <input
                type="checkbox"
                checked={autoScroll}
                onChange={() => setAutoScroll(!autoScroll)}
              />
              Auto-scroll
            </label>
            
            <button 
              className="btn btn-export" 
              onClick={handleExportLogs}
              disabled={logs.length === 0}
            >
              <FaDownload /> Export Logs
            </button>
            
            <button 
              className="btn btn-refresh" 
              onClick={fetchLogs}
              disabled={loading}
            >
              {loading ? 'Loading...' : 'Refresh'}
            </button>
          </div>
        </div>
      </div>
      
      <div className="logs-container">
        {filteredLogs.length > 0 ? (
          <div className="logs-list">
            {filteredLogs.map((log, index) => (
              <div 
                className={`log-entry ${getLogLevelClass(log.level)}`} 
                key={index}
              >
                <span className="log-timestamp">{new Date(log.timestamp).toLocaleString()}</span>
                <span className="log-level">{log.level.toUpperCase()}</span>
                <span className="log-message">{parseAnsiColors(log.message)}</span>
              </div>
            ))}
            <div ref={logsEndRef} />
          </div>
        ) : (
          <div className="no-data">
            {loading ? 'Loading logs...' : 'No logs found matching your criteria.'}
          </div>
        )}
      </div>
    </div>
  );
};

export default Logs;