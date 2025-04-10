import React, { useState } from 'react';
import { NavLink } from 'react-router-dom';
import { 
  FaChartBar, 
  FaExclamationTriangle, 
  FaList, 
  FaCog,
  FaChevronLeft,
  FaChevronRight
} from 'react-icons/fa';
import { useSecurity } from '../context/SecurityContext';
import './Sidebar.css';

const Sidebar = () => {
  const [collapsed, setCollapsed] = useState(false);
  const { alerts } = useSecurity();
  
  // Count unread alerts - this is a placeholder function
  // In a real app, you'd track which alerts have been viewed
  const unreadAlerts = alerts.length > 0 ? alerts.length : null;
  
  const toggleSidebar = () => {
    setCollapsed(!collapsed);
  };
  
  return (
    <aside className={`sidebar ${collapsed ? 'collapsed' : ''}`}>
      <nav className="sidebar-nav">
        <ul>
          <li>
            <NavLink to="/" className={({ isActive }) => isActive ? 'active' : ''}>
              <FaChartBar />
              <span>Dashboard</span>
            </NavLink>
          </li>
          <li>
            <NavLink to="/alerts" className={({ isActive }) => isActive ? 'active' : ''}>
              <FaExclamationTriangle />
              <span>Alerts</span>
              {unreadAlerts && <div className="badge">{unreadAlerts}</div>}
            </NavLink>
          </li>
          <li>
            <NavLink to="/logs" className={({ isActive }) => isActive ? 'active' : ''}>
              <FaList />
              <span>Logs</span>
            </NavLink>
          </li>
          <li>
            <NavLink to="/settings" className={({ isActive }) => isActive ? 'active' : ''}>
              <FaCog />
              <span>Settings</span>
            </NavLink>
          </li>
        </ul>
      </nav>
      
      <div className="sidebar-footer">
        <p>Security Monitor v1.0.0</p>
      </div>
      
      <div className="sidebar-toggle" onClick={toggleSidebar}>
        {collapsed ? <FaChevronRight size={12} /> : <FaChevronLeft size={12} />}
      </div>
    </aside>
  );
};

export default Sidebar;