// agentService.js
import axios from 'axios';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000/api';

export const agentService = {
  // Get list of all agents
  getAgents: async () => {
    const response = await axios.get(`${API_URL}/agents`);
    return response.data;
  },

  // Get details for a specific agent
  getAgentDetails: async (agentId) => {
    const response = await axios.get(`${API_URL}/agents/${agentId}`);
    return response.data;
  },

  // Get alerts for a specific agent
  getAgentAlerts: async (agentId, filters = {}) => {
    const response = await axios.get(`${API_URL}/agents/${agentId}/alerts`, { params: filters });
    return response.data;
  },

  // Get logs for a specific agent
  getAgentLogs: async (agentId, filters = {}) => {
    const response = await axios.get(`${API_URL}/agents/${agentId}/logs`, { params: filters });
    return response.data;
  },

  // Get stats for a specific agent
  getAgentStats: async (agentId) => {
    const response = await axios.get(`${API_URL}/agents/${agentId}/stats`);
    return response.data;
  },

  // Start monitoring for a specific agent
  startAgentMonitoring: async (agentId, config = {}) => {
    const response = await axios.post(`${API_URL}/agents/${agentId}/start`, config);
    return response.data;
  },

  // Stop monitoring for a specific agent
  stopAgentMonitoring: async (agentId) => {
    const response = await axios.post(`${API_URL}/agents/${agentId}/stop`);
    return response.data;
  }
};