import axios from "axios";

const API = axios.create({
  baseURL: "http://localhost:5000/api",
});

export const getSummary = () =>
  API.get("/security-summary");

export const getReport = () =>
  API.get("/security-report");

export const getHighRisk = () =>
  API.get("/high-risk-incidents");