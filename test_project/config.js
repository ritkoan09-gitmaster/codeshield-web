// Enhanced Test File for CodeShield v2.5 Pro Demo

const dbConfig = {
    host: "localhost",
    user: "admin",
    password: "SuperSecretPassword123", // HIGH: Hardcoded Password
    apiKey: "AKIAIOSFODNN7EXAMPLE",       // CRITICAL: AWS Access Key
    githubToken: "ghp_1234567890abcdefghijklmnopqrstuvwxyzAB" // CRITICAL: GitHub Token
};

// CRITICAL: SQL Injection Risk
const query = "SELECT * FROM users WHERE username = '" + req.body.user + "'";

// HIGH: Insecure HTTP Endpoints
const apiEndpoint = "http://api.unsecure-server.com/v1/data";

// LOW: Technical Debt Marker
// TODO: Refactor database connection pool before production build!
console.log("Database initialized.");