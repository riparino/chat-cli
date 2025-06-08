#!/usr/bin/env python3
"""
Azure Security MCP HTTP Server
Production-ready HTTP server for Azure security tools
"""

import asyncio
import os
import json
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
import secrets
import hashlib
import base64

from fastapi import FastAPI, HTTPException, Depends, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

from azure.identity import DefaultAzureCredential, ClientSecretCredential, ManagedIdentityCredential
from azure.monitor.query import LogsQueryClient
from azure.core.exceptions import AzureError
import aiohttp

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Pydantic models for API
class ToolCallRequest(BaseModel):
    name: str
    arguments: Dict[str, Any]

class ToolResponse(BaseModel):
    success: bool
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

class HealthResponse(BaseModel):
    status: str
    version: str
    tools_available: int

class ToolInfo(BaseModel):
    name: str
    description: str
    inputSchema: Dict[str, Any]

class ToolsResponse(BaseModel):
    tools: List[ToolInfo]

class AzureSecurityHTTPServer:
    """HTTP Server for Azure Security Tools"""
    
    def __init__(self):
        self.app = FastAPI(title="Azure Security MCP Server", version="1.0.0")
        self.credential = None
        self.logs_client = None
        self.graph_session = None
        self.workspace_id = os.getenv("LOG_ANALYTICS_WORKSPACE_ID")
        self.tenant_id = os.getenv("AZURE_TENANT_ID")
        
        # Authentication
        self.api_key = os.getenv("MCP_API_KEY")
        self.auth_required = os.getenv("MCP_AUTH_REQUIRED", "false").lower() == "true"
        self.security = HTTPBearer() if self.auth_required else None
        
        # Initialize Azure credentials
        self._initialize_credentials()
        
        # Configure CORS
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],  # Configure appropriately for production
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
        
        # Register routes
        self._register_routes()
        
        # Define available tools
        self.tools = [
            {
                "name": "search_incidents",
                "description": "Search for security incidents in Azure Sentinel",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Search query for incidents"},
                        "limit": {"type": "integer", "description": "Maximum number of results", "default": 10}
                    },
                    "required": ["query"]
                }
            },
            {
                "name": "get_incident_details",
                "description": "Get detailed information about a specific incident",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "incident_id": {"type": "string", "description": "The incident ID to retrieve"}
                    },
                    "required": ["incident_id"]
                }
            },
            {
                "name": "execute_kql_query",
                "description": "Execute a KQL query against Log Analytics workspace",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "KQL query to execute"},
                        "timespan": {"type": "string", "description": "Time range for the query (e.g., 'PT24H')", "default": "PT24H"}
                    },
                    "required": ["query"]
                }
            },
            {
                "name": "search_entra_users",
                "description": "Search for users in Entra ID",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "search_term": {"type": "string", "description": "Search term for users"},
                        "limit": {"type": "integer", "description": "Maximum number of results", "default": 10}
                    },
                    "required": ["search_term"]
                }
            },
            {
                "name": "get_signin_logs",
                "description": "Retrieve sign-in logs from Entra ID",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "user_id": {"type": "string", "description": "User ID to filter logs"},
                        "hours": {"type": "integer", "description": "Number of hours to look back", "default": 24}
                    }
                }
            },
            {
                "name": "analyze_risk_detections",
                "description": "Analyze risk detections from Entra ID",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "user_id": {"type": "string", "description": "User ID to analyze"},
                        "risk_level": {"type": "string", "description": "Risk level filter (low, medium, high)"}
                    }
                }
            }
        ]
    
    def _initialize_credentials(self) -> None:
        """Initialize Azure credentials with fallback strategy"""
        try:
            # Priority: Managed Identity (Azure) -> Service Principal -> Default
            if os.getenv("AZURE_CLIENT_ID") and os.getenv("AZURE_CLIENT_SECRET"):
                # Service Principal authentication for CI/CD
                self.credential = ClientSecretCredential(
                    tenant_id=self.tenant_id,
                    client_id=os.getenv("AZURE_CLIENT_ID"),
                    client_secret=os.getenv("AZURE_CLIENT_SECRET")
                )
                logger.info("Using Service Principal authentication")
            else:
                # Managed Identity for Azure-hosted environments
                try:
                    self.credential = ManagedIdentityCredential()
                    # Test the credential
                    token = self.credential.get_token("https://management.azure.com/.default")
                    logger.info("Using Managed Identity authentication")
                except Exception:
                    # Fallback to DefaultAzureCredential for development
                    self.credential = DefaultAzureCredential()
                    logger.info("Using DefaultAzureCredential authentication")
            
            # Initialize Log Analytics client
            if self.workspace_id:
                self.logs_client = LogsQueryClient(self.credential)
                logger.info("Log Analytics client initialized")
            else:
                logger.warning("LOG_ANALYTICS_WORKSPACE_ID not set")
                
        except Exception as e:
            logger.error(f"Failed to initialize Azure credentials: {e}")
            raise
    
    async def _authenticate_request(self, credentials: HTTPAuthorizationCredentials = Security(HTTPBearer())) -> bool:
        """Authenticate incoming requests"""
        if not self.auth_required:
            return True
            
        if not self.api_key:
            logger.error("MCP_API_KEY not configured but authentication required")
            raise HTTPException(status_code=500, detail="Server authentication not configured")
            
        if not credentials:
            raise HTTPException(status_code=401, detail="Authentication required")
            
        provided_key = credentials.credentials
        if not secrets.compare_digest(provided_key, self.api_key):
            raise HTTPException(status_code=401, detail="Invalid API key")
            
        return True
    
    def _register_routes(self) -> None:
        """Register HTTP routes"""
        
        @self.app.get("/health", response_model=HealthResponse)
        async def health():
            """Health check endpoint"""
            return HealthResponse(
                status="healthy",
                version="1.0.0",
                tools_available=len(self.tools)
            )
        
        @self.app.get("/tools", response_model=ToolsResponse)
        async def get_tools(authenticated: bool = Depends(self._authenticate_request)):
            """Get available tools"""
            return ToolsResponse(tools=[ToolInfo(**tool) for tool in self.tools])
        
        @self.app.post("/call-tool", response_model=ToolResponse)
        async def call_tool(
            request: ToolCallRequest,
            authenticated: bool = Depends(self._authenticate_request)
        ):
            """Execute a tool call"""
            try:
                result = await self._execute_tool(request.name, request.arguments)
                return ToolResponse(success=True, data=result)
            except Exception as e:
                logger.error(f"Tool execution failed: {e}")
                return ToolResponse(success=False, error=str(e))
    
    async def _execute_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a specific tool"""
        if tool_name == "search_incidents":
            return await self._search_incidents(**arguments)
        elif tool_name == "get_incident_details":
            return await self._get_incident_details(**arguments)
        elif tool_name == "execute_kql_query":
            return await self._execute_kql_query(**arguments)
        elif tool_name == "search_entra_users":
            return await self._search_entra_users(**arguments)
        elif tool_name == "get_signin_logs":
            return await self._get_signin_logs(**arguments)
        elif tool_name == "analyze_risk_detections":
            return await self._analyze_risk_detections(**arguments)
        else:
            raise ValueError(f"Unknown tool: {tool_name}")
    
    async def _search_incidents(self, query: str, limit: int = 10) -> Dict[str, Any]:
        """Search for security incidents"""
        try:
            # Mock implementation - replace with actual Sentinel API calls
            incidents = [
                {
                    "id": f"INC-{i:05d}",
                    "title": f"Security Incident {i}",
                    "severity": "Medium",
                    "status": "Active",
                    "created_time": datetime.now().isoformat()
                }
                for i in range(1, min(limit + 1, 6))
            ]
            
            return {
                "incidents": incidents,
                "total_count": len(incidents),
                "query": query
            }
        except Exception as e:
            logger.error(f"Error searching incidents: {e}")
            raise
    
    async def _get_incident_details(self, incident_id: str) -> Dict[str, Any]:
        """Get detailed incident information"""
        try:
            # Mock implementation - replace with actual Sentinel API calls
            return {
                "id": incident_id,
                "title": f"Detailed view of {incident_id}",
                "severity": "High",
                "status": "Investigating",
                "description": "Suspicious activity detected",
                "entities": [
                    {"type": "Account", "name": "user@example.com"},
                    {"type": "Host", "name": "WORKSTATION-01"},
                    {"type": "IP", "name": "192.168.1.100"}
                ],
                "created_time": datetime.now().isoformat(),
                "last_updated": datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"Error getting incident details: {e}")
            raise
    
    async def _execute_kql_query(self, query: str, timespan: str = "PT24H") -> Dict[str, Any]:
        """Execute KQL query against Log Analytics"""
        try:
            if not self.logs_client or not self.workspace_id:
                raise ValueError("Log Analytics not configured")
            
            # Mock implementation - replace with actual KQL execution
            return {
                "query": query,
                "timespan": timespan,
                "results": [
                    {"TimeGenerated": datetime.now().isoformat(), "EventID": 4624, "Account": "user@example.com"},
                    {"TimeGenerated": datetime.now().isoformat(), "EventID": 4625, "Account": "admin@example.com"}
                ],
                "row_count": 2
            }
        except Exception as e:
            logger.error(f"Error executing KQL query: {e}")
            raise
    
    async def _search_entra_users(self, search_term: str, limit: int = 10) -> Dict[str, Any]:
        """Search Entra ID users"""
        try:
            # Mock implementation - replace with actual Graph API calls
            users = [
                {
                    "id": f"user-{i}",
                    "displayName": f"User {i}",
                    "userPrincipalName": f"user{i}@example.com",
                    "accountEnabled": True
                }
                for i in range(1, min(limit + 1, 6))
            ]
            
            return {
                "users": users,
                "total_count": len(users),
                "search_term": search_term
            }
        except Exception as e:
            logger.error(f"Error searching Entra users: {e}")
            raise
    
    async def _get_signin_logs(self, user_id: str = None, hours: int = 24) -> Dict[str, Any]:
        """Get sign-in logs"""
        try:
            # Mock implementation - replace with actual Graph API calls
            logs = [
                {
                    "id": f"signin-{i}",
                    "createdDateTime": datetime.now().isoformat(),
                    "userPrincipalName": f"user{i}@example.com",
                    "appDisplayName": "Office 365",
                    "status": {"errorCode": 0, "additionalDetails": "Success"},
                    "location": {"city": "Seattle", "countryOrRegion": "US"}
                }
                for i in range(1, 6)
            ]
            
            return {
                "signInLogs": logs,
                "total_count": len(logs),
                "timeRange": f"Last {hours} hours"
            }
        except Exception as e:
            logger.error(f"Error getting signin logs: {e}")
            raise
    
    async def _analyze_risk_detections(self, user_id: str = None, risk_level: str = None) -> Dict[str, Any]:
        """Analyze risk detections"""
        try:
            # Mock implementation - replace with actual Graph API calls
            detections = [
                {
                    "id": f"risk-{i}",
                    "detectedDateTime": datetime.now().isoformat(),
                    "riskType": "unfamiliarFeatures",
                    "riskLevel": "medium",
                    "riskDetail": "aiConfirmedSigninSafe",
                    "userPrincipalName": f"user{i}@example.com"
                }
                for i in range(1, 4)
            ]
            
            return {
                "riskDetections": detections,
                "total_count": len(detections),
                "analyzed_user": user_id,
                "risk_level_filter": risk_level
            }
        except Exception as e:
            logger.error(f"Error analyzing risk detections: {e}")
            raise
    
    def run(self, host: str = "0.0.0.0", port: int = 8000):
        """Run the HTTP server"""
        logger.info(f"Starting Azure Security MCP HTTP Server on {host}:{port}")
        logger.info(f"Authentication required: {self.auth_required}")
        logger.info(f"Available tools: {len(self.tools)}")
        
        uvicorn.run(
            self.app,
            host=host,
            port=port,
            log_level="info"
        )

def main():
    """Entry point for the HTTP server"""
    server = AzureSecurityHTTPServer()
    
    # Get configuration from environment
    host = os.getenv("MCP_HOST", "0.0.0.0")
    port = int(os.getenv("MCP_PORT", "8000"))
    
    server.run(host=host, port=port)

if __name__ == "__main__":
    main()
