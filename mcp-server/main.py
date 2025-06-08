#!/usr/bin/env python3
"""
Azure Security MCP Server
Provides tools for Azure Sentinel, Entra ID, and Microsoft Graph integration
"""

import asyncio
import os
import json
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Sequence
from urllib.parse import quote
import hashlib
import secrets
import base64

from mcp.server.models import InitializationOptions
from mcp.server import NotificationOptions, Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    Resource,
    Tool,
    TextContent,
    ImageContent,
    EmbeddedResource,
    LoggingLevel
)
import mcp.types as types

from azure.identity import DefaultAzureCredential, ClientSecretCredential, ManagedIdentityCredential
from azure.monitor.query import LogsQueryClient
from azure.core.exceptions import AzureError
import aiohttp

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AzureSecurityMCPServer:
    """MCP Server for Azure Security Tools with Authentication"""
    
    def __init__(self):
        self.server = Server("azure-security-mcp")
        self.credential = None
        self.logs_client = None
        self.graph_session = None
        self.workspace_id = os.getenv("LOG_ANALYTICS_WORKSPACE_ID")
        self.tenant_id = os.getenv("AZURE_TENANT_ID")
        
        # MCP Server Authentication
        self.api_key = os.getenv("MCP_API_KEY")
        self.auth_required = os.getenv("MCP_AUTH_REQUIRED", "false").lower() == "true"
        
        # Initialize credentials based on environment
        self._initialize_credentials()
        
        # Register tools and handlers
        self._register_tools()
        self._register_handlers()
    
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
    
    def _authenticate_request(self, headers: Dict[str, str]) -> bool:
        """Authenticate incoming MCP requests"""
        if not self.auth_required:
            return True
            
        if not self.api_key:
            logger.error("MCP_API_KEY not configured but authentication required")
            return False
            
        auth_header = headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return False
            
        provided_key = auth_header[7:]  # Remove "Bearer " prefix
        return secrets.compare_digest(provided_key, self.api_key)
        
        # Register tools
        self._register_tools()
        
        # Register resources
        self._register_resources()
    
    def _initialize_credentials(self):
        """Initialize Azure credentials with fallback options"""
        try:
            # Try managed identity first (for Azure-hosted scenarios)
            if os.getenv("AZURE_CLIENT_ID"):
                self.credential = DefaultAzureCredential()
                logger.info("Using Managed Identity authentication")
            elif all([
                os.getenv("AZURE_CLIENT_ID"),
                os.getenv("AZURE_CLIENT_SECRET"), 
                os.getenv("AZURE_TENANT_ID")
            ]):
                # Service principal for CI/CD or development
                self.credential = ClientSecretCredential(
                    tenant_id=os.getenv("AZURE_TENANT_ID"),
                    client_id=os.getenv("AZURE_CLIENT_ID"),
                    client_secret=os.getenv("AZURE_CLIENT_SECRET")
                )
                logger.info("Using Service Principal authentication")
            else:
                # Default credential for local development
                self.credential = DefaultAzureCredential()
                logger.info("Using Default Azure Credential")
                
            # Initialize Log Analytics client
            if self.workspace_id:
                self.logs_client = LogsQueryClient(self.credential)
                logger.info(f"Connected to Log Analytics workspace: {self.workspace_id}")
            else:
                logger.warning("LOG_ANALYTICS_WORKSPACE_ID not set - Log Analytics queries disabled")
                
        except Exception as e:
            logger.error(f"Failed to initialize Azure credentials: {e}")
            raise
    
    def _register_tools(self):
        """Register MCP tools for Azure security operations"""
        
        @self.server.call_tool()
        async def search_sentinel_incidents(arguments: dict) -> Sequence[types.TextContent]:
            """Search for security incidents in Azure Sentinel"""
            try:
                # Extract parameters
                time_range = arguments.get("time_range", "24h")
                severity = arguments.get("severity", "")
                status = arguments.get("status", "")
                limit = min(int(arguments.get("limit", 50)), 100)  # Cap at 100
                
                # Build KQL query
                query = f"""
                SecurityIncident
                | where TimeGenerated >= ago({time_range})
                """
                
                if severity:
                    query += f"\n| where Severity == '{severity}'"
                if status:
                    query += f"\n| where Status == '{status}'"
                    
                query += f"""
                | project TimeGenerated, IncidentNumber, Title, Severity, Status, 
                          Owner, Classification, Labels, Description
                | order by TimeGenerated desc
                | limit {limit}
                """
                
                result = await self._execute_kql_query(query)
                return [types.TextContent(
                    type="text",
                    text=f"Found {len(result)} incidents:\n\n" + 
                         self._format_incidents_table(result)
                )]
                
            except Exception as e:
                logger.error(f"Error searching incidents: {e}")
                return [types.TextContent(
                    type="text", 
                    text=f"Error searching incidents: {str(e)}"
                )]
        
        @self.server.call_tool()
        async def get_incident_details(arguments: dict) -> Sequence[types.TextContent]:
            """Get detailed information about a specific incident"""
            try:
                incident_id = arguments.get("incident_id")
                if not incident_id:
                    return [types.TextContent(
                        type="text",
                        text="Error: incident_id parameter is required"
                    )]
                
                # Query for incident details
                query = f"""
                SecurityIncident
                | where IncidentNumber == '{incident_id}'
                | project TimeGenerated, IncidentNumber, Title, Severity, Status,
                          Owner, Classification, Labels, Description, Tactics, Techniques,
                          AdditionalData, Entities
                | limit 1
                """
                
                result = await self._execute_kql_query(query)
                if not result:
                    return [types.TextContent(
                        type="text",
                        text=f"No incident found with ID: {incident_id}"
                    )]
                
                incident = result[0]
                details = self._format_incident_details(incident)
                
                return [types.TextContent(type="text", text=details)]
                
            except Exception as e:
                logger.error(f"Error getting incident details: {e}")
                return [types.TextContent(
                    type="text",
                    text=f"Error getting incident details: {str(e)}"
                )]
        
        @self.server.call_tool()
        async def execute_kql_query(arguments: dict) -> Sequence[types.TextContent]:
            """Execute a custom KQL query against Log Analytics"""
            try:
                query = arguments.get("query")
                limit = min(int(arguments.get("limit", 100)), 1000)  # Cap at 1000
                
                if not query:
                    return [types.TextContent(
                        type="text",
                        text="Error: query parameter is required"
                    )]
                
                # Add limit if not present
                if "limit" not in query.lower():
                    query += f"\n| limit {limit}"
                
                result = await self._execute_kql_query(query)
                
                if not result:
                    return [types.TextContent(
                        type="text",
                        text="Query executed successfully but returned no results"
                    )]
                
                # Format results as table
                formatted_result = self._format_query_results(result)
                
                return [types.TextContent(
                    type="text",
                    text=f"Query returned {len(result)} rows:\n\n{formatted_result}"
                )]
                
            except Exception as e:
                logger.error(f"Error executing KQL query: {e}")
                return [types.TextContent(
                    type="text",
                    text=f"Error executing query: {str(e)}"
                )]
        
        @self.server.call_tool()
        async def search_entra_users(arguments: dict) -> Sequence[types.TextContent]:
            """Search for users in Entra ID (Azure AD)"""
            try:
                search_term = arguments.get("search_term", "")
                limit = min(int(arguments.get("limit", 20)), 50)  # Cap at 50
                
                # Use Microsoft Graph API
                filter_query = ""
                if search_term:
                    filter_query = f"?$filter=startswith(displayName,'{search_term}') or startswith(userPrincipalName,'{search_term}')&"
                else:
                    filter_query = "?"
                
                url = f"https://graph.microsoft.com/v1.0/users{filter_query}$top={limit}&$select=id,displayName,userPrincipalName,mail,accountEnabled,signInActivity"
                
                result = await self._call_graph_api(url)
                users = result.get("value", [])
                
                formatted_users = self._format_users_table(users)
                
                return [types.TextContent(
                    type="text",
                    text=f"Found {len(users)} users:\n\n{formatted_users}"
                )]
                
            except Exception as e:
                logger.error(f"Error searching Entra users: {e}")
                return [types.TextContent(
                    type="text",
                    text=f"Error searching users: {str(e)}"
                )]
        
        @self.server.call_tool()
        async def get_user_signin_logs(arguments: dict) -> Sequence[types.TextContent]:
            """Get sign-in logs for a specific user"""
            try:
                user_principal_name = arguments.get("user_principal_name")
                days = min(int(arguments.get("days", 7)), 30)  # Cap at 30 days
                limit = min(int(arguments.get("limit", 50)), 100)  # Cap at 100
                
                if not user_principal_name:
                    return [types.TextContent(
                        type="text",
                        text="Error: user_principal_name parameter is required"
                    )]
                
                # KQL query for sign-in logs
                query = f"""
                SigninLogs
                | where TimeGenerated >= ago({days}d)
                | where UserPrincipalName == '{user_principal_name}'
                | project TimeGenerated, UserPrincipalName, AppDisplayName, 
                          IPAddress, Location, DeviceDetail, RiskDetail, Status
                | order by TimeGenerated desc
                | limit {limit}
                """
                
                result = await self._execute_kql_query(query)
                
                if not result:
                    return [types.TextContent(
                        type="text",
                        text=f"No sign-in logs found for user: {user_principal_name}"
                    )]
                
                formatted_logs = self._format_signin_logs(result)
                
                return [types.TextContent(
                    type="text",
                    text=f"Found {len(result)} sign-in events for {user_principal_name}:\n\n{formatted_logs}"
                )]
                
            except Exception as e:
                logger.error(f"Error getting sign-in logs: {e}")
                return [types.TextContent(
                    type="text",
                    text=f"Error getting sign-in logs: {str(e)}"
                )]
        
        @self.server.call_tool()
        async def analyze_risk_detections(arguments: dict) -> Sequence[types.TextContent]:
            """Analyze risk detections from Entra ID Protection"""
            try:
                time_range = arguments.get("time_range", "7d")
                risk_level = arguments.get("risk_level", "")
                limit = min(int(arguments.get("limit", 50)), 100)
                
                query = f"""
                AADRiskyUsers
                | where TimeGenerated >= ago({time_range})
                """
                
                if risk_level:
                    query += f"\n| where RiskLevel == '{risk_level}'"
                
                query += f"""
                | project TimeGenerated, UserPrincipalName, RiskLevel, RiskDetail,
                          RiskState, RiskLastUpdatedDateTime
                | order by TimeGenerated desc
                | limit {limit}
                """
                
                result = await self._execute_kql_query(query)
                
                if not result:
                    return [types.TextContent(
                        type="text",
                        text="No risk detections found for the specified criteria"
                    )]
                
                formatted_risks = self._format_risk_detections(result)
                
                return [types.TextContent(
                    type="text",
                    text=f"Found {len(result)} risk detections:\n\n{formatted_risks}"
                )]
                
            except Exception as e:
                logger.error(f"Error analyzing risk detections: {e}")
                return [types.TextContent(
                    type="text",
                    text=f"Error analyzing risk detections: {str(e)}"
                )]
    
    def _register_resources(self):
        """Register MCP resources"""
        
        @self.server.list_resources()
        async def handle_list_resources() -> list[Resource]:
            """List available security resources"""
            return [
                Resource(
                    uri="sentinel://incidents",
                    name="Security Incidents",
                    description="Azure Sentinel security incidents",
                    mimeType="application/json"
                ),
                Resource(
                    uri="entra://users", 
                    name="Entra ID Users",
                    description="Azure Entra ID user directory",
                    mimeType="application/json"
                ),
                Resource(
                    uri="logs://analytics",
                    name="Log Analytics",
                    description="Azure Log Analytics workspace data",
                    mimeType="application/json"
                )
            ]
        
        @self.server.read_resource()
        async def handle_read_resource(uri: str) -> str:
            """Read security resource data"""
            if uri == "sentinel://incidents":
                # Return recent incidents summary
                query = """
                SecurityIncident
                | where TimeGenerated >= ago(24h)
                | summarize Count=count() by Severity
                | order by Severity asc
                """
                result = await self._execute_kql_query(query)
                return json.dumps(result, indent=2)
            
            elif uri == "entra://users":
                # Return user statistics
                try:
                    url = "https://graph.microsoft.com/v1.0/users/$count"
                    headers = {"ConsistencyLevel": "eventual"}
                    result = await self._call_graph_api(url, headers=headers)
                    return json.dumps({"total_users": result}, indent=2)
                except:
                    return json.dumps({"error": "Unable to fetch user count"}, indent=2)
            
            else:
                return json.dumps({"error": "Resource not found"}, indent=2)
    
    async def _execute_kql_query(self, query: str) -> List[Dict[str, Any]]:
        """Execute KQL query against Log Analytics"""
        if not self.logs_client or not self.workspace_id:
            raise Exception("Log Analytics client not configured")
        
        try:
            # Execute query with retry logic
            for attempt in range(3):
                try:
                    response = self.logs_client.query_workspace(
                        workspace_id=self.workspace_id,
                        query=query,
                        timespan=timedelta(days=30)
                    )
                    
                    # Convert to list of dictionaries
                    results = []
                    if response.tables:
                        table = response.tables[0]
                        for row in table.rows:
                            row_dict = {}
                            for i, column in enumerate(table.columns):
                                row_dict[column.name] = row[i]
                            results.append(row_dict)
                    
                    return results
                    
                except Exception as e:
                    if attempt == 2:  # Last attempt
                        raise
                    logger.warning(f"Query attempt {attempt + 1} failed, retrying: {e}")
                    await asyncio.sleep(2 ** attempt)  # Exponential backoff
                    
        except Exception as e:
            logger.error(f"KQL query failed: {e}")
            raise
    
    async def _call_graph_api(self, url: str, headers: Dict[str, str] = None) -> Dict[str, Any]:
        """Call Microsoft Graph API with authentication"""
        try:
            # Get access token
            token = self.credential.get_token("https://graph.microsoft.com/.default")
            
            # Prepare headers
            request_headers = {
                "Authorization": f"Bearer {token.token}",
                "Content-Type": "application/json"
            }
            if headers:
                request_headers.update(headers)
            
            # Make API call with retry logic
            async with aiohttp.ClientSession() as session:
                for attempt in range(3):
                    try:
                        async with session.get(url, headers=request_headers) as response:
                            if response.status == 200:
                                return await response.json()
                            else:
                                error_text = await response.text()
                                raise Exception(f"Graph API error {response.status}: {error_text}")
                    except Exception as e:
                        if attempt == 2:  # Last attempt
                            raise
                        logger.warning(f"Graph API attempt {attempt + 1} failed, retrying: {e}")
                        await asyncio.sleep(2 ** attempt)  # Exponential backoff
                        
        except Exception as e:
            logger.error(f"Graph API call failed: {e}")
            raise
    
    def _format_incidents_table(self, incidents: List[Dict]) -> str:
        """Format incidents as a readable table"""
        if not incidents:
            return "No incidents found"
        
        table = "| Incident # | Title | Severity | Status | Owner | Time |\n"
        table += "|------------|-------|----------|--------|-------|------|\n"
        
        for incident in incidents:
            incident_num = incident.get("IncidentNumber", "N/A")
            title = (incident.get("Title", "")[:30] + "...") if len(incident.get("Title", "")) > 30 else incident.get("Title", "")
            severity = incident.get("Severity", "N/A")
            status = incident.get("Status", "N/A")
            owner = incident.get("Owner", "Unassigned")
            time_gen = incident.get("TimeGenerated", "")
            
            if isinstance(time_gen, datetime):
                time_str = time_gen.strftime("%m/%d %H:%M")
            else:
                time_str = str(time_gen)[:16] if time_gen else "N/A"
            
            table += f"| {incident_num} | {title} | {severity} | {status} | {owner} | {time_str} |\n"
        
        return table
    
    def _format_incident_details(self, incident: Dict) -> str:
        """Format detailed incident information"""
        details = f"""
## Incident Details: {incident.get('IncidentNumber', 'N/A')}

**Title:** {incident.get('Title', 'N/A')}
**Severity:** {incident.get('Severity', 'N/A')}
**Status:** {incident.get('Status', 'N/A')}
**Owner:** {incident.get('Owner', 'Unassigned')}
**Classification:** {incident.get('Classification', 'N/A')}
**Time Generated:** {incident.get('TimeGenerated', 'N/A')}

**Description:**
{incident.get('Description', 'No description available')}

**Tactics:** {incident.get('Tactics', 'N/A')}
**Techniques:** {incident.get('Techniques', 'N/A')}
**Labels:** {incident.get('Labels', 'N/A')}

**Entities:** {incident.get('Entities', 'No entities listed')}
"""
        return details
    
    def _format_query_results(self, results: List[Dict]) -> str:
        """Format query results as a table"""
        if not results:
            return "No results"
        
        # Get column names from first row
        columns = list(results[0].keys())
        
        # Create header
        header = "| " + " | ".join(columns) + " |\n"
        separator = "|" + "|".join(["---"] * len(columns)) + "|\n"
        
        # Create rows
        rows = ""
        for row in results[:20]:  # Limit to first 20 rows for readability
            row_values = []
            for col in columns:
                value = str(row.get(col, ""))
                # Truncate long values
                if len(value) > 30:
                    value = value[:27] + "..."
                row_values.append(value)
            rows += "| " + " | ".join(row_values) + " |\n"
        
        if len(results) > 20:
            rows += f"\n... ({len(results) - 20} more rows)\n"
        
        return header + separator + rows
    
    def _format_users_table(self, users: List[Dict]) -> str:
        """Format users as a readable table"""
        if not users:
            return "No users found"
        
        table = "| Display Name | UPN | Email | Enabled | Last Sign-in |\n"
        table += "|--------------|-----|-------|---------|-------------|\n"
        
        for user in users:
            display_name = user.get("displayName", "N/A")[:20]
            upn = user.get("userPrincipalName", "N/A")[:25]
            email = user.get("mail", "N/A")[:25] if user.get("mail") else "N/A"
            enabled = "Yes" if user.get("accountEnabled") else "No"
            
            # Handle sign-in activity
            signin_activity = user.get("signInActivity", {})
            last_signin = "N/A"
            if signin_activity and signin_activity.get("lastSignInDateTime"):
                last_signin = signin_activity["lastSignInDateTime"][:10]  # Date only
            
            table += f"| {display_name} | {upn} | {email} | {enabled} | {last_signin} |\n"
        
        return table
    
    def _format_signin_logs(self, logs: List[Dict]) -> str:
        """Format sign-in logs as a readable table"""
        if not logs:
            return "No sign-in logs found"
        
        table = "| Time | App | IP Address | Location | Status |\n"
        table += "|------|-----|------------|----------|--------|\n"
        
        for log in logs[:20]:  # Limit to 20 for readability
            time_gen = log.get("TimeGenerated", "")
            if isinstance(time_gen, datetime):
                time_str = time_gen.strftime("%m/%d %H:%M")
            else:
                time_str = str(time_gen)[:16] if time_gen else "N/A"
            
            app = log.get("AppDisplayName", "N/A")[:20]
            ip = log.get("IPAddress", "N/A")
            location = log.get("Location", "N/A")[:15]
            status = "Success" if log.get("Status", {}).get("errorCode") == 0 else "Failed"
            
            table += f"| {time_str} | {app} | {ip} | {location} | {status} |\n"
        
        return table
    
    def _format_risk_detections(self, risks: List[Dict]) -> str:
        """Format risk detections as a readable table"""
        if not risks:
            return "No risk detections found"
        
        table = "| User | Risk Level | Risk Detail | State | Last Updated |\n"
        table += "|------|------------|-------------|-------|-------------|\n"
        
        for risk in risks:
            user = risk.get("UserPrincipalName", "N/A")[:25]
            level = risk.get("RiskLevel", "N/A")
            detail = risk.get("RiskDetail", "N/A")[:20]
            state = risk.get("RiskState", "N/A")
            updated = risk.get("RiskLastUpdatedDateTime", "N/A")
            
            if isinstance(updated, datetime):
                updated = updated.strftime("%m/%d %H:%M")
            else:
                updated = str(updated)[:16] if updated != "N/A" else "N/A"
            
            table += f"| {user} | {level} | {detail} | {state} | {updated} |\n"
        
        return table
    
    async def run(self):
        """Run the MCP server"""
        # Define tool schemas
        tools = [
            Tool(
                name="search_sentinel_incidents",
                description="Search for security incidents in Azure Sentinel",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "time_range": {
                            "type": "string",
                            "description": "Time range for search (e.g., '24h', '7d', '30d')",
                            "default": "24h"
                        },
                        "severity": {
                            "type": "string",
                            "description": "Filter by severity (High, Medium, Low, Informational)",
                            "default": ""
                        },
                        "status": {
                            "type": "string", 
                            "description": "Filter by status (New, Active, Closed)",
                            "default": ""
                        },
                        "limit": {
                            "type": "number",
                            "description": "Maximum number of incidents to return",
                            "default": 50
                        }
                    }
                }
            ),
            Tool(
                name="get_incident_details",
                description="Get detailed information about a specific security incident",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "incident_id": {
                            "type": "string",
                            "description": "The incident number/ID to retrieve details for",
                            "required": True
                        }
                    },
                    "required": ["incident_id"]
                }
            ),
            Tool(
                name="execute_kql_query",
                description="Execute a custom KQL query against Log Analytics workspace",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "The KQL query to execute",
                            "required": True
                        },
                        "limit": {
                            "type": "number",
                            "description": "Maximum number of results to return",
                            "default": 100
                        }
                    },
                    "required": ["query"]
                }
            ),
            Tool(
                name="search_entra_users",
                description="Search for users in Entra ID (Azure AD)",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "search_term": {
                            "type": "string",
                            "description": "Search term for user display name or UPN",
                            "default": ""
                        },
                        "limit": {
                            "type": "number",
                            "description": "Maximum number of users to return",
                            "default": 20
                        }
                    }
                }
            ),
            Tool(
                name="get_user_signin_logs",
                description="Get sign-in logs for a specific user",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "user_principal_name": {
                            "type": "string",
                            "description": "The user principal name (UPN) to get logs for",
                            "required": True
                        },
                        "days": {
                            "type": "number",
                            "description": "Number of days to look back (max 30)",
                            "default": 7
                        },
                        "limit": {
                            "type": "number", 
                            "description": "Maximum number of log entries to return",
                            "default": 50
                        }
                    },
                    "required": ["user_principal_name"]
                }
            ),
            Tool(
                name="analyze_risk_detections",
                description="Analyze risk detections from Entra ID Protection",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "time_range": {
                            "type": "string",
                            "description": "Time range for analysis (e.g., '7d', '30d')",
                            "default": "7d"
                        },
                        "risk_level": {
                            "type": "string",
                            "description": "Filter by risk level (Low, Medium, High)",
                            "default": ""
                        },
                        "limit": {
                            "type": "number",
                            "description": "Maximum number of detections to return",
                            "default": 50
                        }
                    }
                }
            )
        ]
        
        # Set server capabilities
        self.server.update_initialization_options(
            InitializationOptions(
                server_name="Azure Security MCP Server",
                server_version="1.0.0",
                capabilities={
                    "tools": tools,
                    "resources": True,
                    "logging": {}
                }
            )
        )
          # Run the server
        async with stdio_server() as (read_stream, write_stream):
            await self.server.run(
                read_stream, 
                write_stream, 
                InitializationOptions(
                    server_name="Azure Security MCP Server",
                    server_version="1.0.0",
                    capabilities=self.server.get_capabilities()
                )
            )

async def main():
    """Main entry point"""
    try:
        server = AzureSecurityMCPServer()
        await server.run()
    except KeyboardInterrupt:
        logger.info("Server shutdown requested")
    except Exception as e:
        logger.error(f"Server error: {e}")
        raise

if __name__ == "__main__":
    asyncio.run(main())
