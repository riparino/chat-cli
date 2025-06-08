#!/usr/bin/env python3
"""
Startup script for Azure Security MCP HTTP Server
"""

import os
import sys
from pathlib import Path
from dotenv import load_dotenv

def main():
    """Start the MCP HTTP server"""
    # Load environment variables
    env_file = Path(__file__).parent / ".env"
    if env_file.exists():
        load_dotenv(env_file)
        print("✅ Loaded environment variables from .env")
    else:
        print("⚠️  No .env file found - using environment variables")
    
    # Check required environment variables
    required_vars = [
        "AZURE_TENANT_ID",
        "LOG_ANALYTICS_WORKSPACE_ID"
    ]
    
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    if missing_vars:
        print(f"❌ Missing required environment variables: {', '.join(missing_vars)}")
        print("Please check your .env file or environment configuration")
        sys.exit(1)
      # Import and start the server
    try:
        # Add the mcp-server directory to Python path
        mcp_server_path = Path(__file__).parent / "mcp-server"
        sys.path.insert(0, str(mcp_server_path))
        
        from http_server import AzureSecurityHTTPServer
        
        server = AzureSecurityHTTPServer()
        
        # Get configuration
        host = os.getenv("MCP_HOST", "localhost")
        port = int(os.getenv("MCP_PORT", "8000"))
        
        print(f"🚀 Starting Azure Security MCP Server on {host}:{port}")
        server.run(host=host, port=port)
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("Make sure you've installed the requirements: pip install -r mcp-server/requirements.txt")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Failed to start server: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
