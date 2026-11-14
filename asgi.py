"""Render/Uvicorn entrypoint: serve the complete authenticated app at root."""
from server import create_http_app

# Importing server first registers all twelve tools and public routes.
# The returned Starlette application also owns the MCP session-manager lifespan.
app = create_http_app()
