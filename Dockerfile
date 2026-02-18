FROM python:3.12-slim

WORKDIR /app

# Install uv for fast dependency management
RUN pip install --no-cache-dir uv

# Copy project files
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/

# Install the package
RUN uv pip install --system .

# The firewall uses stdio transport — stdin/stdout
ENTRYPOINT ["mcp-action-firewall"]
