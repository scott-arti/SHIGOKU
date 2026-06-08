# Dockerfile for CAI Clone - Kali Linux based security testing environment
FROM kalilinux/kali-rolling

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Update and install security tools + dependencies for new tools
RUN apt-get update && apt-get install -y \
    # Core tools
    python3 \
    python3-pip \
    git \
    vim \
    # Security tools
    nmap \
    hydra \
    amass \
    nikto \
    sqlmap \
    gobuster \
    ffuf \
    chromium \
    # Network tools
    netcat-traditional \
    dnsutils \
    curl \
    wget \
    whatweb \
    libpcap-dev \
    # New dependencies: Go, Ruby, pipx
    golang-go \
    ruby \
    ruby-dev \
    pipx \
    nodejs \
    npm \
    # Clean up
    && rm -rf /var/lib/apt/lists/*

# Python3 is already available as default in Kali

# Setup pipx and Go paths
ENV GOPATH=/root/go
ENV PATH="${PATH}:/root/.local/bin:${GOPATH}/bin"
RUN pipx ensurepath

# Install Go-based tools
# Install Go-based tools (ProjectDiscovery & others)
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
RUN go install -v github.com/projectdiscovery/katana/cmd/katana@latest
RUN go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
RUN go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
RUN go install -v github.com/lc/gau/v2/cmd/gau@latest
RUN go install -v github.com/PentestPad/subzy@latest
RUN go install -v github.com/projectdiscovery/notify/cmd/notify@latest
RUN go install -v github.com/sensepost/gowitness@latest
RUN go install -v github.com/projectdiscovery/alterx/cmd/alterx@latest

# Update Nuclei Templates
RUN nuclei -update-templates || true


# Install specific Python tools
# bbot: recursive scan, might need deps. 
# playwright: for browser automation
RUN pip3 install --no-cache-dir --break-system-packages bbot playwright \
    && playwright install --with-deps chromium

# Install Python tools via pipx (isolated environments)
# Use || true to continue if package not found on PyPI
RUN pipx install wafw00f || true
RUN pipx install jwt_tool || true

# Install commix from git (not available on PyPI)
RUN git clone --depth 1 https://github.com/commixproject/commix /opt/commix || true

# Install tplmap from git (not available on PyPI)
RUN git clone --depth 1 https://github.com/epinna/tplmap /opt/tplmap \
    && pip3 install --no-cache-dir --break-system-packages -r /opt/tplmap/requirements.txt || true

# Install git-based tools
RUN git clone --depth 1 https://github.com/arthaud/git-dumper /opt/git-dumper \
    && pip3 install --no-cache-dir --break-system-packages -r /opt/git-dumper/requirements.txt

RUN git clone --depth 1 https://github.com/initstring/cloud_enum /opt/cloud_enum \
    && pip3 install --no-cache-dir --break-system-packages -r /opt/cloud_enum/requirements.txt

RUN git clone --depth 1 https://github.com/nccgroup/ScoutSuite /opt/ScoutSuite \
    && pip3 install --no-cache-dir --break-system-packages --ignore-installed -r /opt/ScoutSuite/requirements.txt || true

RUN git clone --depth 1 https://github.com/torque59/Nosql-Exploitation-Framework /opt/nosql-exploit \
    && pip3 install --no-cache-dir --break-system-packages -r /opt/nosql-exploit/requirements.txt || true

# Install Ruby-based tools
RUN git clone --depth 1 https://github.com/enjoiz/XXEinjector /opt/xxeinjector

# Install Python dependencies
WORKDIR /app
COPY pyproject.toml ./
RUN pip3 install --no-cache-dir --break-system-packages \
    litellm==1.81.9 \
    pydantic==2.12.5 \
    pydantic-core==2.41.5 \
    pydantic-settings==2.12.0 \
    python-dotenv>=1.0.0 \
    rich>=13.0.0 \
    typer>=0.9.0 \
    pytest>=8.0.0 \
    pytest-asyncio>=0.23.0 \
    aiofiles>=23.2.0 \
    networkx>=3.0 \
    aiohttp>=3.9.0 \
    fastapi>=0.110.0 \
    uvicorn>=0.29.0

# Copy application code
COPY . .

# Install application in editable mode
RUN pip3 install --no-cache-dir --break-system-packages -e .

# Create workspace directory
RUN mkdir -p /workspace
WORKDIR /workspace

# Set environment variables
ENV CAI_GUARDRAILS=true
ENV CAI_TRACING=false

# Default command
CMD ["cai"]
