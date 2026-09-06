FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

# Basic packages, golang for go tools, python3 and pip
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv golang-go git nmap ffuf curl wget unzip jq build-essential ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Set GOPATH and PATH
ENV GOPATH=/root/go
ENV PATH=$PATH:/root/go/bin

# Copy repo files
WORKDIR /opt/0xGhost
COPY . /opt/0xGhost

# Install Python requirements
RUN pip3 install --no-cache-dir -r requirements.txt \
    && pip3 install --no-cache-dir requests beautifulsoup4 urllib3 python-nmap tqdm

# Install Go-based tools used by the pipeline
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
 && go install github.com/projectdiscovery/httpx/cmd/httpx@latest \
 && go install github.com/projectdiscovery/katana/cmd/katana@latest \
 && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
 && go install github.com/lc/gau/v2/cmd/gau@latest \
 && go install github.com/tomnomnom/waybackurls@latest

# Ensure /opt/0xGhost is writable for scan_results
RUN mkdir -p /opt/0xGhost/scan_results && chown -R root:root /opt/0xGhost

EXPOSE 8080

CMD ["python3", "app.py"]
