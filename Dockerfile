FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv golang-go git nmap ffuf curl wget unzip jq build-essential ca-certificates \
    amass sqlmap testssl.sh \
    && rm -rf /var/lib/apt/lists/*

ENV GOPATH=/root/go
ENV PATH=$PATH:/root/go/bin

WORKDIR /opt/0xGhost
COPY . /opt/0xGhost

RUN pip3 install --no-cache-dir -r requirements.txt \
    && pip3 install --no-cache-dir flask-cors CORStest

RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
 && go install github.com/projectdiscovery/httpx/cmd/httpx@latest \
 && go install github.com/projectdiscovery/katana/cmd/katana@latest \
 && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
 && go install github.com/lc/gau/v2/cmd/gau@latest \
 && go install github.com/tomnomnom/waybackurls@latest \
 && go install github.com/PentestPad/subzy@latest

RUN mkdir -p /opt/0xGhost/scan_results && chown -R root:root /opt/0xGhost

EXPOSE 8080

CMD ["python3", "app.py"]
