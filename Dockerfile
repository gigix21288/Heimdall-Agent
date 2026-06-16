FROM python:3.12-slim

# scapy needs libpcap at runtime for packet capture.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpcap0.8 tcpdump \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir scapy "websockets>=12"

COPY heimdall_agent.py /app/heimdall_agent.py
WORKDIR /app

# NOTE: the container MUST run with host networking + NET_RAW/NET_ADMIN so it
# can see LAN traffic (see docker-compose.yml / README).
ENTRYPOINT ["python", "heimdall_agent.py"]
CMD ["--mode", "pcap"]
