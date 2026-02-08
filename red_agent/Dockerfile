# red_agent/Dockerfile
FROM kalilinux/kali-rolling

# 1. Update and install specific attack tools
# We keep it light to save your RAM
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    nmap \
    curl \
    iputils-ping \
    net-tools \
    # Metasploit is heavy, uncomment only if needed later
    # metasploit-framework \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

CMD ["tail", "-f", "/dev/null"]
