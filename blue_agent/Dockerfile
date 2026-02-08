# blue_agent/Dockerfile
FROM ubuntu:22.04

# Avoid prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# 1. Install Python and Basic Tools
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    iputils-ping \
    curl \
    git \
    # 2. Install BPF Compiler Collection (BCC) tools
    bpfcc-tools \
    python3-bpfcc \
    linux-headers-generic \
    && rm -rf /var/lib/apt/lists/*

# 3. Create a workspace
WORKDIR /app

# 4. Keep container alive
CMD ["tail", "-f", "/dev/null"]
