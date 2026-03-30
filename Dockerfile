FROM node:20-slim

# Install tshark and dependencies
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
      tshark \
      wireshark-common \
      libpcap0.8 \
      --no-install-recommends && \
    # Allow non-root users to run tshark
    chmod +x /usr/bin/tshark && \
    groupadd -f wireshark && \
    usermod -a -G wireshark node && \
    chgrp wireshark /usr/bin/dumpcap && \
    chmod 750 /usr/bin/dumpcap && \
    setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' /usr/bin/dumpcap && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# App directory
WORKDIR /app

# Install Node dependencies
COPY package.json ./
RUN npm install --production

# Copy source
COPY server.js ./

# Run as node user
USER node

EXPOSE 3000

CMD ["node", "server.js"]
