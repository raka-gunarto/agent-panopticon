FROM mitmproxy/mitmproxy:10.4.2

USER root

RUN apt-get update && apt-get install -y --no-install-recommends \
      iptables curl \
    && rm -rf /var/lib/apt/lists/*

# Non-root user for mitmproxy (UID used by iptables to exempt proxy traffic)
RUN useradd -r -u 1337 -s /usr/sbin/nologin -m mitmuser

COPY addons/ /etc/proxy/addons/
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

VOLUME /home/mitmuser/.mitmproxy

ENTRYPOINT ["/entrypoint.sh"]
