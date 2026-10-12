FROM alpine:3.20

RUN apk add --no-cache tor curl

# Run as the tor user created by the package
RUN mkdir -p /var/lib/tor /var/log/tor \
    && chown -R tor:tor /var/lib/tor /var/log/tor \
    && chmod 700 /var/lib/tor

USER tor
EXPOSE 9050 9051

CMD ["tor", "-f", "/etc/tor/torrc"]
