docker run --rm --hostname dns.mageddo -d --name dns-proxy-server -p 5380:5380 \
  -v /opt/dns-proxy-server/conf:/app/conf \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /etc/resolv.conf:/etc/resolv.conf \
  defreitas/dns-proxy-server 

docker run -e ATOMIC_SERVER_URL=atomic.dev.intranet --rm -d -p 80:8080 --name="atomic-server" --hostname atomic.dev.intranet atomic-server