# dns-nodejs

## build
```
docker build . -t local/dns-nodejs
```

## run
```
docker run --rm -p 53:53/udp -it local/dns-nodejs
```

## check
```
dig jsx.jp @127.0.0.1
dig proxy.x.jsx.jp @127.0.0.1
dig n100.jsx.jp @127.0.0.1
dig proxy.us.jsx.jp @127.0.0.1
dig github.io @127.0.0.1
```
