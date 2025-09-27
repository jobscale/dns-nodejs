# dns-nodejs

## build
```
docker build . -t local/dns-nodejs
```

# run
```
docker run --rm -p 53:53/udp -it local/dns-nodejs
```
