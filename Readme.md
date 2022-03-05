# Hueue Socks5 Proxy
> It's fast and safe realization of SOCKS5 proxy protocol.

## Usage
### Build from source
```sh
cargo build --release
./target/release/hueue-proxy
```

### Environments
#### Default
```env
ADDR=127.0.0.1:1080 # address for listening socks5 proxy
MAX_PENDING_CONNECTIONS=1024 # how much connections may be queued (more will be drop)
```
#### Optional
```env
ALLOWED_IPS=127.0.0.1,127.0.0.2 # allow list of ips splitted by , (other ips will restricted)
USER_PASSWORD=user:password # username and password splitted by :
```

## Develop
### Run
```sh 
cargo run
```

### Tests
```sh 
cargo test
```

### Feature list
- [x] `CONNECT` command
- [] `BIND` command
- [ ] `ASSOCIATE` command
- [x] Username/password authentication
- [ ] GSSAPI authentication