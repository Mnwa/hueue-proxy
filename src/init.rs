use std::net::{IpAddr, SocketAddr};

#[derive(Debug, Clone)]
pub struct Opts {
    pub listening_addr: SocketAddr,
    pub max_pending_connections: u32,
    pub allowed_ips: Option<Vec<IpAddr>>,
    pub auth: Option<Auth>,
}

#[derive(Debug, Clone)]
pub struct Auth {
    pub user: String,
    pub password: String,
}

impl Opts {
    pub fn init() -> Result<Self, std::io::Error> {
        env_logger::init();

        let listening_addr: SocketAddr = match std::env::var("ADDR")
            .unwrap_or_else(|_| "127.0.0.1:1080".to_string())
            .parse()
        {
            Ok(a) => a,
            Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, e)),
        };

        let max_pending_connections: u32 = match std::env::var("MAX_PENDING_CONNECTIONS")
            .unwrap_or_else(|_| "1024".to_string())
            .parse()
        {
            Ok(c) => c,
            Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, e)),
        };

        let allowed_ips_result: Option<Result<Vec<IpAddr>, _>> =
            std::env::var("ALLOWED_IPS").ok().map(|allowed| {
                allowed
                    .split(',')
                    .map(|ip| ip.trim())
                    .map(|ip| ip.parse::<IpAddr>())
                    .collect()
            });

        let allowed_ips = match allowed_ips_result {
            None => None,
            Some(Ok(a)) => Some(a),
            Some(Err(e)) => return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, e)),
        };

        let user_password: Option<String> = std::env::var("USER_PASSWORD").ok();
        let auth: Option<Auth> = match user_password {
            None => None,
            Some(up) => match up.split_once(':') {
                Some((u, p)) => Some(Auth {
                    user: u.trim().to_string(),
                    password: p.trim().to_string(),
                }),
                None => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "Invalid USER_PASSWORD env",
                    ))
                }
            },
        };

        Ok(Self {
            listening_addr,
            max_pending_connections,
            allowed_ips,
            auth,
        })
    }
}
