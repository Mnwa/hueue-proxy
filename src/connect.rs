use crate::{Socks5Error, SOCKS5_VERSION};
use byteorder::ReadBytesExt;
use std::io::Cursor;

#[derive(Debug)]
pub struct ConnectRequest {
    methods: Vec<Method>,
}

impl<'a> TryFrom<&'a [u8]> for ConnectRequest {
    type Error = Socks5Error;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        let mut rdr = Cursor::new(value);
        let version = rdr.read_u8()?;

        if version != SOCKS5_VERSION {
            return Err(Socks5Error::InvalidVersion(version));
        }

        let c_methods = rdr.read_u8()?;

        let methods = (0..c_methods)
            .map(|_| rdr.read_u8())
            .try_fold::<_, _, Result<_, Socks5Error>>(
                Vec::with_capacity(c_methods as usize),
                |mut acc, method| {
                    acc.push(Method::from(method?));
                    Ok(acc)
                },
            )?;

        Ok(Self { methods })
    }
}

#[derive(Debug)]
pub struct ConnectResponse {
    pub method: Method,
}

impl From<ConnectRequest> for ConnectResponse {
    fn from(request: ConnectRequest) -> Self {
        let method = if request.methods.contains(&Method::NoAuth) {
            Method::NoAuth
        } else {
            Method::NotAcceptable
        };

        Self { method }
    }
}

impl From<ConnectResponse> for Vec<u8> {
    fn from(response: ConnectResponse) -> Self {
        vec![SOCKS5_VERSION, response.method.into()]
    }
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug)]
pub enum Method {
    NoAuth,
    Gssapi,
    UserPassword,
    Iana(u8),
    Private(u8),
    NotAcceptable,
}

impl From<u8> for Method {
    fn from(code: u8) -> Self {
        match code {
            0x00 => Method::NoAuth,
            0x01 => Method::Gssapi,
            0x02 => Method::UserPassword,
            c if (0x03..=0x7F).contains(&c) => Method::Iana(c),
            c if (0x80..=0xFE).contains(&c) => Method::Private(c),
            _ => Method::NotAcceptable,
        }
    }
}

impl From<Method> for u8 {
    fn from(method: Method) -> Self {
        match method {
            Method::NoAuth => 0x00,
            Method::Gssapi => 0x01,
            Method::UserPassword => 0x02,
            Method::Iana(c) => c,
            Method::Private(c) => c,
            Method::NotAcceptable => 0xFF,
        }
    }
}
