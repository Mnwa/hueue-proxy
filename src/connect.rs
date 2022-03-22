use crate::{Socks5Error, SOCKS5_VERSION, SUB_NEGOTIATION_VERSION};
use byteorder::ReadBytesExt;
use std::collections::HashSet;
use std::io::{Cursor, Read};

#[derive(Debug)]
pub struct ConnectRequest {
    pub methods: HashSet<Method>,
}

impl ConnectRequest {
    pub fn get_allowed_method(&self, auth_required: bool) -> Method {
        if auth_required {
            if self.methods.contains(&Method::UserPassword) {
                Method::UserPassword
            } else {
                Method::NotAcceptable
            }
        } else if self.methods.contains(&Method::NoAuth) {
            Method::NoAuth
        } else {
            Method::NotAcceptable
        }
    }
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
                HashSet::with_capacity(c_methods as usize),
                |mut acc, method| {
                    acc.insert(Method::from(method?));
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

impl From<Method> for ConnectResponse {
    fn from(method: Method) -> Self {
        Self { method }
    }
}

impl From<ConnectResponse> for Vec<u8> {
    fn from(response: ConnectResponse) -> Self {
        vec![SOCKS5_VERSION, response.method.into()]
    }
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
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

#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Debug)]
pub struct UserPasswordRequest {
    username: String,
    password: String,
}

impl UserPasswordRequest {
    pub fn is_valid(&self, username: String, password: String) -> bool {
        Self { username, password }.eq(self)
    }
}

impl<'a> TryFrom<&'a [u8]> for UserPasswordRequest {
    type Error = Socks5Error;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        let mut rdr = Cursor::new(value);
        let version = rdr.read_u8()?;

        if version != SUB_NEGOTIATION_VERSION {
            return Err(Socks5Error::InvalidVersion(version));
        }

        let u_len = rdr.read_u8()? as usize;
        let mut u_buf = vec![0; u_len];
        rdr.read_exact(&mut u_buf)?;

        let p_len = rdr.read_u8()? as usize;
        let mut p_buf = vec![0; p_len];
        rdr.read_exact(&mut p_buf)?;

        let username = std::str::from_utf8(u_buf.as_slice())?.to_string();
        let password = std::str::from_utf8(p_buf.as_slice())?.to_string();

        Ok(Self { username, password })
    }
}

#[derive(Copy, Clone, Debug)]
pub struct UserPasswordResponse {
    pub is_valid: bool,
}

impl From<UserPasswordResponse> for Vec<u8> {
    fn from(r: UserPasswordResponse) -> Self {
        let status = if r.is_valid { 0x00 } else { 0x01 };

        vec![SUB_NEGOTIATION_VERSION, status]
    }
}

#[cfg(test)]
mod test {
    use crate::connect::{
        ConnectRequest, ConnectResponse, Method, UserPasswordRequest, UserPasswordResponse,
    };
    use crate::{SOCKS5_VERSION, SUB_NEGOTIATION_VERSION};
    use std::collections::HashSet;

    #[test]
    fn test_no_auth_connect() {
        let raw_request = vec![SOCKS5_VERSION, 1, 0x00];
        let parsed_request = ConnectRequest::try_from(raw_request.as_slice()).unwrap();

        assert_eq!(parsed_request.methods, HashSet::from([Method::NoAuth]))
    }

    #[test]
    fn test_no_auth_response() {
        let parsed_response = ConnectResponse {
            method: Method::NoAuth,
        };

        assert_eq!(Vec::from(parsed_response), vec![SOCKS5_VERSION, 0x00])
    }

    #[test]
    fn test_auth_request() {
        let user = "u_test".as_bytes();
        let password = "p_test".as_bytes();

        let mut raw_request = vec![SUB_NEGOTIATION_VERSION];
        raw_request.push(user.len() as u8);
        raw_request.extend_from_slice(user);
        raw_request.push(password.len() as u8);
        raw_request.extend_from_slice(password);

        let parsed_request = UserPasswordRequest::try_from(raw_request.as_slice()).unwrap();

        assert_eq!(parsed_request.username.as_bytes(), user);
        assert_eq!(parsed_request.password.as_bytes(), password);
        assert!(parsed_request.is_valid(
            std::str::from_utf8(user).unwrap().to_string(),
            std::str::from_utf8(password).unwrap().to_string()
        ))
    }

    #[test]
    fn test_auth_response() {
        let parsed_response = UserPasswordResponse { is_valid: true };
        assert_eq!(Vec::from(parsed_response), vec![SUB_NEGOTIATION_VERSION, 0]);

        let parsed_response = UserPasswordResponse { is_valid: false };
        assert_eq!(Vec::from(parsed_response), vec![SUB_NEGOTIATION_VERSION, 1])
    }
}
