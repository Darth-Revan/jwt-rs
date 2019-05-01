// MIT License
//
// Copyright (c) 2019 Kevin Kirchner
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

//! Defines a wrapper structure around all the possible errors that may occur
//! when using this library.

use std::str::Utf8Error;
use std::error::Error as StdError;

macro_rules! fail {
    ($k:expr, $msg:expr) => {
        return Err(crate::errors::Error::new($k, $msg));
    };
}

/// Enumeration of error types
#[derive(Debug)]
pub enum ErrorKind {
    /// The token to parse does not have a valid JWT format
    InvalidTokenFormat,
    /// The signature is not valid for the payload
    InvalidSignature,
    /// An unsupported algorithm is requested
    UnkownAlgorithm,
    /// The token has expired (_exp_ claim)
    SignatureExpired,
    /// One or more errors occurred in OpenSSL
    OpenSSLError(openssl::error::ErrorStack),
    /// The key is not valid for the intended purpose
    InvalidKey,
    /// The token's _iat_ claim is in the future
    InvalidIAT,
    /// The token's _nbf_ claim is in the future
    InvalidNBF,
    /// The token's subject claim does not match expected value
    InvalidSubject,
    /// The token's issuer claim does not match expected value
    InvalidIssuer,
    /// The token's audience claim does not match expected value
    InvalidAudience,
    /// Error converting some kind of data to an UTF-8 string
    ConversionError(Utf8Error),
    /// Error parsing JSON data
    JsonParseError(serde_json::Error),
    /// Error decoding some base64 data
    Base64Error(base64::DecodeError),
    /// A generic error if no other fits
    GenericError,
    #[doc(hidden)]
    __Nonexhaustive,
}

/// Structure representing an error
#[derive(Debug)]
pub struct Error {
    /// The kind of error
    pub kind: ErrorKind,
    /// Descriptive error message
    pub message: String,
}

impl Error {
    /// Creates a new instance of `Error`.
    /// # Arguments
    /// * `k` - The kind of error
    /// * `msg` - A message describing the error
    /// # Returns
    /// A new instance of `Error`
    pub fn new<T>(k: ErrorKind, msg: T) -> Self where T: Into<String> {
        Error { kind: k, message: msg.into() }
    }

    /// Creates a new instance of `Error` without specifying a custom error
    /// message.
    /// # Arguments
    /// * `k` - The kind of error
    /// # Returns
    /// A new instance of `Error`
    pub fn new_without_msg(k: ErrorKind) -> Self {
        Error {kind: k, message: String::default()}
    }

    /// Creates a new instance of `Error` for generic errors (kind
    /// `GenericError`) using the message specified in `msg`.
    /// # Arguments
    /// * `msg` - A message describing the error
    /// # Returns
    /// A new instance of `Error`
    pub fn generic<T>(msg: T) -> Self where T: Into<String> {
        Error { kind: ErrorKind::GenericError, message: msg.into() }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self.kind {
            ErrorKind::ConversionError(ref e)   => e.fmt(f),
            ErrorKind::JsonParseError(ref e)    => e.fmt(f),
            ErrorKind::Base64Error(ref e)       => e.fmt(f),
            ErrorKind::OpenSSLError(ref e)      => write!(f, "OpenSSL error: {}", e.errors()[0].reason().unwrap_or("")),
            _                                   => write!(f, "{}", self.message),
        }
    }
}

impl StdError for Error {
    fn description(&self) -> &str {
        match self.kind {
            ErrorKind::ConversionError(_)       => "failed to convert data to UTF-8 string",
            ErrorKind::Base64Error(_)           => "failed to decode Base64 data",
            ErrorKind::JsonParseError(_)        => "failed to parse JSON data",
            ErrorKind::OpenSSLError(_)          => "an error occurred in OpenSSL",
            ErrorKind::InvalidKey               => "the key is not valid for the intended use",
            ErrorKind::InvalidAudience          => "the token's \"aud\" claim is not valid",
            ErrorKind::InvalidIssuer            => "the token's \"iss\" claim is not valid",
            ErrorKind::InvalidSubject           => "the token's \"sub\" claim is not valid",
            ErrorKind::InvalidTokenFormat       => "the data format is not valid for JWTs",
            ErrorKind::InvalidSignature         => "the signature is not valid for the token's payload",
            ErrorKind::InvalidIAT               => "the token's \"iat\" claim lies in the future",
            ErrorKind::InvalidNBF               => "the token's \"nbf\" claim lies in the future",
            ErrorKind::SignatureExpired         => "the token's signature has expired",
            ErrorKind::UnkownAlgorithm          => "the requested algorithm is not supported or unkown",
            ErrorKind::GenericError             => "an error has occurred",
            _                                   => "an error has occurred",
        }
    }

    fn cause(&self) -> Option<&std::error::Error> {
        match self.kind {
            ErrorKind::ConversionError(ref e)   => Some(e),
            ErrorKind::JsonParseError(ref e)    => Some(e),
            ErrorKind::Base64Error(ref e)       => Some(e),
            ErrorKind::OpenSSLError(ref e)      => Some(e),
            _                                   => None,
        }
    }
}

// Construction of error from a tuple
impl<T> From<(ErrorKind, T)> for Error where T: Into<String> {
    fn from((e, desc): (ErrorKind, T)) -> Self  {
        Error { kind: e, message: desc.into() }
    }
}

impl From<openssl::error::ErrorStack> for Error {
    fn from(e: openssl::error::ErrorStack) -> Self {
        Error::new_without_msg(ErrorKind::OpenSSLError(e))
    }
}

impl From<Utf8Error> for Error {
    fn from(e: Utf8Error) -> Self {
        Error::new_without_msg(ErrorKind::ConversionError(e))
    }
}

impl From<base64::DecodeError> for Error {
    fn from(e: base64::DecodeError) -> Self {
        Error::new_without_msg(ErrorKind::Base64Error(e))
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::new_without_msg(ErrorKind::JsonParseError(e))
    }
}

/// Type alias for convenience
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn create_error() {
        let e = Error::new(ErrorKind::InvalidTokenFormat, "foobar");
        assert!(e.description().len() > 0);
        assert_eq!(e.message, "foobar");
        assert!(match e.kind { ErrorKind::InvalidTokenFormat => true, _ => false });
    }

    #[test]
    fn create_generic_error() {
        let e = Error::generic("foobar");
        assert!(e.description().len() > 0);
        assert_eq!(e.message, "foobar");
        assert!(match e.kind { ErrorKind::GenericError => true, _ => false });
    }

    #[test]
    fn create_from_tuple() {
        let e = Error::from((ErrorKind::SignatureExpired, "foobar"));
        assert!(e.description().len() > 0);
        assert_eq!(e.message, "foobar");
        assert!(match e.kind { ErrorKind::SignatureExpired => true, _ => false });
    }

}
