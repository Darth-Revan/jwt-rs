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

macro_rules! fail {
    ($e:expr) => {
        return Err($e);
    };
}

/// Enumeration of custom errors
#[derive(Debug)]
pub enum JwtError {
    /// The token to parse does not have a valid JWT format
    InvalidTokenFormat,
    /// The signature is not valid for the payload
    InvalidSignature,
    /// The token has expired (_exp_ claim)
    TokenExpired(i64),
    /// The token is not valid yet (current time before _nbf_ claim)
    TokenNotYetValid(i64),
    /// An unsupported algorithm is requested
    UnknownAlgorithm,
    /// The requested algorithm is not valid in the desired context
    InvalidAlgorithm,
    /// The key is not valid for the intended purpose
    InvalidKey,
    /// One or more errors occurred in OpenSSL
    OpenSSLError(openssl::error::ErrorStack),
    /// Validation of a claim has failed
    InvalidClaim(String, String),
    /// Error converting some kind of data to an UTF-8 string
    ConversionError(std::string::FromUtf8Error),
    /// Error parsing JSON data
    JsonParseError(serde_json::Error),
    /// Error decoding some base64 data
    Base64Error(base64::DecodeError),
    /// A generic error if no other fits
    GenericError(String),
    #[doc(hidden)]
    __Nonexhaustive,
}

impl std::fmt::Display for JwtError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        #![allow(non_snake_case)]
        match self {
            JwtError::ConversionError(ref e)    => write!(f, "Error converting UTF-8 data: {}", e),
            JwtError::JsonParseError(ref e)     => write!(f, "Error parsing JSON data: {}", e),
            JwtError::Base64Error(ref e)        => write!(f, "Error decoding Base64 data: {}", e),
            JwtError::OpenSSLError(ref e)       => write!(f, "OpenSSL error: {}", e.errors()[0].reason().unwrap_or("")),
            JwtError::GenericError(ref msg)     => write!(f, "{}", msg),
            JwtError::InvalidSignature          => write!(f, "The token's signature is not valid."),
            JwtError::InvalidTokenFormat        => write!(f, "The specified JWT is badly formatted."),
            JwtError::UnknownAlgorithm          => write!(f, "The requested algorithm is not known or not supported."),
            JwtError::InvalidAlgorithm          => write!(f, "The requested algorithm is not valid in this context."),
            JwtError::InvalidKey                => write!(f, "This key is not valid for the requested algorithm."),
            JwtError::InvalidClaim(ref c, ref v)    => write!(f, "The claim \"{}\" (value: \"{}\") is not valid.", c, v),
            JwtError::TokenExpired(t)   => {
                let time = chrono::NaiveDateTime::from_timestamp(*t, 0);
                let time: chrono::DateTime<chrono::Utc> = chrono::DateTime::from_utc(time, chrono::Utc);
                write!(f, "The token expired on {}.", time.to_rfc2822())
            },
            JwtError::TokenNotYetValid(t)   => {
                let time = chrono::NaiveDateTime::from_timestamp(*t, 0);
                let time: chrono::DateTime<chrono::Utc> = chrono::DateTime::from_utc(time, chrono::Utc);
                write!(f, "The token is not valid before {}.", time.to_rfc2822())
            },
            __Nonexhaustive                     => unreachable!(),
        }
    }
}

impl std::error::Error for JwtError {
    fn description(&self) -> &str {
        match self {
            JwtError::ConversionError(_)        => "failed to convert data to UTF-8 string",
            JwtError::Base64Error(_)            => "failed to decode Base64 data",
            JwtError::JsonParseError(_)         => "failed to parse JSON data",
            JwtError::OpenSSLError(_)           => "an error occurred in OpenSSL",
            JwtError::InvalidKey                => "the key is not valid for the intended use",
            JwtError::InvalidClaim(_, _)        => "the token contains an invalid claim",
            JwtError::InvalidTokenFormat        => "the data format is not valid for JWTs",
            JwtError::InvalidSignature          => "the signature is not valid for the token's payload",
            JwtError::TokenExpired(_)       => "the token has expired",
            JwtError::TokenNotYetValid(_)   => "the token is not yet valid",
            JwtError::UnknownAlgorithm          => "the requested algorithm is not supported or unkown",
            JwtError::InvalidAlgorithm          => "the requested algorithm is not valid for this use case",
            JwtError::GenericError(_)           => "an error occurred",
            _                                   => "an error occurred",
        }
    }

    fn cause(&self) -> Option<&std::error::Error> {
        match self {
            JwtError::ConversionError(ref e)   => Some(e),
            JwtError::JsonParseError(ref e)    => Some(e),
            JwtError::Base64Error(ref e)       => Some(e),
            JwtError::OpenSSLError(ref e)      => Some(e),
            _                                  => None,
        }
    }
}

impl From<openssl::error::ErrorStack> for JwtError {
    fn from(e: openssl::error::ErrorStack) -> Self {
        JwtError::OpenSSLError(e)
    }
}

impl From<std::string::FromUtf8Error> for JwtError {
    fn from(e: std::string::FromUtf8Error) -> Self {
        JwtError::ConversionError(e)
    }
}

impl From<base64::DecodeError> for JwtError {
    fn from(e: base64::DecodeError) -> Self {
        JwtError::Base64Error(e)
    }
}

impl From<serde_json::Error> for JwtError {
    fn from(e: serde_json::Error) -> Self {
        JwtError::JsonParseError(e)
    }
}

// manuall implementation as derive is not possible due to some encapsulated
// errors do not implement PartialEq
impl PartialEq for JwtError {
    fn eq(&self, other: &Self) -> bool {
        use JwtError::*;
        match (self, other) {
            (InvalidSignature, InvalidSignature)        => true,
            (InvalidTokenFormat, InvalidTokenFormat)    => true,
            (TokenExpired(a), TokenExpired(b))  => a == b,
            (TokenNotYetValid(a), TokenNotYetValid(b))  => a == b,
            (UnknownAlgorithm, UnknownAlgorithm)        => true,
            (InvalidAlgorithm, InvalidAlgorithm)        => true,
            (InvalidKey, InvalidKey)                    => true,
            (Base64Error(a), Base64Error(b))            => a == b,
            (GenericError(a), GenericError(b))          => a == b,
            (InvalidClaim(a, _), InvalidClaim(b, _))    => a == b,
            _   => false
        }
    }
}

/// Type alias for convenience
pub type JwtResult<T> = std::result::Result<T, JwtError>;
