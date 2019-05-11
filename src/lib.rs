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

//! Simple library crate for reading and creating JSON Web Tokens based on the
//! specifications found in RFC 7519. This library is also able to automatically
//! validate JWTs, including the cryptographic signature in use and various
//! claims (e.g. _exp_ or _nbf_).

// Forbid missing docs for public items and unsafe code in the whole crate
#![forbid(missing_docs)]
#![forbid(unsafe_code)]

#[cfg(test)]
#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate serde_derive;

#[macro_use]
mod errors;
mod crypto;
mod header;
mod claims;

pub use errors::{JwtError, JwtResult};
pub use header::JwtHeader;
pub use crypto::{JsonWebAlgorithm, verify, sign};
pub use claims::{Claims, ClaimValidator, REGISTERED_CLAIM_NAMES};

use serde::Serialize;
use serde::de::DeserializeOwned;

/// The data of a JWT including the header and the claims, but not the signature
#[derive(Debug)]
pub struct JwtData {
    /// The JWT's header
    pub header: JwtHeader,
    /// The JWT's decoded claims/payload
    pub claims: Claims,
}

/// Serializes some generic data into JSON, encodes the result using URL-safe
/// Base64 and returns the resulting string.
/// # Arguments
/// * `data` - Some generic serializable data
/// # Returns
/// A string containing the Base64URL encoded JSON form of the input data
/// # Errors
/// Returns an error if serializing the input data fails.
fn data_to_jwt_payload<T: Serialize>(data: &T) -> JwtResult<String> {
    Ok(base64::encode_config(serde_json::to_string(data)?.as_bytes(), base64::URL_SAFE_NO_PAD))
}

/// Decodes some URL-safe Base64 encoded JSON data and deserializes the result
/// into a struct which will be returned afterwards. Essentially the reverse of
/// `data_to_jwt_payload`.
/// # Arguments
/// * `input` - Some Base64URL encoded data
/// # Returns
/// A struct representing the deserialized data from the Base64URL encoded input
/// # Errors
/// Returns an error if any of the following operations fails:
/// * decoding the input as a Base64URL encoded string
/// * converting the decoded string into a valid UTF-8 string
/// * deserializing the data as JSON
fn data_from_jwt_payload<E: AsRef<str>, T: DeserializeOwned>(input: E) -> JwtResult<T> {
    let d = base64::decode_config(input.as_ref(), base64::URL_SAFE_NO_PAD)?;
    let d = String::from_utf8(d)?;
    Ok(serde_json::from_str(&d)?)
}

macro_rules! get_two {
    ($iterator:expr) => {{
        let mut iterator = $iterator;
        match (iterator.next(), iterator.next(), iterator.next()) {
            (Some(a), Some(b), None)    => (a, b),
            _                           => fail!(JwtError::InvalidTokenFormat)
        }
    }};
}

/// Encodes some give header data and claims into a Base64URL encoded JWT. The
/// signature algorithm to use for calculating the signature is taken from the
/// `header`. If the chosen algorithm is `None`, you can safely set `signing_key`
/// to an empty string.
/// # Arguments
/// * `header` - The header of the JWT specifying the algorithm (at least)
/// * `claims` - The token claims to serialize
/// * `signing_key` - Key for creating the signature. The format depends on the
/// algorithm used (for HMACs this may be some random string or password, for
/// other algorithms, e.g. RSA this is a PEM encoded key). If you chose the
/// algorithm `None` you may set this to an empty string as it will be ignored.
/// # Returns
/// The serialized token including the signature as a Base64URL encoded string
/// on success, an error type otherwise
/// # Errors
/// This function may fail for the following reasons:
/// * Either header or claims cannot be serialized successfully
/// * The specified key is not valid
/// * The specified key does not meet the requirements of the chosen algorithm
/// * Creating the signature simply fails because `openssl` decides to fail
/// * Encoding the data using Base64URL fails
/// # Examples
/// ```rust
/// # use jwt_rs::{Claims, JwtHeader, encode_token};
/// let claims = Claims::default();
/// let header = JwtHeader::default();
/// let token = encode_token(&header, &claims, "key".as_bytes());
/// assert!(token.is_ok());
/// println!("{}", token.unwrap());
/// ```
pub fn encode_token(header: &JwtHeader, claims: &Claims, signing_key: &[u8]) -> JwtResult<String> {
    let algorithm = header.alg;
    let header = data_to_jwt_payload(&header)?;
    let claims = data_to_jwt_payload(&claims)?;
    let payload = [header.as_ref(), claims.as_ref()].join(".");
    let signature = sign(&payload, signing_key, algorithm)?;
    Ok([payload, signature].join("."))
}

/// Decodes a JWT from a Base64URL string without any validation on signature or
/// claims.
///
/// **WARNING:** This method should not be used in a productive, security relevant
/// environment. JWTs without validation provide **NO** security as clients can
/// easily tamper with the data without the server noticing. I warned you!
/// # Arguments
/// * `input` - The input data to deserialize into a JWT as Base64URL string
/// # Returns
/// The deserialized JWT header and claims (unvalidated!) or an error type on
/// failure
/// # Errors
/// This function returns an error if it was unable to deserialize the data
/// into a valid JWT header and claims. The returned error may be further
/// inspected to get root cause of failure.
/// # Examples
/// ```rust
/// # use jwt_rs::{Claims, JwtHeader, encode_token, decode_token_unsafe};
/// # let claims = Claims::default();
/// # let header = JwtHeader::default();
/// let token = encode_token(&header, &claims, "key".as_bytes()).unwrap();
/// let decoded = decode_token_unsafe(&token).unwrap();      // no validation!
/// let (header, claims) = (decoded.header, decoded.claims);
/// ```
pub fn decode_token_unsafe(input: &str) -> JwtResult<JwtData> {
    let (_, payload) = get_two!(input.rsplitn(2, '.'));
    let (claims, header) = get_two!(payload.rsplitn(2, '.'));
    let header: JwtHeader = data_from_jwt_payload(header)?;
    let claims: Claims = data_from_jwt_payload(claims)?;
    Ok(JwtData {header, claims})
}

/// Decodes only the header part of a JWT from a Base64URL string without any
/// validation on signature or claims.
///
/// **WARNING:** This method should not be used in a productive, security relevant
/// environment. JWTs without validation provide **NO** security as clients can
/// easily tamper with the data without the server noticing. I warned you!
/// # Arguments
/// * `input` - The input data to deserialize into a JWT header as Base64URL string
/// # Returns
/// The deserialized JWT header (unvalidated!) or an error type on failure
/// # Errors
/// This function returns an error if it was unable to deserialize the data
/// into a valid JWT header. The returned error may be further inspected to get
/// root cause of failure.
/// # Examples
/// ```rust
/// # use jwt_rs::{Claims, JwtHeader, encode_token, decode_token_header, JsonWebAlgorithm};
/// # let claims = Claims::default();
/// # let header = JwtHeader::default();
/// let token = encode_token(&header, &claims, "key".as_bytes()).unwrap();
/// let decoded_header = decode_token_header(&token).unwrap();      // no validation and returns only header
/// assert_eq!(decoded_header.alg, JsonWebAlgorithm::HS256);
/// ```
pub fn decode_token_header(input: &str) -> JwtResult<JwtHeader> {
    let (_, payload) = get_two!(input.rsplitn(2, '.'));
    let (_, header) = get_two!(payload.rsplitn(2, '.'));
    data_from_jwt_payload(header)
}

/// Decodes a JWT header and claims from a Base64URL string and verifies both
/// the signature and the claims against a given validator.
/// # Arguments
/// * `input` - The input data to deserialize into a JWT as Base64URL string
/// * `key` - The key to verify the signature with. The format dependes on the
/// algorithm used in the token. You may first inspect the header on itself
/// using [decode_token_header](fn.decode_token_header.html) to get the algorithm
/// used and then validate the token using this function and the correct key if
/// your application supports/uses more than one algorithm.
/// * `validator` - A validator instance to use for validating the deserialized
/// claims
/// # Returns
/// The deserialized and validated JWT or an error type on failure
/// # Errors
/// This function returns an error in any of the following cases
/// * Decoding the input data as Base64URL string fails
/// * Either header or claims cannot be deserialized successfully
/// * The specified key is not valid
/// * The specified key does not meet the requirements of the algorithm in use
/// * Verifying the signature fails because it is simply not valid
/// * Verifying the signature fails because `openssl` decides to fail
/// * Any of the claims is invalid in the context of the given validator
/// # Examples
/// ```rust
/// # use jwt_rs::{Claims, JwtHeader, encode_token, decode_token, ClaimValidator};
/// # use chrono;
/// let mut claims = Claims::default();
/// claims.exp = Some(chrono::Utc::now().timestamp() + 10000);
/// let header = JwtHeader::default();
/// let token = encode_token(&header, &claims, "key".as_bytes()).unwrap();
/// let validator = ClaimValidator::default();
/// let decoded = decode_token(&token, "key".as_bytes(), &validator).unwrap();
/// let (header, claims) = (decoded.header, decoded.claims);
/// ```
pub fn decode_token(input: &str, key: &[u8], validator: &ClaimValidator) -> JwtResult<JwtData> {
    let (signature, payload) = get_two!(input.rsplitn(2, '.'));
    let (claims, header) = get_two!(payload.rsplitn(2, '.'));
    let header: JwtHeader = data_from_jwt_payload(header)?;

    if !verify(signature, payload, key, header.alg)? {
        fail!(JwtError::InvalidSignature);
    }

    let claims: Claims = data_from_jwt_payload(claims)?;
    if !validator.validate(&claims)? {
        fail!(JwtError::GenericError("The validation of token claims failed.".to_string()));
    }

    Ok(JwtData {header, claims})
}

#[cfg(test)]
mod tests {
    use super::*;

    mod generic {
        use super::*;

        #[test]
        fn get_two_macro_good() -> JwtResult<()> {
            let s1 = "foo.bar";
            let (r, l) = get_two!(s1.rsplitn(2, '.'));
            assert_eq!(l, "foo");
            assert_eq!(r, "bar");
            let s2 = "foo.bar.baz";
            let (r, l) = get_two!(s2.rsplitn(2, '.'));
            assert_eq!(l, "foo.bar");
            assert_eq!(r, "baz");
            Ok(())
        }

        fn inner(s: &str, n: usize, p: char) -> JwtResult<(&str, &str)> {
            Ok(get_two!(s.rsplitn(n, p)))
        }

        #[test]
        #[should_panic]
        fn get_two_macro_fail_1() {
            inner("foo", 2, '.').expect("That's ok");
        }

        #[test]
        #[should_panic]
        fn get_two_macro_fail_2() {
            inner("foo.bar", 2, ';').expect("That's ok");
        }

        #[test]
        #[should_panic]
        fn get_two_macro_fail_3() {
            inner("foo.bar", 1, '.').expect("That's ok");
        }

        #[derive(Serialize, Deserialize)]
        struct TestStruct {
            a: String,
            b: String,
        }

        #[test]
        fn encode_data() -> JwtResult<()> {
            let x = TestStruct {a: "Foo".to_string(), b: "Bar".to_string()};
            assert_eq!(data_to_jwt_payload(&x)?, "eyJhIjoiRm9vIiwiYiI6IkJhciJ9");
            Ok(())
        }

        #[test]
        fn decode_data_success() -> JwtResult<()> {
            let x: TestStruct = data_from_jwt_payload("eyJhIjoiRm9vIiwiYiI6IkJhciJ9")?;
            assert_eq!(x.a, "Foo");
            assert_eq!(x.b, "Bar");
            Ok(())
        }

        #[test]
        fn decode_data_fail_no_base64() -> JwtResult<()> {
            let x: JwtResult<TestStruct> = data_from_jwt_payload("eyJhIjoiRm9vIiwiYiI6IkJhciJ9ü*");
            assert!(x.is_err());
            Ok(())
        }

        #[test]
        fn decode_data_fail_wrong_format() -> JwtResult<()> {
            let input = "eyJhIjoiRm9vIiwiYyI6IkJhciJ9";     // {"a": "Foo","c":"Bar"}
            let x: JwtResult<TestStruct> = data_from_jwt_payload(&input);
            assert!(x.is_err());
            Ok(())
        }
    }

    mod tokens {
        use super::*;
        use serde_json::json;

        lazy_static! {
            static ref HEADER: JwtHeader = JwtHeader::new(JsonWebAlgorithm::HS256);
            static ref NOW: i64 = chrono::Utc::now().timestamp();
            static ref CLAIMS: Claims = {
                let mut claims = Claims::default();
                claims.sub = Some("Foobar".to_string());
                claims.nbf = Some(10000);
                claims.exp = Some(*NOW + 10000);
                claims.set_custom_claim("name", &"John Doe").expect("Failed to set custom claim!");
                claims
            };
        }
        const KEY: &str = "secretkey";

        #[test]
        fn encode_decode_token_success() -> JwtResult<()> {
            let token = encode_token(&HEADER, &CLAIMS, "key".as_bytes())?;
            let decoded = decode_token(&token, "key".as_bytes(), &ClaimValidator::default())?;
            let (header, claims) = (decoded.header, decoded.claims);
            assert_eq!(header.typ.unwrap(), "JWT".to_string());
            assert_eq!(header.alg, JsonWebAlgorithm::HS256);
            assert_eq!(claims.exp.unwrap(), *NOW + 10000);
            assert_eq!(claims.nbf.unwrap(), 10000);
            assert_eq!(claims.sub, Some("Foobar".to_string()));
            assert_eq!(claims.get_custom_claim("name").unwrap(), &json!("John Doe"));
            Ok(())
        }

        #[test]
        fn encode_decode_no_algo() -> JwtResult<()> {
            let header = JwtHeader::new(JsonWebAlgorithm::None);
            let token = encode_token(&header, &CLAIMS, &[])?;
            let decoded = decode_token(&token, &[], &ClaimValidator::default())?;
            let (header, claims) = (decoded.header, decoded.claims);
            assert_eq!(header.typ.unwrap(), "JWT".to_string());
            assert_eq!(header.alg, JsonWebAlgorithm::None);
            assert_eq!(claims.nbf.unwrap(), 10000);
            assert_eq!(claims.get_custom_claim("name").unwrap(), &json!("John Doe"));
            Ok(())
        }

        #[test]
        fn decode_wrong_key() {
            let token = encode_token(&HEADER, &CLAIMS, "key".as_bytes()).unwrap();
            let decoded = decode_token(&token, "notmykey".as_bytes(), &ClaimValidator::default());
            assert!(decoded.is_err());
            match decoded.unwrap_err() {
                JwtError::InvalidSignature  => assert!(true),
                _                           => assert!(false),
            }
        }

        #[test]
        fn decode_no_key() {
            let token = encode_token(&HEADER, &CLAIMS, "key".as_bytes()).unwrap();
            let decoded = decode_token(&token, "".as_bytes(), &ClaimValidator::default());
            assert!(decoded.is_err());
            match decoded.unwrap_err() {
                JwtError::InvalidSignature  => assert!(true),
                _                           => assert!(false),
            }
        }

        #[test]
        fn decode_validation() {
            let token = encode_token(&HEADER, &CLAIMS, "key".as_bytes()).unwrap();
            let mut validator = ClaimValidator::default();
            validator.validate_sub = Some("Foobar".to_string());
            validator.validate_nbf = true;
            let decoded = decode_token(&token, "key".as_bytes(), &validator);
            assert!(decoded.is_ok());
        }

        #[test]
        fn decode_validation_expired() {
            let expires: i64 = *NOW - 10000;
            let mut my_claims = (*CLAIMS).clone();
            my_claims.exp = Some(expires);
            let token = encode_token(&HEADER, &my_claims, "supersecret".as_bytes()).unwrap();
            let decoded = decode_token(&token, "supersecret".as_bytes(), &ClaimValidator::default());
            assert!(decoded.is_err());
            match decoded.unwrap_err() {
                JwtError::TokenExpired(v)   => assert!(v == expires),
                _                           => assert!(false),
            }
        }

        #[test]
        fn decode_header() {
            let token = encode_token(&HEADER, &CLAIMS, KEY.as_bytes()).unwrap();
            let header = decode_token_header(&token).unwrap();
            assert_eq!(header.alg, JsonWebAlgorithm::HS256);
            assert_eq!(header.typ.unwrap(), "JWT".to_string());
        }

        #[test]
        fn decode_header_expired() {
            let token = encode_token(&HEADER, &CLAIMS, KEY.as_bytes()).unwrap();
            let header = decode_token_header(&token).unwrap();  // does not validate!
            assert_eq!(header.alg, JsonWebAlgorithm::HS256);
            assert_eq!(header.typ.unwrap(), "JWT".to_string());
        }

        #[test]
        fn decode_unsafe() {
            let token = encode_token(&HEADER, &CLAIMS, KEY.as_bytes()).unwrap();
            let decoded = decode_token_unsafe(&token).unwrap();
            let header = decoded.header;
            assert_eq!(header.alg, JsonWebAlgorithm::HS256);
            assert_eq!(header.typ.unwrap(), "JWT".to_string());
        }

        #[test]
        fn decode_usafe_expired() {
            let mut my_claims = CLAIMS.clone();
            my_claims.exp = Some(*NOW - 10000);
            let token = encode_token(&HEADER, &my_claims, KEY.as_bytes()).unwrap();
            let decoded = decode_token_unsafe(&token).unwrap();
            let claims = decoded.claims;
            assert_eq!(claims.exp, Some(*NOW - 10000));
            assert_eq!(claims.sub.unwrap(), "Foobar".to_string());
        }
    }

}
