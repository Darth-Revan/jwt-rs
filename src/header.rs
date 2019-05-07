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

//! Defines the structure of a JWT header and various methods for it.

use crate::crypto::JsonWebAlgorithm;

/// A basic header for a JWT
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JwtHeader {
    /// The type of token. Can only be "JWT" here
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,
    /// The algorithm to use for creating the signature
    pub alg: JsonWebAlgorithm,
    /// The optional content type for the token's payload
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cty: Option<String>,
    /// The URL to a set of JSON keys (JWK)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jku: Option<String>,
    /// ID of the JSON key (JWK) used
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    /// URI referring to a X.509 certificate of the key
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5u: Option<String>,
    /// Base64URL encoded thumbprint (SHA-1) of the X.509 certificate
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5t: Option<String>
}

impl JwtHeader {
    /// Returns a new instance of a JWT header using the specified algorithm for
    /// signing.
    /// # Arguments
    /// * `algorithm` - The algorithm to use for creating the signature
    /// # Returns
    /// A new JWT header using the specified algorithm and default values for
    /// all other struct members.
    pub fn new(algorithm: JsonWebAlgorithm) -> Self {
        JwtHeader {
            typ: Some("JWT".to_string()),
            alg: algorithm,
            cty: None,
            jku: None,
            kid: None,
            x5t: None,
            x5u: None,
        }
    }
}

impl Default for JwtHeader {
    /// Returns a default JWT header using the default algorithm (HS256)
    fn default() -> Self {
        JwtHeader::new(JsonWebAlgorithm::default())
    }
}
