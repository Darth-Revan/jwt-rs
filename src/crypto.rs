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

//! Defines the cryptographic operations used for signing and verifying
//! signatures used by JWTs. Essentially wraps the respective functions
//! provided by `ring`.

use crate::errors::{Error, ErrorKind, Result};
use base64;
use openssl::{
    hash,
    pkey,
    rsa,
    sign,
};

#[cfg(not(feature = "no-ecdsa"))]
use openssl::{
    bn::BigNum,
    nid::Nid,
    ec,
    ecdsa::EcdsaSig
};

/// Enumeration of supported JWAs (JSON Web Algorithms) as described in RFC 7518
#[derive(Debug, PartialEq, Copy, Clone, Serialize, Deserialize)]
pub enum JsonWebAlgorithm {
    /// No crypto; not recommended
    None,
    /// HMAC using SHA-256
    HS256,
    /// HMAC using SHA-384
    HS384,
    /// HMAC using SHA-512
    HS512,
    /// RSA PKCS#1 1.5 signature using SHA-256
    RS256,
    /// RSA PKCS#1 1.5 signature using SHA-384
    RS384,
    /// RSA PKCS#1 1.5 signature using SHA-512
    RS512,
    #[cfg(not(feature = "no-ecdsa"))]
    /// ECDSA signature using the P-256 curve and SHA-256
    ES256,
    #[cfg(not(feature = "no-ecdsa"))]
    /// ECDSA signature using the P-384 curve and SHA-384
    ES384,
    #[cfg(not(feature = "no-ecdsa"))]
    /// ECDSA signature using the P-521 curve and SHA-512
    ES512,
    /// RSA PSS signature using SHA-256 for both data hashing and Mask Generation Function (MGF)
    PS256,
    /// RSA PSS signature using SHA-384 for both data hashing and Mask Generation Function (MGF)
    PS384,
    /// RSA PSS signature using SHA-512 for both data hashing and Mask Generation Function (MGF)
    PS512,
}

impl Default for JsonWebAlgorithm {
    fn default() -> Self {
        JsonWebAlgorithm::HS256
    }
}

impl std::str::FromStr for JsonWebAlgorithm {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "HS256" => Ok(JsonWebAlgorithm::HS256),
            "HS384" => Ok(JsonWebAlgorithm::HS384),
            "HS512" => Ok(JsonWebAlgorithm::HS512),
            "RS256" => Ok(JsonWebAlgorithm::RS256),
            "RS384" => Ok(JsonWebAlgorithm::RS384),
            "RS512" => Ok(JsonWebAlgorithm::RS512),
            #[cfg(not(feature = "no-ecdsa"))]
            "ES256" => Ok(JsonWebAlgorithm::ES256),
            #[cfg(not(feature = "no-ecdsa"))]
            "ES384" => Ok(JsonWebAlgorithm::ES384),
            #[cfg(not(feature = "no-ecdsa"))]
            "ES512" => Ok(JsonWebAlgorithm::ES512),
            "PS256" => Ok(JsonWebAlgorithm::PS256),
            "PS384" => Ok(JsonWebAlgorithm::PS384),
            "PS512" => Ok(JsonWebAlgorithm::PS512),
            _       => Err(Error::new(ErrorKind::UnkownAlgorithm, "The requested algorithm is either not valid or not supported by this crate!"))
        }
    }
}

/// Creates a signature using a HMAC algorithm.
///
/// # Arguments
/// * `algo` - The algorithm to use for signing
/// * `key` - The key for signing the data
/// * `input` - The data to sign
/// # Returns
/// The Base64 encoded signature in a String if successful, an error type
/// otherwise
/// # Errors
/// Returns an error if specifying a signature algorithm that is not based on
/// a HMAC.
fn sign_hmac(algo: JsonWebAlgorithm, key: &[u8], input: &str) -> Result<String> {
    let algo = match algo {
        JsonWebAlgorithm::HS256 => hash::MessageDigest::sha256(),
        JsonWebAlgorithm::HS384 => hash::MessageDigest::sha384(),
        JsonWebAlgorithm::HS512 => hash::MessageDigest::sha512(),
        _                       => fail!(ErrorKind::UnkownAlgorithm, "The requested algorithm is not a valid HMAC algorithm.")
    };
    let signing_key = pkey::PKey::hmac(key)?;
    let mut signer = sign::Signer::new(algo, &signing_key)?;
    signer.update(input.as_bytes())?;
    let hmac = signer.sign_to_vec()?;
    Ok(base64::encode_config(&hmac, base64::URL_SAFE_NO_PAD))
}

/// Creates a signature using a RSA PKCS#1 1.5 algorithm.
///
/// # Arguments
/// * `algo` - The algorithm to use for signing
/// * `key` - The key for signing the data; must be a PEM encoded RSA private key
/// * `input` - The data to sign
/// # Returns
/// The Base64 encoded signature in a String if successful, an error type
/// otherwise
/// # Errors
/// Returns an error if specifying a signature algorithm that is not based on
/// RSA PKCS#1 1.5 or if OpenSSL fails to parse the input key as PEM encoded
/// private key.
fn sign_rsa_pkcs(algo: JsonWebAlgorithm, key: &[u8], input: &str) -> Result<String> {
    let algo = match algo {
        JsonWebAlgorithm::RS256 => hash::MessageDigest::sha256(),
        JsonWebAlgorithm::RS384 => hash::MessageDigest::sha384(),
        JsonWebAlgorithm::RS512 => hash::MessageDigest::sha512(),
        _                       => fail!(ErrorKind::UnkownAlgorithm, "The requested algorithm is not a flavor of RSA with PKCS#1 padding.")
    };

    let signing_key = rsa::Rsa::private_key_from_pem(key)?;
    let signing_key = pkey::PKey::from_rsa(signing_key)?;

    // Requirement from RFC 7518
    if signing_key.bits() < 2048 {
        fail!(ErrorKind::InvalidKey, "The key for signing is required to have at least 2048 bits.");
    }

    let mut signer = sign::Signer::new(algo, &signing_key)?;
    signer.set_rsa_padding(rsa::Padding::PKCS1)?;
    signer.update(input.as_bytes())?;
    let signature = signer.sign_to_vec()?;
    Ok(base64::encode_config(&signature, base64::URL_SAFE_NO_PAD))
}

/// Creates a signature using a RSA PSS algorithm.
///
/// # Arguments
/// * `algo` - The algorithm to use for signing
/// * `key` - The key for signing the data; must be a PEM encoded RSA private key
/// * `input` - The data to sign
/// # Returns
/// The Base64 encoded signature in a String if successful, an error type
/// otherwise
/// # Errors
/// Returns an error if specifying a signature algorithm that is not based on
/// RSA PSS or if OpenSSL fails to parse the input key as PEM encoded
/// private key.
fn sign_rsa_pss(algo: JsonWebAlgorithm, key: &[u8], input: &str) -> Result<String> {
    let algo = match algo {
        JsonWebAlgorithm::PS256 => hash::MessageDigest::sha256(),
        JsonWebAlgorithm::PS384 => hash::MessageDigest::sha384(),
        JsonWebAlgorithm::PS512 => hash::MessageDigest::sha512(),
        _                       => fail!(ErrorKind::UnkownAlgorithm, "The requested algorithm is not a flavor of RSA with PSS Padding.")
    };

    let signing_key = rsa::Rsa::private_key_from_pem(key)?;
    let signing_key = pkey::PKey::from_rsa(signing_key)?;

    // Requirement from RFC 7518
    if signing_key.bits() < 2048 {
        fail!(ErrorKind::InvalidKey, "The key for signing is required to have at least 2048 bits.");
    }

    let mut signer = sign::Signer::new(algo, &signing_key)?;
    signer.set_rsa_padding(rsa::Padding::PKCS1_PSS)?;
    signer.set_rsa_pss_saltlen(sign::RsaPssSaltlen::DIGEST_LENGTH)?;    // as described in RFC 7518
    signer.set_rsa_mgf1_md(algo)?;
    signer.update(input.as_bytes())?;
    let signature = signer.sign_to_vec()?;
    Ok(base64::encode_config(&signature, base64::URL_SAFE_NO_PAD))
}

#[cfg(not(feature = "no-ecdsa"))]
/// Creates a signature using a ECDSA algorithm with fixed length.
///
/// # Arguments
/// * `algo` - The algorithm to use for signing
/// * `key` - The key for signing the data in PEM format
/// * `input` - The data to sign
/// # Returns
/// The Base64 encoded signature in a String if successful, an error type
/// otherwise
/// # Errors
/// Returns an error in any of the following cases:
/// * `algo` is not a supported flavor of ECDSA
/// * the private key could not be parsed as PEM encoded private ECDSA key
/// * the private key's curve degree does not match the degree expected for the chosen `algo`
/// * the curve used to create the private key is not supported (not NIST P-256 or P-384)
/// * either hashing of the input data or signing the hash fails
fn sign_ecdsa(algo: JsonWebAlgorithm, key: &[u8], input: &str) -> Result<String> {

    // NIST P-256 and P-384 are called prime256v1 and secp384r1 in OpenSSL
    let (hash_algo, req_octets, req_degree, req_curve) = match algo {
        JsonWebAlgorithm::ES256 => (hash::MessageDigest::sha256(), 32usize, 256, Nid::X9_62_PRIME256V1),
        JsonWebAlgorithm::ES384 => (hash::MessageDigest::sha384(), 48usize, 384, Nid::SECP384R1),
        JsonWebAlgorithm::ES512 => (hash::MessageDigest::sha512(), 66usize, 521, Nid::SECP521R1),
        _                       => fail!(ErrorKind::UnkownAlgorithm, "The requested algorithm is not a supported flavor of ECDSA.")
    };
    let private_key = ec::EcKey::private_key_from_pem(key)?;
    let private_key_group = private_key.group();

    if private_key_group.degree() != req_degree {
        fail!(ErrorKind::InvalidKey, format!("Expected an ECDSA key with a degree of {}.", req_degree));
    }

    let private_key_curve = private_key_group.curve_name().ok_or(
        Error::new(ErrorKind::InvalidKey, "Failed to get name of elliptic curve from key.")
    )?;
    if private_key_curve != req_curve {
        fail!(ErrorKind::InvalidKey, format!("Expected a key for NIST P-256 or P-384, but got {}.", Nid::long_name(&private_key_curve).unwrap_or("")))
    }

    // we use the low level bindings here because we need r and s directly; with the high level interface we get a
    // ASN.1 object that we need to parse which is cumbersome
    let data = hash::hash(hash_algo, input.as_bytes())?;
    let signature = EcdsaSig::sign(&data, &private_key)?;
    let (mut r, mut s) = (signature.r().to_vec(), signature.s().to_vec());

    // left pad the binary vectors
    while r.len() < req_octets {
        r.insert(0, 0x00u8);
    }
    while s.len() < req_octets {
        s.insert(0, 0x00u8);
    }

    // concatenate r + s and return them after Base64 encoding
    r.append(&mut s);
    Ok(base64::encode_config(&r, base64::URL_SAFE_NO_PAD))
}

/// Verifies a signature created using a HMAC algorithm.
///
/// # Arguments
/// * `algo` - The algorithm to create the verification signature with
/// * `key` - The key used to verify the signature with
/// * `input` - The input to create the verification signature on
/// * `signature` - The Base64 encoded signature to verify against
/// # Returns
/// A boolean indicating verification success (`true`) or failure (`false`)
/// success, or an error if the specified algorithm is not based on a HMAC
/// # Errors
/// Returns an error type if the specified algorithm is not based on a HMAC.
fn verify_hmac(algo: JsonWebAlgorithm, key: &[u8], input: &str, signature: &str) -> Result<bool> {
    // sadly, in rust-openssl we cannot use sign::Verifier for HMACs (https://docs.rs/openssl/0.10.20/openssl/sign/index.html),
    // so we simply calc the new HMAC and compare them
    let new_sig = sign_hmac(algo, key, input)?;

    // yeah, memcmp::eq panics, if both signatures are not equally long (which may happen if comparing signatures created
    // with different HMAC algorithms), so we early return; this is not a timing attack, because the length of the signatures
    // depends on the Hash functions which is public information (see https://codahale.com/a-lesson-in-timing-attacks/)
    if new_sig.len() != signature.len() {
        return Ok(false);
    }

    Ok(openssl::memcmp::eq(new_sig.as_bytes(), signature.as_bytes()))   // this version of memcmp is resistant to timing attacks
}

/// Verifies a signature creating using the RSA PKCS#1 1.5 algorithm.
///
/// # Arguments
/// * `algo` - The algorithm to create the verification signature with
/// * `key` - The key used to verify the signature with
/// * `input` - The input to create the verification signature on
/// * `signature` - The Base64 encoded signature to verify against
/// # Returns
/// A boolean indicating verification success (`true`) or failure (`false`)
/// success, or an error type on failure
/// # Errors
/// Returns an error if
/// * the signature value could not be Base64 decoded
/// * the specified algorithm is not a variant of RSA PKCS#1
/// * `key` is not a PEM encoded public key or has an invalid lenght
/// * the verification of the signature fails with an error
fn verify_rsa_pkcs(algo: JsonWebAlgorithm, key: &[u8], input: &str, signature: &str) -> Result<bool> {
    let signature = base64::decode_config(signature, base64::URL_SAFE_NO_PAD)?;
    let algo = match algo {
        JsonWebAlgorithm::RS256 => hash::MessageDigest::sha256(),
        JsonWebAlgorithm::RS384 => hash::MessageDigest::sha384(),
        JsonWebAlgorithm::RS512 => hash::MessageDigest::sha512(),
        _                       => fail!(ErrorKind::UnkownAlgorithm, "The requested algorithm is not a flavor of RSA with PSS Padding.")
    };

    let key = rsa::Rsa::public_key_from_pem(key)?;
    let key = pkey::PKey::from_rsa(key)?;

    // Requirement from RFC 7518
    if key.bits() < 2048 {
        fail!(ErrorKind::InvalidKey, "The key for verification is required to have at least 2048 bits.");
    }

    let mut verifier = sign::Verifier::new(algo, &key)?;
    verifier.set_rsa_padding(rsa::Padding::PKCS1)?;
    verifier.update(input.as_bytes())?;
    verifier.verify(&signature).map_err(|e| Error::new_without_msg(ErrorKind::OpenSSLError(e)))
}

/// Verifies a signature creating using the RSA PSS algorithm.
///
/// # Arguments
/// * `algo` - The algorithm to create the verification signature with
/// * `key` - The key used to verify the signature with
/// * `input` - The input to create the verification signature on
/// * `signature` - The Base64 encoded signature to verify against
/// # Returns
/// A boolean indicating verification success (`true`) or failure (`false`)
/// success, or an error type on failure
/// # Errors
/// Returns an error if
/// * the signature value could not be Base64 decoded
/// * the specified algorithm is not a variant of RSA PSS
/// * `key` is not a PEM encoded public key or has an invalid lenght
/// * the verification of the signature fails with an error
fn verify_rsa_pss(algo: JsonWebAlgorithm, key: &[u8], input: &str, signature: &str) -> Result<bool> {
    let signature = base64::decode_config(signature, base64::URL_SAFE_NO_PAD)?;
    let algo = match algo {
        JsonWebAlgorithm::PS256 => hash::MessageDigest::sha256(),
        JsonWebAlgorithm::PS384 => hash::MessageDigest::sha384(),
        JsonWebAlgorithm::PS512 => hash::MessageDigest::sha512(),
        _                       => fail!(ErrorKind::UnkownAlgorithm, "The requested algorithm is not a flavor of RSA with PSS Padding.")
    };

    let key = rsa::Rsa::public_key_from_pem(key)?;
    let key = pkey::PKey::from_rsa(key)?;

    // Requirement from RFC 7518
    if key.bits() < 2048 {
        fail!(ErrorKind::InvalidKey, "The key for verification is required to have at least 2048 bits.");
    }

    let mut verifier = sign::Verifier::new(algo, &key)?;
    verifier.set_rsa_padding(rsa::Padding::PKCS1_PSS)?;
    verifier.set_rsa_pss_saltlen(sign::RsaPssSaltlen::DIGEST_LENGTH)?;
    verifier.set_rsa_mgf1_md(algo)?;
    verifier.update(input.as_bytes())?;
    verifier.verify(&signature).map_err(|e| Error::new_without_msg(ErrorKind::OpenSSLError(e)))
}

#[cfg(not(feature = "no-ecdsa"))]
/// Verifies a signature created using a ECDSA algorithm with fixed length.
///
/// # Arguments
/// * `algo` - The algorithm to create the verification signature with
/// * `key` - The key used to verify the signature with
/// * `input` - The input to create the verification signature on
/// * `signature` - The Base64 encoded signature to verify against
/// # Returns
/// A boolean indicating verification success (`true`) or failure (`false`)
/// success, or an error type on failure
/// # Errors
/// Returns an error in any of the following cases:
/// * `signature` is not a Base64 encoded string
/// * `algo` is not a supported flavor of ECDSA
/// * the private key could not be parsed as PEM encoded public ECDSA key
/// * the public key's curve degree does not match the degree expected for the chosen `algo`
/// * the curve used to create the public key is not supported (not NIST P-256 or P-384)
/// * either hashing of the input data or signing the hash fails
fn verify_ecdsa(algo: JsonWebAlgorithm, key: &[u8], input: &str, signature: &str) -> Result<bool> {
    let signature = base64::decode_config(signature, base64::URL_SAFE_NO_PAD)?;

    let (hash_algo, req_octets, req_degree, req_curve) = match algo {
        JsonWebAlgorithm::ES256 => (hash::MessageDigest::sha256(), 32usize, 256, Nid::X9_62_PRIME256V1),
        JsonWebAlgorithm::ES384 => (hash::MessageDigest::sha384(), 48usize, 384, Nid::SECP384R1),
        JsonWebAlgorithm::ES512 => (hash::MessageDigest::sha512(), 66usize, 521, Nid::SECP521R1),
        _                       => fail!(ErrorKind::UnkownAlgorithm, "The requested algorithm is not a supported flavor of ECDSA.")
    };

    let public_key = pkey::PKey::public_key_from_pem(key)?;
    let public_key: ec::EcKey<pkey::Public> = public_key.ec_key()?;

    let public_key_group = public_key.group();
    if public_key_group.degree() != req_degree {
        fail!(ErrorKind::InvalidKey, format!("Expected an ECDSA key with a degree of {}.", req_degree));
    }

    let public_key_curve = public_key_group.curve_name().ok_or(
        Error::new(ErrorKind::InvalidKey, "Failed to get name of elliptic curve from key.")
    )?;
    if public_key_curve != req_curve {
        fail!(ErrorKind::InvalidKey, format!("Expected a key for NIST P-256 or P-384, but got {}.", Nid::long_name(&public_key_curve).unwrap_or("")))
    }

    if signature.len() != (req_octets * 2) {
        fail!(ErrorKind::InvalidSignature, "The signature has an invalid length.");
    }

    let signature = signature.split_at(signature.len() / 2);
    let (r, s) = (BigNum::from_slice(signature.0)?, BigNum::from_slice(signature.1)?);

    let signature = EcdsaSig::from_private_components(r, s)?;
    let data = hash::hash(hash_algo, input.as_bytes())?;
    signature.verify(&data, &public_key).map_err(|e| Error::new_without_msg(ErrorKind::OpenSSLError(e)))
}

/// Creates and returns a digital signature on some input using a JSON Web
/// Algorithm.
///
/// # Arguments
/// * `input` - The input data to create a signature for
/// * `key` - The key to use for creation of the signature
/// * `algorithm` - The algorithm to use for creation of the signature
/// # Returns
/// The signature of `input` using the specified algorithm or an empty string
/// if the algorithm was `JsonWebAlgorithm::None` on success. Returns an error
/// on failure.
/// # Errors
/// Returns an error if the creation of the signature fails. The error type
/// itself can be inspected to get more information on the cause.
/// # Example
/// ```rust
/// # use jwt_rs::crypto::{sign, JsonWebAlgorithm};
/// let key = b"mysupersecretkey";
/// let signature = sign("Hello World", key, JsonWebAlgorithm::HS256);
/// println!("{:?}", signature);
/// ```
pub fn sign(input: &str, key: &[u8], algorithm: JsonWebAlgorithm) -> Result<String> {
    match algorithm {
        JsonWebAlgorithm::HS256 | JsonWebAlgorithm::HS384 | JsonWebAlgorithm::HS512 => sign_hmac(algorithm, key, input),
        JsonWebAlgorithm::RS256 | JsonWebAlgorithm::RS384 | JsonWebAlgorithm::RS512 => sign_rsa_pkcs(algorithm, key, input),
        JsonWebAlgorithm::PS256 | JsonWebAlgorithm::PS384 | JsonWebAlgorithm::PS512 => sign_rsa_pss(algorithm, key, input),
        #[cfg(not(feature = "no-ecdsa"))]
        JsonWebAlgorithm::ES256 | JsonWebAlgorithm::ES384 | JsonWebAlgorithm::ES512 => sign_ecdsa(algorithm, key, input),
        JsonWebAlgorithm::None  => Ok(String::new()),
    }
}

/// Verifies a digital signature create for some input using a Json Web
/// Algorithm.
///
/// # Arguments
/// * `signature` - The signature to verify
/// * `input` - The input data to verify the signature for
/// * `key` - The key to use for signature verification
/// * `algorithm` - The algorithm to use for signature verification
/// # Returns
/// The signature of `input` using the specified algorithm or an empty string
/// if the algorithm was `JsonWebAlgorithm::None` on success. Returns an error
/// on failure.
/// # Errors
/// Returns an error if the creation of the signature fails. The error type
/// itself can be inspected to get more information on the cause.
/// # Example
/// ```rust
/// # use jwt_rs::crypto::{sign, JsonWebAlgorithm};
/// let key = b"mysupersecretkey";
/// let signature = sign("Hello World", key, JsonWebAlgorithm::HS256);
/// println!("{:?}", signature);
/// ```
pub fn verify(signature: &str, input: &str, key: &[u8], algorithm: JsonWebAlgorithm) -> Result<bool> {
    match algorithm {
        JsonWebAlgorithm::None if signature.is_empty()  => Ok(true),
        JsonWebAlgorithm::HS256 | JsonWebAlgorithm::HS384 | JsonWebAlgorithm::HS512 => verify_hmac(algorithm, key, input, signature),
        JsonWebAlgorithm::RS256 | JsonWebAlgorithm::RS384 | JsonWebAlgorithm::RS512 => verify_rsa_pkcs(algorithm, key, input, signature),
        JsonWebAlgorithm::PS256 | JsonWebAlgorithm::PS384 | JsonWebAlgorithm::PS512 => verify_rsa_pss(algorithm, key, input, signature),
        #[cfg(not(feature = "no-ecdsa"))]
        JsonWebAlgorithm::ES256 | JsonWebAlgorithm::ES384 | JsonWebAlgorithm::ES512 => verify_ecdsa(algorithm, key, input, signature),
        _   => Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    const RSA_PUBLIC_KEY_FILE: &'static str = "testdata/rsa_pub.pem";
    const RSA_PRIVATE_KEY_FILE: &'static str = "testdata/rsa_priv.pem";
    const RSA_OTHER_PUBLIC_KEY_FILE: &'static str = "testdata/rsa_other_pub.pem";
    const RSA_OTHER_PRIVATE_KEY_FILE: &'static str = "testdata/rsa_other_priv.pem";

    #[cfg(not(feature = "no-ecdsa"))]
    const EC_PUBLIC_KEY_FILE: &'static str = "testdata/ec_pub.pem";
    #[cfg(not(feature = "no-ecdsa"))]
    const EC_PRIVATE_KEY_FILE: &'static str = "testdata/ec_priv.pem";
    #[cfg(not(feature = "no-ecdsa"))]
    const EC_OTHER_PUBLIC_KEY_FILE: &'static str = "testdata/ec_other_pub.pem";
    #[cfg(not(feature = "no-ecdsa"))]
    const EC_OTHER_PRIVATE_KEY_FILE: &'static str = "testdata/ec_other_priv.pem";
    #[cfg(not(feature = "no-ecdsa"))]
    const EC_OTHER_CURVE_PUBLIC_KEY_FILE: &'static str = "testdata/ec_other_curve_pub.pem";
    #[cfg(not(feature = "no-ecdsa"))]
    const EC_OTHER_CURVE_PRIVATE_KEY_FILE: &'static str = "testdata/ec_other_curve_priv.pem";
    #[cfg(not(feature = "no-ecdsa"))]
    const EC_521_PUBLIC_KEY_FILE: &'static str = "testdata/ec_521_pub.pem";
    #[cfg(not(feature = "no-ecdsa"))]
    const EC_521_PRIVATE_KEY_FILE: &'static str = "testdata/ec_521_priv.pem";

    // A short helper method for reading and returning the plain contents of a file
    fn read_content_from_file(filename: &str) -> std::io::Result<String> {
        let mut file = std::fs::File::open(filename)?;
        let mut content = String::new();
        file.read_to_string(&mut content)?;
        Ok(content)
    }

    #[test]
    fn sign_verify_none() -> Result<()> {
        let message = "Hello World";
        let signature = sign(message, b"doesnmatter", JsonWebAlgorithm::None)?;
        assert!(signature.is_empty());
        assert!(verify(&signature, message, b"doesnotmattereither", JsonWebAlgorithm::None)?);
        Ok(())
    }

    #[test]
    fn sign_verify_different_algo() -> Result<()> {
        let message = "Hello World";
        let signature = sign(message, b"secret", JsonWebAlgorithm::HS256)?;
        assert!(!signature.is_empty());
        assert!(!verify(&signature, message, b"doesntmatter", JsonWebAlgorithm::None)?);
        Ok(())
    }

    mod hmac {
        use super::*;

        #[test]
        fn success() -> Result<()> {
            let key = b"mysupersecretkey";
            let message = "Hello World";
            let signature = sign(message, key, JsonWebAlgorithm::HS256)?;
            assert!(!signature.is_empty());
            assert!(signature.is_ascii());
            assert!(verify(&signature, message, key, JsonWebAlgorithm::HS256)?);
            Ok(())
        }

        #[test]
        fn fail_stripped_signature() -> Result<()> {
            let key = b"secret";
            let message = "Hello World";
            let signature = sign(message, key, JsonWebAlgorithm::HS256)?;
            assert!(!signature.is_empty());
            assert!(signature.is_ascii());
            assert!(!verify("", message, key, JsonWebAlgorithm::HS256)?);
            Ok(())
        }

        #[test]
        fn fail_wrong_key() -> Result<()> {
            let key = b"mysupersecretkey";
            let message = "Hello World";
            let signature = sign(message, key, JsonWebAlgorithm::HS256)?;
            let v = verify(&signature, message, b"someotherkey", JsonWebAlgorithm::HS256);
            assert!(v.is_ok());
            assert!(!v.unwrap());
            Ok(())
        }

        #[test]
        fn fail_wrong_msg() -> Result<()> {
            let key = b"mysupersecretkey";
            let message = "Hello World";
            let signature = sign(message, key, JsonWebAlgorithm::HS256)?;
            let v = verify(&signature, "Hello Worlb", key, JsonWebAlgorithm::HS256);
            assert!(v.is_ok());
            assert!(!v.unwrap());
            Ok(())
        }

        #[test]
        fn fail_wrong_length_algo() -> Result<()> {
            let key = b"mysupersecretkey";
            let message = "Hello World";
            let signature = sign(message, key, JsonWebAlgorithm::HS256)?;
            let v = verify(&signature, message, key, JsonWebAlgorithm::HS384);
            assert!(v.is_ok());
            assert!(!v.unwrap());
            Ok(())
        }

        #[test]
        fn fail_wrong_algo() -> Result<()> {
            let key = b"mysupersecretkey";
            let message = "Hello World";
            let signature = sign(message, key, JsonWebAlgorithm::HS256)?;
            let v = verify(&signature, message, key, JsonWebAlgorithm::RS256);
            assert!(v.is_err());
            let v = verify(&signature, message, key, JsonWebAlgorithm::PS256);
            assert!(v.is_err());
            #[cfg(not(feature = "no-ecdsa"))]
            assert!(verify(&signature, message, key, JsonWebAlgorithm::ES256).is_err());
            Ok(())
        }
    }

    mod rsa_pkcs {
        use super::*;

        lazy_static! {
            static ref PUBLIC_KEY: String = read_content_from_file(RSA_PUBLIC_KEY_FILE).expect("Failed to read RSA public key for unit tests!");
            static ref PRIVATE_KEY: String = read_content_from_file(RSA_PRIVATE_KEY_FILE).expect("Failed to read RSA private key for unit tests!");
            static ref OTHER_PUBLIC_KEY: String = read_content_from_file(RSA_OTHER_PUBLIC_KEY_FILE).expect("Failed to read other RSA public key for unit tests!");
            static ref OTHER_PRIVATE_KEY: String = read_content_from_file(RSA_OTHER_PRIVATE_KEY_FILE).expect("Failed to read other RSA private key for unit tests!");
        }

        #[test]
        fn success() -> Result<()> {
            let message = "Hello World";
            let signature = sign(message, PRIVATE_KEY.as_bytes(), JsonWebAlgorithm::RS256)?;
            assert!(!signature.is_empty());
            assert!(signature.is_ascii());
            assert!(verify(&signature, message, PUBLIC_KEY.as_bytes(), JsonWebAlgorithm::RS256)?);
            Ok(())
        }

        #[test]
        fn fail_stripped_signature() -> Result<()> {
            let message = "Hello World";
            let signature = sign(message, PRIVATE_KEY.as_bytes(), JsonWebAlgorithm::RS256)?;
            assert!(!signature.is_empty());
            assert!(signature.is_ascii());
            assert!(!verify("", message, PUBLIC_KEY.as_bytes(), JsonWebAlgorithm::RS256)?);
            Ok(())
        }

        #[test]
        fn fail_wrong_verification_key() -> Result<()> {
            let message = "Hello World";
            let signature = sign(message, PRIVATE_KEY.as_bytes(), JsonWebAlgorithm::RS256)?;
            let v = verify(&signature, message, OTHER_PUBLIC_KEY.as_bytes(), JsonWebAlgorithm::RS256);
            assert!(v.is_ok());
            assert!(!v.unwrap());
            Ok(())
        }

        #[test]
        fn fail_wrong_signing_key() -> Result<()> {
            let message = "Hello World";
            let signature = sign(message, OTHER_PRIVATE_KEY.as_bytes(), JsonWebAlgorithm::RS256)?;
            let v = verify(&signature, message, PUBLIC_KEY.as_bytes(), JsonWebAlgorithm::RS256);
            assert!(v.is_ok());
            assert!(!v.unwrap());
            Ok(())
        }

        #[test]
        fn fail_wrong_msg() -> Result<()> {
            let signature = sign("Hello World", PRIVATE_KEY.as_bytes(), JsonWebAlgorithm::RS256)?;
            let v = verify(&signature, "Hello Worlb", PUBLIC_KEY.as_bytes(), JsonWebAlgorithm::RS256);
            assert!(v.is_ok());
            assert!(!v.unwrap());
            Ok(())
        }

        #[test]
        fn fail_wrong_length_algo() -> Result<()> {
            let message = "Hello World";
            let signature = sign(message, PRIVATE_KEY.as_bytes(), JsonWebAlgorithm::RS256)?;
            let v = verify(&signature, message, PUBLIC_KEY.as_bytes(), JsonWebAlgorithm::RS384);
            assert!(v.is_ok());
            assert!(!v.unwrap());
            Ok(())
        }

        #[test]
        fn fail_wrong_algo() -> Result<()> {
            let message = "Hello World";
            let signature = sign(message, PRIVATE_KEY.as_bytes(), JsonWebAlgorithm::RS256)?;

            #[cfg(not(feature = "no-ecdsa"))]
            assert!(verify(&signature, message, PUBLIC_KEY.as_bytes(), JsonWebAlgorithm::ES256).is_err());

            let v = verify(&signature, message, PUBLIC_KEY.as_bytes(), JsonWebAlgorithm::PS256);
            assert!(v.is_ok());
            assert!(!v.unwrap());
            let v = verify(&signature, message, PUBLIC_KEY.as_bytes(), JsonWebAlgorithm::HS256);
            assert!(v.is_ok());
            assert!(!v.unwrap());
            Ok(())
        }
    }

    mod rsa_pss {
        use super::*;

        lazy_static! {
            static ref PUBLIC_KEY: String = read_content_from_file(RSA_PUBLIC_KEY_FILE).expect("Failed to read RSA public key for unit tests!");
            static ref PRIVATE_KEY: String = read_content_from_file(RSA_PRIVATE_KEY_FILE).expect("Failed to read RSA private key for unit tests!");
            static ref OTHER_PUBLIC_KEY: String = read_content_from_file(RSA_OTHER_PUBLIC_KEY_FILE).expect("Failed to read other RSA public key for unit tests!");
            static ref OTHER_PRIVATE_KEY: String = read_content_from_file(RSA_OTHER_PRIVATE_KEY_FILE).expect("Failed to read other RSA private key for unit tests!");
        }

        #[test]
        fn success() -> Result<()> {
            let message = "Hello World";
            let signature = sign(message, PRIVATE_KEY.as_bytes(), JsonWebAlgorithm::PS256)?;
            assert!(!signature.is_empty());
            assert!(signature.is_ascii());
            assert!(verify(&signature, message, PUBLIC_KEY.as_bytes(), JsonWebAlgorithm::PS256)?);
            Ok(())
        }

        #[test]
        fn fail_stripped_signature() -> Result<()> {
            let message = "Hello World";
            let signature = sign(message, PRIVATE_KEY.as_bytes(), JsonWebAlgorithm::PS256)?;
            assert!(!signature.is_empty());
            assert!(signature.is_ascii());
            assert!(!verify("", message, PUBLIC_KEY.as_bytes(), JsonWebAlgorithm::PS256)?);
            Ok(())
        }

        #[test]
        fn fail_wrong_verification_key() -> Result<()> {
            let message = "Hello World";
            let signature = sign(message, PRIVATE_KEY.as_bytes(), JsonWebAlgorithm::PS256)?;
            let v = verify(&signature, message, OTHER_PUBLIC_KEY.as_bytes(), JsonWebAlgorithm::PS256);
            assert!(v.is_ok());
            assert!(!v.unwrap());
            Ok(())
        }

        #[test]
        fn fail_wrong_signing_key() -> Result<()> {
            let message = "Hello World";
            let signature = sign(message, OTHER_PRIVATE_KEY.as_bytes(), JsonWebAlgorithm::PS256)?;
            let v = verify(&signature, message, PUBLIC_KEY.as_bytes(), JsonWebAlgorithm::PS256);
            assert!(v.is_ok());
            assert!(!v.unwrap());
            Ok(())
        }

        #[test]
        fn fail_wrong_msg() -> Result<()> {
            let signature = sign("Hello World", PRIVATE_KEY.as_bytes(), JsonWebAlgorithm::PS256)?;
            let v = verify(&signature, "Hello Worlb", PUBLIC_KEY.as_bytes(), JsonWebAlgorithm::PS256);
            assert!(v.is_ok());
            assert!(!v.unwrap());
            Ok(())
        }

        #[test]
        fn fail_wrong_length_algo() -> Result<()> {
            let message = "Hello World";
            let signature = sign(message, PRIVATE_KEY.as_bytes(), JsonWebAlgorithm::PS256)?;
            let v = verify(&signature, message, PUBLIC_KEY.as_bytes(), JsonWebAlgorithm::PS384);
            assert!(v.is_ok());
            assert!(!v.unwrap());
            Ok(())
        }

        #[test]
        fn fail_wrong_algo() -> Result<()> {
            let message = "Hello World";
            let signature = sign(message, PRIVATE_KEY.as_bytes(), JsonWebAlgorithm::PS256)?;

            #[cfg(not(feature = "no-ecdsa"))]
            assert!(verify(&signature, message, PUBLIC_KEY.as_bytes(), JsonWebAlgorithm::ES256).is_err());

            let v = verify(&signature, message, PUBLIC_KEY.as_bytes(), JsonWebAlgorithm::RS256);
            assert!(v.is_ok());
            assert!(!v.unwrap());
            let v = verify(&signature, message, PUBLIC_KEY.as_bytes(), JsonWebAlgorithm::HS256);
            assert!(v.is_ok());
            assert!(!v.unwrap());
            Ok(())
        }
    }

    #[cfg(not(feature = "no-ecdsa"))]
    mod ecdsa {
        use super::*;

        lazy_static! {
            static ref PUBLIC_KEY: String = read_content_from_file(EC_PUBLIC_KEY_FILE).expect("Failed to read ECDSA public key for unit tests!");
            static ref PRIVATE_KEY: String = read_content_from_file(EC_PRIVATE_KEY_FILE).expect("Failed to read ECDSA private key for unit tests!");
            static ref OTHER_PUBLIC_KEY: String = read_content_from_file(EC_OTHER_PUBLIC_KEY_FILE).expect("Failed to read other ECDSA public key for unit tests!");
            static ref OTHER_PRIVATE_KEY: String = read_content_from_file(EC_OTHER_PRIVATE_KEY_FILE).expect("Failed to read other ECDSA private key for unit tests!");
            static ref OTHER_CURVE_PUBLIC_KEY: String = read_content_from_file(EC_OTHER_CURVE_PUBLIC_KEY_FILE).expect("Failed to read other ECDSA private key for unit tests!");
            static ref OTHER_CURVE_PRIVATE_KEY: String = read_content_from_file(EC_OTHER_CURVE_PRIVATE_KEY_FILE).expect("Failed to read other ECDSA private key for unit tests!");
        }

        #[test]
        fn success() -> Result<()> {
            let message = "Hello World";
            let signature = sign(message, PRIVATE_KEY.as_bytes(), JsonWebAlgorithm::ES256)?;
            assert!(!signature.is_empty());
            assert!(signature.is_ascii());
            assert!(verify(&signature, message, PUBLIC_KEY.as_bytes(), JsonWebAlgorithm::ES256)?);
            Ok(())
        }

        #[test]
        fn fail_stripped_signature() -> Result<()> {
            let message = "Hello World";
            let signature = sign(message, PRIVATE_KEY.as_bytes(), JsonWebAlgorithm::ES256)?;
            assert!(!signature.is_empty());
            assert!(signature.is_ascii());
            assert!(verify("", message, PUBLIC_KEY.as_bytes(), JsonWebAlgorithm::ES256).is_err());
            Ok(())
        }

        #[test]
        fn fail_wrong_verification_key() -> Result<()> {
            let message = "Hello World";
            let signature = sign(message, PRIVATE_KEY.as_bytes(), JsonWebAlgorithm::ES256)?;
            let v = verify(&signature, message, OTHER_PUBLIC_KEY.as_bytes(), JsonWebAlgorithm::ES256);
            assert!(v.is_ok());
            assert!(!v.unwrap());
            Ok(())
        }

        #[test]
        fn fail_wrong_curve() -> Result<()> {
            let message = "Hello World";
            let signature = sign(message, PRIVATE_KEY.as_bytes(), JsonWebAlgorithm::ES256)?;
            let v = verify(&signature, message, OTHER_CURVE_PUBLIC_KEY.as_bytes(), JsonWebAlgorithm::ES256);
            assert!(v.is_err());
            Ok(())
        }

        #[test]
        fn fail_wrong_signing_key() -> Result<()> {
            let message = "Hello World";
            let signature = sign(message, OTHER_PRIVATE_KEY.as_bytes(), JsonWebAlgorithm::ES256)?;
            let v = verify(&signature, message, PUBLIC_KEY.as_bytes(), JsonWebAlgorithm::ES256);
            assert!(v.is_ok());
            assert!(!v.unwrap());
            Ok(())
        }

        #[test]
        fn fail_wrong_msg() -> Result<()> {
            let signature = sign("Hello World", PRIVATE_KEY.as_bytes(), JsonWebAlgorithm::ES256)?;
            let v = verify(&signature, "Hello Worlb", PUBLIC_KEY.as_bytes(), JsonWebAlgorithm::ES256);
            assert!(v.is_ok());
            assert!(!v.unwrap());
            Ok(())
        }

        #[test]
        fn fail_wrong_length_algo() -> Result<()> {
            let message = "Hello World";
            let signature = sign(message, PRIVATE_KEY.as_bytes(), JsonWebAlgorithm::ES256)?;
            let v = verify(&signature, message, PUBLIC_KEY.as_bytes(), JsonWebAlgorithm::ES384);
            assert!(v.is_err());
            Ok(())
        }

        #[test]
        fn fail_wrong_algo() -> Result<()> {
            let message = "Hello World";
            let signature = sign(message, PRIVATE_KEY.as_bytes(), JsonWebAlgorithm::ES256)?;
            let v = verify(&signature, message, PUBLIC_KEY.as_bytes(), JsonWebAlgorithm::PS256);
            assert!(v.is_err());
            let v = verify(&signature, message, PUBLIC_KEY.as_bytes(), JsonWebAlgorithm::RS256);
            assert!(v.is_err());
            let v = verify(&signature, message, PUBLIC_KEY.as_bytes(), JsonWebAlgorithm::HS256);
            assert!(v.is_ok());
            assert!(!v.unwrap());
            Ok(())
        }
    }

    #[cfg(not(feature = "no-ecdsa"))]
    mod ecdsa_p521 {
        use super::*;

        lazy_static! {
            static ref PUBLIC_KEY: String = read_content_from_file(EC_521_PUBLIC_KEY_FILE).expect("Failed to read ECDSA public key for unit tests!");
            static ref PRIVATE_KEY: String = read_content_from_file(EC_521_PRIVATE_KEY_FILE).expect("Failed to read ECDSA private key for unit tests!");
            static ref OTHER_PUBLIC_KEY: String = read_content_from_file(EC_OTHER_PUBLIC_KEY_FILE).expect("Failed to read other ECDSA public key for unit tests!");
            static ref OTHER_PRIVATE_KEY: String = read_content_from_file(EC_OTHER_PRIVATE_KEY_FILE).expect("Failed to read other ECDSA private key for unit tests!");
            static ref OTHER_CURVE_PUBLIC_KEY: String = read_content_from_file(EC_OTHER_CURVE_PUBLIC_KEY_FILE).expect("Failed to read other ECDSA private key for unit tests!");
            static ref OTHER_CURVE_PRIVATE_KEY: String = read_content_from_file(EC_OTHER_CURVE_PRIVATE_KEY_FILE).expect("Failed to read other ECDSA private key for unit tests!");
        }

        #[test]
        fn success() -> Result<()> {
            let message = "Hello World";
            let signature = sign(message, PRIVATE_KEY.as_bytes(), JsonWebAlgorithm::ES512)?;
            assert!(!signature.is_empty());
            assert!(signature.is_ascii());
            assert!(verify(&signature, message, PUBLIC_KEY.as_bytes(), JsonWebAlgorithm::ES512)?);
            Ok(())
        }

        #[test]
        fn fail_stripped_signature() -> Result<()> {
            let message = "Hello World";
            let signature = sign(message, PRIVATE_KEY.as_bytes(), JsonWebAlgorithm::ES512)?;
            assert!(!signature.is_empty());
            assert!(signature.is_ascii());
            assert!(verify("", message, PUBLIC_KEY.as_bytes(), JsonWebAlgorithm::ES512).is_err());
            Ok(())
        }

        #[test]
        fn fail_wrong_verification_key() -> Result<()> {
            let message = "Hello World";
            let signature = sign(message, PRIVATE_KEY.as_bytes(), JsonWebAlgorithm::ES512)?;
            let v = verify(&signature, message, OTHER_PUBLIC_KEY.as_bytes(), JsonWebAlgorithm::ES256);
            assert!(v.is_err());
            Ok(())
        }

        #[test]
        fn fail_wrong_curve() -> Result<()> {
            let message = "Hello World";
            let signature = sign(message, PRIVATE_KEY.as_bytes(), JsonWebAlgorithm::ES512)?;
            let v = verify(&signature, message, OTHER_CURVE_PUBLIC_KEY.as_bytes(), JsonWebAlgorithm::ES512);
            assert!(v.is_err());
            Ok(())
        }

        #[test]
        fn fail_wrong_signing_key() -> Result<()> {
            let message = "Hello World";
            let signature = sign(message, OTHER_PRIVATE_KEY.as_bytes(), JsonWebAlgorithm::ES256)?;
            let v = verify(&signature, message, PUBLIC_KEY.as_bytes(), JsonWebAlgorithm::ES512);
            assert!(v.is_err());
            Ok(())
        }

        #[test]
        fn fail_wrong_msg() -> Result<()> {
            let signature = sign("Hello World", PRIVATE_KEY.as_bytes(), JsonWebAlgorithm::ES512)?;
            let v = verify(&signature, "Hello Worlb", PUBLIC_KEY.as_bytes(), JsonWebAlgorithm::ES512);
            assert!(v.is_ok());
            assert!(!v.unwrap());
            Ok(())
        }

        #[test]
        fn fail_wrong_length_algo() -> Result<()> {
            let message = "Hello World";
            let signature = sign(message, PRIVATE_KEY.as_bytes(), JsonWebAlgorithm::ES512)?;
            let v = verify(&signature, message, PUBLIC_KEY.as_bytes(), JsonWebAlgorithm::ES384);
            assert!(v.is_err());
            Ok(())
        }

        #[test]
        fn fail_wrong_algo() -> Result<()> {
            let message = "Hello World";
            let signature = sign(message, PRIVATE_KEY.as_bytes(), JsonWebAlgorithm::ES512)?;
            let v = verify(&signature, message, PUBLIC_KEY.as_bytes(), JsonWebAlgorithm::PS256);
            assert!(v.is_err());
            let v = verify(&signature, message, PUBLIC_KEY.as_bytes(), JsonWebAlgorithm::RS256);
            assert!(v.is_err());
            let v = verify(&signature, message, PUBLIC_KEY.as_bytes(), JsonWebAlgorithm::HS256);
            assert!(v.is_ok());
            assert!(!v.unwrap());
            Ok(())
        }
    }
}
