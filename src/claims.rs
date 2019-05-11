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

//! Defines the set of registered JWT claims and methods for validating claims.

use serde_json::Value as JValue;
use serde::{Serialize, Deserialize, Deserializer,
    de::{Visitor, SeqAccess}};
use std::collections::HashMap;

use crate::errors::{JwtResult, JwtError};

/// Array containing the names of registred claims according to RFC 7519
pub const REGISTERED_CLAIM_NAMES: [&'static str; 7] = ["iss", "sub", "aud", "exp", "nbf", "iat", "jti"];

/// Structure containing all well-known registered claims according to RFC 7519
/// and a map for additional, custom claims.
/// The audience claim has to be set through the respective method of this struct.
/// # Example
/// ```rust
/// # use jwt_rs::Claims;
/// # use serde_json::json;
/// let mut claims = Claims::default();
/// claims.sub = Some("Foobar".to_string());
/// claims.iat = Some(42);
/// claims.set_audience(&"MyAudience");
/// claims.set_custom_claim("abc", &"XYZ");
///
/// // serialize claims
/// let s = serde_json::to_string(&claims).unwrap();
/// assert_eq!(s, "{\"sub\":\"Foobar\",\"aud\":\"MyAudience\",\"iat\":42,\"abc\":\"XYZ\"}");
///
/// // safe deserialization from JSON string
/// let s = "{\"sub\":\"Foobar\",\"aud\":[\"A\",\"B\"],\"iat\":1000,\"abc\":\"XYZ\"}";
/// let claims = serde_json::from_str::<Claims>(&s).unwrap();
/// assert_eq!(claims.iat.unwrap(), 1000);
/// assert!(claims.get_audience().is_some());
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Claims {
    /// The issuer claim according to RFC 7519 Section 4.1.1
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    /// The subject claim according to RFC 7519 Section 4.1.2
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    /// The audience claim according to RFC 7519 Section 4.1.3
    #[serde(skip_serializing_if = "Option::is_none", default, deserialize_with = "parse_option_aud")]
    aud: Option<JValue>,
    /// The audience claim according to RFC 7519 Section 4.1.4
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    /// The audience claim according to RFC 7519 Section 4.1.5
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,
    /// The audience claim according to RFC 7519 Section 4.1.6
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,
    /// The audience claim according to RFC 7519 Section 4.1.7
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    /// HashMap for custom claims that will be serialized and deserialized
    /// next to the registered ones; this is not public, as setting a key to
    /// a registered claim name will duplicate this claim which is not allowed
    #[serde(flatten, skip_serializing_if = "HashMap::is_empty")]
    custom: HashMap<String, JValue>,
}

/// Parses an optional JSON value by wrapping it and deserializing the wrapped
/// value using [parse_aud](fn.parse_aud.html).
/// Sadly, there is currently no well supported way to manually deserialize an
/// optional value using `deserialize_with`. The recommended method is wrapping
/// the optional value inside a struct and use the real deserialization function
/// on the wrapped value. See [this issue on GitHub](https://github.com/serde-rs/serde/issues/1444).
/// # Arguments
/// * `deserializer` - A generic deserializer of lifetime `de`
/// # Returns
/// An optional JSON value on success, an error type otherwise
/// # Errors
/// Returns an error if deserialization fails.
fn parse_option_aud<'de, D>(deserializer: D) -> Result<Option<JValue>, D::Error>
    where D: Deserializer<'de> {

    #[derive(Deserialize)]
    struct Wrapper(
        #[serde(deserialize_with = "parse_aud")]
        JValue,
    );

    let value = Option::deserialize(deserializer)?;
    Ok(value.map(|Wrapper(v)| v))
}

/// Parses an JSON value as a string or an array of strings.
/// # Arguments
/// * `deserializer` - A generic deserializer of lifetime `de`
/// # Returns
/// A JSON value on success (string or array of strings), an error type otherwise
/// # Errors
/// Returns an error if deserialization fails because of the input value not
/// being a string or an array of strings (or if serde decides to fail because
/// of some other issue).
fn parse_aud<'de, D>(deserializer: D) -> Result<JValue, D::Error> where D: Deserializer<'de> {
    struct StringOrArray;

    impl<'de> Visitor<'de> for StringOrArray {
        type Value = JValue;

        // description of the type(s) we are expecting
        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("string or array of strings")
        }

        // called when running across a str
        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> where E: serde::de::Error {
            self.visit_string(String::from(value))
        }

        // called when running across a owned String
        fn visit_string<E>(self, value: String) -> Result<Self::Value, E> where E: serde::de::Error {
            Ok(JValue::String(value))
        }

        // called when running across a sequence (JSON array)
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut ret: Vec<JValue> = Vec::new();
            while let Some(value) = seq.next_element::<String>()? { // we only accept arrays of strings
                ret.push(JValue::String(value))
            }
            Ok(JValue::Array(ret))
        }

        // every other type will be rejected by serde
    }
    deserializer.deserialize_any(StringOrArray {})
}

impl Default for Claims {
    /// Returns a default instance of `Claims` where each claim is set to `None`
    /// and `iat` is set to the current time. The map for custom claims is
    /// initialized to an empty map
    fn default() -> Self {
        Claims {
            iss: None,
            sub: None,
            aud: None,
            exp: None,
            nbf: None,
            iat: Some(chrono::Utc::now().timestamp()),
            jti: None,
            custom: HashMap::new(),
        }
    }
}

/// Validates `aud` by checking if it is either a string or an array of strings
/// an returns an error if not.
/// # Arguments
/// * `aud` - The audience value to validate
/// # Returns
/// The unit type `()` if `aud` is valid, an error otherwise
/// # Errors
/// Returns an error if `aud` not a string or an array of strings.
fn check_aud_type(aud: &JValue) -> JwtResult<()> {
    if !aud.is_array() && !aud.is_string() {
        fail!(JwtError::GenericError("The value for 'aud' must be a string or array of strings.".to_string()));
    }
    if aud.is_array() {
        let tmp = aud.as_array().unwrap();
        if !tmp.is_empty() && !tmp[0].is_string() {
            fail!(JwtError::GenericError("The value for 'aud' must be a string or array of strings.".to_string()));
        }
    }
    Ok(())
}

impl Claims {
    /// Sets the value for `aud` claim. As RFC 7519 allows this value
    /// to be either a single string or a vector of strings, this methods takes
    /// care of serializing the input value and setting the audience correctly.
    /// # Arguments
    /// * `audience` - The value for the `aud` claim
    /// # Returns
    /// An error if setting the audience claim fails
    /// # Errors
    /// Returns an error if the specified value for the `aud` claim is not a
    /// string or not an array of string and thus invalid.
    pub fn set_audience<T: Serialize>(&mut self, audience: &T) -> JwtResult<()> {
        let value = serde_json::to_value(audience).unwrap_or(JValue::Null);
        check_aud_type(&value)?;
        self.aud = Some(value);
        Ok(())
    }

    /// Returns the current value for the `aud` claim.
    /// # Returns
    /// The current value of the `aud` claim
    pub fn get_audience(&self) -> &Option<JValue> {
        &self.aud
    }

    /// Sets a custom claim identified by `key` to a serializable value.
    /// This method only allows keys which do not reflect a registered claim
    /// (this could allow duplicate claims which is not RFC compliant).
    /// # Arguments
    /// * `key` - The name of the claim to add (must not be a registered claim)
    /// * `value` - Serializable value of the claim
    /// # Returns
    /// The unit type on success, an error on failure
    /// # Errors
    /// This function returns an error if `key` reflects a registered claim
    /// (see [REGISTERED_CLAIM_NAMES](constant.REGISTERED_CLAIM_NAMES.html))
    pub fn set_custom_claim<T: Serialize>(&mut self, key: &str, value: &T) -> JwtResult<()> {
        let key = key.to_lowercase();
        if key.is_empty() {
            fail!(JwtError::GenericError("Empty names for claims are not allowed.".to_string()));
        }
        if REGISTERED_CLAIM_NAMES.contains(&key.as_str()) {
            fail!(JwtError::GenericError("Setting a registered claim via custom claim structure is not allowed.".to_string()));
        }
        self.custom.insert(key, serde_json::to_value(value)?);
        Ok(())
    }

    /// Returns a map of the current state of custom claims.
    /// # Returns
    /// Reference to the current custom claim map
    pub fn get_custom_claims(&self) -> &HashMap<String, JValue> {
        &self.custom
    }

    /// Returns the value of a specific custom claim, if any.
    /// # Arguments
    /// * `key` - The key of the custom claim to return the value of
    /// # Returns
    /// The value of the specified claim or a `None` value if the claim could
    /// not be found
    pub fn get_custom_claim(&self, key: &str) -> Option<&JValue> {
        self.custom.get(key)
    }
}

/// A structure used to automatically validate registered claims. Custom claims
/// have to be validated manually according to their respective application
/// logic.
/// All validations using time (expiration checks, ...) are using UTC timestamps
/// provided by the system clock through `chrono`.
/// The audience claim has to be set through the respective method of this struct.
/// # Example
/// ```rust
/// # use jwt_rs::{ClaimValidator, Claims};
/// # use chrono::Utc;
/// let mut claims = Claims::default();
/// claims.sub = Some("John".to_string());
/// claims.exp = Some(Utc::now().timestamp() + 100000);
///
/// let mut validator = ClaimValidator::default();
/// validator.validate_sub = Some("John".to_string());
/// assert!(validator.validate(&claims).is_ok());
///
/// validator.validate_sub = Some("Frank".to_string());
/// assert!(validator.validate(&claims).is_err());
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct ClaimValidator {
    /// The tolerance in seconds to apply to time validations (`exp`, `nbf` and
    /// `iat`). Defaults to `0`.
    pub time_tolerance: i64,
    /// Validate the `exp` claim and return an error if validation fails.
    /// Defaults to `true`
    pub validate_exp: bool,
    /// Validate the `nbf` claim and return an error if the current time is
    /// before the timestamp in the `nbf` claim. Defalts to `false`.
    pub validate_nbf: bool,
    /// Validate the `aud` claim and return an error if the expected and the
    /// actual values do not match. Defaults to `None`.
    /// *Note:* As RFC 7519 allows for `aud` being either a single String or a
    /// `Vec<String>` you must use the method
    /// [set_expected_audience](struct.ClaimValidator.html#method.set_expected_audience)
    /// to set this value (in fact, you have no choice, because this member is
    /// private ;-)).
    validate_aud: Option<JValue>,
    /// Validate the `iss` claim and return an error if the expected and the
    /// actual value do not match. Defaults to `None`.
    pub validate_iss: Option<String>,
    /// Validate the `sub` claim and return an error if the expected and the
    /// actual value do not match. Defaults to `None`.
    pub validate_sub: Option<String>,
}

impl Default for ClaimValidator {
    /// Returns a new instance of this struct with default values for all members.
    fn default() -> Self {
        ClaimValidator {
            time_tolerance: 0,
            validate_exp: true,
            validate_nbf: false,
            validate_aud: None,
            validate_iss: None,
            validate_sub: None,
        }
    }
}

impl ClaimValidator {
    /// Creates a new validator using the specified time tolerance in seconds.
    /// # Arguments
    /// * `tolerance` - The tolerance (in seconds) for time comparisons
    /// # Returns
    /// New instance of `ClaimValidator` where the tolerance is set to the
    /// specified value and all other fields use their respective defaults
    pub fn new(tolerance: i64) -> Self {
        ClaimValidator {time_tolerance: tolerance, ..ClaimValidator::default()}
    }

    /// Sets the expected value for `aud` claim. As RFC 7519 allows this value
    /// to be either a single string or a vector of strings, this methods takes
    /// care of serializing the input value and setting the audience correctly.
    /// # Arguments
    /// * `audience` - The value to be expected for the `aud` claim
    /// # Returns
    /// An error if setting the audience claim fails
    /// # Errors
    /// Returns an error if the specified value for the `aud` claim is not a
    /// string or not an array of string and thus invalid.
    pub fn set_expected_audience<T: Serialize>(&mut self, audience: &T) -> JwtResult<()> {
        let value = serde_json::to_value(audience).unwrap_or(JValue::Null);
        check_aud_type(&value)?;
        self.validate_aud = Some(value);
        Ok(())
    }

    /// Returns the expected value for the `aud` claim currently set in this
    /// validator instance.
    /// # Returns
    /// The currently expected value of the `aud` claim
    pub fn get_expected_audience(&self) -> &Option<JValue> {
        &self.validate_aud
    }

    /// Validates the specified claims using the current validator instance and
    /// its settings.
    /// # Arguments
    /// * `claims` - Reference to the claims to validate
    /// # Returns
    /// `true` if the validation succeeds, an error type otherwise
    /// # Error
    /// Returns an error if the validation fails.
    pub fn validate(&self, claims: &Claims) -> JwtResult<bool> {
        let now = chrono::Utc::now().timestamp();
        const MISSING_VALUE: &str = "<MISSING>";

        if self.validate_exp {
            if let Some(exp) = &claims.exp {
                if *exp < now - self.time_tolerance {
                    fail!(JwtError::TokenExpired(*exp));
                }
            } else {
                fail!(JwtError::InvalidClaim("exp".to_string(), MISSING_VALUE.to_string()))
            }
        }

        if self.validate_nbf {
            if let Some(nbf) = &claims.nbf {
                if *nbf > now + self.time_tolerance {
                    fail!(JwtError::TokenNotYetValid(*nbf));
                }
            } else {
                fail!(JwtError::InvalidClaim("nbf".to_string(), MISSING_VALUE.to_string()));
            }
        }

        if let Some(ref expected_iss) = self.validate_iss {
            if let Some(iss) = &claims.iss {
                if iss != expected_iss {
                    fail!(JwtError::InvalidClaim("iss".to_string(), iss.clone()));
                }
            } else {
                fail!(JwtError::InvalidClaim("iss".to_string(), MISSING_VALUE.to_string()));
            }
        }

        if let Some(ref expected_sub) = self.validate_sub {
            if let Some(sub) = &claims.sub {
                if sub != expected_sub {
                    fail!(JwtError::InvalidClaim("sub".to_string(), sub.clone()));
                }
            } else {
                fail!(JwtError::InvalidClaim("sub".to_string(), MISSING_VALUE.to_string()));
            }
        }

        if let Some(ref expected_aud) = self.validate_aud {
            if let Some(aud) = &claims.aud {
                if aud != expected_aud {
                    fail!(JwtError::InvalidClaim("aud".to_string(), aud.to_string()))
                }
            } else {
                fail!(JwtError::InvalidClaim("aud".to_string(), MISSING_VALUE.to_string()))
            }
        }

        Ok(true)
    }
}

#[cfg(test)]
mod tests {

    mod claims {
        use crate::claims::Claims;
        use crate::errors::JwtResult;
        use serde_json::json;

        #[test]
        fn initialize_and_serialize_claims() -> JwtResult<()> {
            let mut claims = Claims::default();
            claims.sub = Some("Foobar".to_string());
            claims.iat = Some(42);
            claims.set_audience(&"MyAudience")?;
            assert!(claims.custom.is_empty());
            claims.custom.insert("abc".to_string(), json!("XYZ"));
            let s = serde_json::to_string(&claims).unwrap_or(String::default());
            assert_eq!(s, "{\"sub\":\"Foobar\",\"aud\":\"MyAudience\",\"iat\":42,\"abc\":\"XYZ\"}");
            Ok(())
        }

        #[test]
        fn deserialize_claims() -> JwtResult<()> {
            let s = "{\"sub\":\"Foobar\",\"aud\":[\"John\",\"Doe\"],\"iat\":42,\"abc\":\"XYZ\"}";
            let claims: Claims = serde_json::from_str(&s)?;
            assert_eq!(claims.exp, None);
            assert_eq!(&claims.sub.unwrap(), "Foobar");
            assert_eq!(claims.iat.unwrap(), 42);
            let audience = claims.aud.unwrap();
            let audience = audience.as_array().unwrap();
            assert!(audience.contains(&json!("John")));
            assert!(audience.contains(&json!("Doe")));
            assert_eq!(claims.custom.get("abc").unwrap().as_str().unwrap(), "XYZ");
            Ok(())
        }

        #[test]
        fn deserialize_aud_string() -> JwtResult<()> {
            let s = "{\"sub\":\"test\",\"aud\":\"John\"}";
            let claims: Claims = serde_json::from_str(&s)?;
            assert_eq!(&claims.sub.unwrap(), "test");
            let aud = claims.aud.unwrap();
            assert!(aud.is_string());
            assert_eq!(aud, "John");
            Ok(())
        }

        #[test]
        fn deserialize_aud_array_of_strings() -> JwtResult<()> {
            let s = "{\"sub\":\"test\",\"aud\":[\"John\",\"Frank\"]}";
            let claims: Claims = serde_json::from_str(&s)?;
            let aud = claims.aud.unwrap();
            assert!(aud.is_array());
            let aud = aud.as_array().unwrap();
            assert!(aud.contains(&json!("John")));
            assert!(aud.contains(&json!("Frank")));
            Ok(())
        }

        #[test]
        fn deserialize_aud_null() -> JwtResult<()> {
            let s = "{\"sub\":\"test\",\"aud\":null}";
            let claims: Claims = serde_json::from_str(&s)?;
            assert!(claims.aud.is_none());
            Ok(())
        }

        #[test]
        fn deserialize_aud_empty() -> JwtResult<()> {
            let s = "{\"sub\":\"test\",\"aud\":\"\"}";
            let claims: Claims = serde_json::from_str(&s)?;
            let aud = claims.aud.unwrap();
            assert!(aud.is_string());
            assert_eq!(aud, "");
            Ok(())
        }

        #[test]
        fn deserialize_aud_int() {
            let s = "{\"sub\":\"test\",\"aud\":42}";
            assert!(serde_json::from_str::<Claims>(&s).is_err());
        }

        #[test]
        fn deserialize_aud_array_int() {
            let s = "{\"sub\":\"test\",\"aud\":[42,1]}";
            assert!(serde_json::from_str::<Claims>(&s).is_err());
        }

        #[test]
        fn deserialize_aud_bool() {
            let s = "{\"sub\":\"test\",\"aud\":true}";
            assert!(serde_json::from_str::<Claims>(&s).is_err());
        }

        #[test]
        fn deserialize_aud_array_mixed() {
            let s = "{\"sub\":\"test\",\"aud\":[42,true,\"foo\"]}";
            assert!(serde_json::from_str::<Claims>(&s).is_err());
        }

        #[test]
        fn deserialize_aud_object() {
            let s = "{\"sub\":\"test\",\"aud\":{\"foo\":\"bar\"}}";
            assert!(serde_json::from_str::<Claims>(&s).is_err());
        }

        #[test]
        fn init_claims_invalid_audience() {
            let mut claims = Claims::default();
            assert!(claims.set_audience(&42).is_err());
        }

        #[test]
        fn set_get_custom_claims() -> JwtResult<()> {
            let s = "{\"sub\":\"test\",\"aud\":\"John\",\"custom1\":42,\"custom2\":\"foo\"}";
            let claims = serde_json::from_str::<Claims>(s)?;
            let custom1 = claims.get_custom_claim("custom1").unwrap();
            let custom2 = claims.get_custom_claim("custom2").unwrap();
            assert_eq!(custom1, 42);
            assert_eq!(custom2, "foo");

            let customs = claims.get_custom_claims();
            assert_eq!(customs["custom1"], 42);
            assert_eq!(customs["custom2"], "foo");

            assert!(claims.get_custom_claim("custom3").is_none());
            let mut claims = claims;
            claims.set_custom_claim("custom3", &true)?;
            assert_eq!(claims.get_custom_claim("custom3").unwrap(), true);

            assert_eq!(claims.sub.clone().unwrap(), "test");
            assert!(claims.set_custom_claim("sub", &"hacked").is_err()); // yeah, nice try
            assert_eq!(claims.sub.unwrap(), "test");
            Ok(())
        }
    }

    mod validator {
        use crate::errors::{JwtResult, JwtError};
        use crate::claims::{Claims, ClaimValidator};

        use chrono::Utc;

        #[test]
        fn exp_in_future() {
            let mut claims = Claims::default();
            claims.exp = Some(Utc::now().timestamp() + 10000);
            let validator = ClaimValidator::default();
            assert!(validator.validate(&claims).is_ok());
        }

        #[test]
        fn exp_in_past() {
            let mut claims = Claims::default();
            claims.exp = Some(Utc::now().timestamp() - 10000);
            let validator = ClaimValidator::default();
            let result = validator.validate(&claims);
            assert!(result.is_err());
            match result.unwrap_err() {
                JwtError::TokenExpired(_)   => assert!(true),
                _                           => assert!(false),
            }
        }

        #[test]
        fn exp_in_past_tolerance() {
            let mut claims = Claims::default();
            claims.exp = Some(Utc::now().timestamp() - 500);
            let mut validator = ClaimValidator::default();
            validator.time_tolerance = 1000;
            assert!(validator.validate(&claims).is_ok());
        }

        #[test]
        fn exp_missing() {
            let claims = Claims::default();
            let validator = ClaimValidator::default();
            let result = validator.validate(&claims);
            assert!(result.is_err());
            match result.unwrap_err() {
                JwtError::InvalidClaim(_, _)    => assert!(true),
                _                               => assert!(false),
            }
        }

        #[test]
        fn nbf_in_past() {
            let mut claims = Claims::default();
            claims.nbf = Some(Utc::now().timestamp() - 10000);
            let mut validator = ClaimValidator::default();
            validator.validate_nbf = true;
            validator.validate_exp = false;
            assert!(validator.validate(&claims).is_ok());
        }

        #[test]
        fn nbf_in_future() {
            let mut claims = Claims::default();
            claims.nbf = Some(Utc::now().timestamp() + 10000);
            let mut validator = ClaimValidator::default();
            validator.validate_nbf = true;
            validator.validate_exp = false;
            let result = validator.validate(&claims);
            assert!(result.is_err());
            match result.unwrap_err() {
                JwtError::TokenNotYetValid(_)   => assert!(true),
                _                               => assert!(false),
            }
        }

        #[test]
        fn nbf_in_future_tolerance() {
            let mut claims = Claims::default();
            claims.nbf = Some(Utc::now().timestamp() + 500);
            let mut validator = ClaimValidator::new(1000);
            validator.validate_nbf = true;
            validator.validate_exp = false;
            assert!(validator.validate(&claims).is_ok());
        }

        #[test]
        fn iss_ok() {
            let mut claims = Claims::default();
            claims.iss = Some("John".to_string());
            let mut validator = ClaimValidator::default();
            validator.validate_exp = false;
            validator.validate_iss = Some("John".to_string());
            assert!(validator.validate(&claims).is_ok());
        }

        #[test]
        fn iss_not_matching() {
            let mut claims = Claims::default();
            claims.iss = Some("John".to_string());
            let mut validator = ClaimValidator::default();
            validator.validate_exp = false;
            validator.validate_iss = Some("Frank".to_string());
            let result = validator.validate(&claims);
            assert!(result.is_err());
            match result.unwrap_err() {
                JwtError::InvalidClaim(_, _)    => assert!(true),
                _                               => assert!(false),
            }
        }

        #[test]
        fn iss_missing() {
            let claims = Claims::default();
            let mut validator = ClaimValidator::default();
            validator.validate_exp = false;
            validator.validate_iss = Some("John".to_string());
            let result = validator.validate(&claims);
            assert!(result.is_err());
            match result.unwrap_err() {
                JwtError::InvalidClaim(_, _)    => assert!(true),
                _                               => assert!(false),
            }
        }

        #[test]
        fn sub_ok() {
            let mut claims = Claims::default();
            claims.sub = Some("John".to_string());
            let mut validator = ClaimValidator::default();
            validator.validate_exp = false;
            validator.validate_sub = Some("John".to_string());
            assert!(validator.validate(&claims).is_ok());
        }

        #[test]
        fn sub_not_matching() {
            let mut claims = Claims::default();
            claims.sub = Some("John".to_string());
            let mut validator = ClaimValidator::default();
            validator.validate_exp = false;
            validator.validate_sub = Some("Frank".to_string());
            let result = validator.validate(&claims);
            assert!(result.is_err());
            match result.unwrap_err() {
                JwtError::InvalidClaim(_, _)    => assert!(true),
                _                               => assert!(false),
            }
        }

        #[test]
        fn sub_missing() {
            let claims = Claims::default();
            let mut validator = ClaimValidator::default();
            validator.validate_exp = false;
            validator.validate_sub = Some("John".to_string());
            let result = validator.validate(&claims);
            assert!(result.is_err());
            match result.unwrap_err() {
                JwtError::InvalidClaim(_, _)    => assert!(true),
                _                               => assert!(false),
            }
        }

        #[test]
        fn aud_string_ok() -> JwtResult<()> {
            let mut claims = Claims::default();
            claims.set_audience(&"John")?;
            let mut validator = ClaimValidator::default();
            validator.validate_exp = false;
            validator.set_expected_audience(&"John")?;
            assert!(validator.validate(&claims).is_ok());
            Ok(())
        }

        #[test]
        fn aud_array_of_strings_ok() -> JwtResult<()> {
            let mut claims = Claims::default();
            claims.set_audience(&["John", "Frank"])?;
            let mut validator = ClaimValidator::default();
            validator.validate_exp = false;
            validator.set_expected_audience(&["John", "Frank"])?;
            assert!(validator.validate(&claims).is_ok());
            Ok(())
        }

        #[test]
        fn aud_type_mismatch() -> JwtResult<()> {
            let mut claims = Claims::default();
            claims.set_audience(&"John")?;
            let mut validator = ClaimValidator::default();
            validator.validate_exp = false;
            validator.set_expected_audience(&["John", "Frank"])?;
            let result = validator.validate(&claims);
            assert!(result.is_err());
            match result.unwrap_err() {
                JwtError::InvalidClaim(_, _)    => assert!(true),
                _                               => assert!(false),
            }
            Ok(())
        }

        #[test]
        fn aud_not_match_string() -> JwtResult<()> {
            let mut claims = Claims::default();
            claims.set_audience(&"John")?;
            let mut validator = ClaimValidator::default();
            validator.validate_exp = false;
            validator.set_expected_audience(&"Frank")?;
            let result = validator.validate(&claims);
            assert!(result.is_err());
            match result.unwrap_err() {
                JwtError::InvalidClaim(_, _)    => assert!(true),
                _                               => assert!(false),
            }
            Ok(())
        }

        #[test]
        fn aud_not_match_array() -> JwtResult<()> {
            let mut claims = Claims::default();
            claims.set_audience(&["John", "Frank"])?;
            let mut validator = ClaimValidator::default();
            validator.validate_exp = false;
            validator.set_expected_audience(&["John", "Ian"])?;
            let result = validator.validate(&claims);
            assert!(result.is_err());
            match result.unwrap_err() {
                JwtError::InvalidClaim(_, _)    => assert!(true),
                _                               => assert!(false),
            }
            Ok(())
        }

        #[test]
        fn aud_missing() -> JwtResult<()> {
            let claims = Claims::default();
            let mut validator = ClaimValidator::default();
            validator.validate_exp = false;
            validator.set_expected_audience(&["John", "Ian"])?;
            let result = validator.validate(&claims);
            assert!(result.is_err());
            match result.unwrap_err() {
                JwtError::InvalidClaim(_, _)    => assert!(true),
                _                               => assert!(false),
            }
            Ok(())
        }

    }
}
