//
// Copyright 2025 Nexlab-One.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Algorithm registry for signature algorithms.
//!
//! This module provides functionality to map protobuf PublicKeyDetails enum values
//! to algorithm details, and to detect algorithms from public key bytes.

use crate::errors::*;

use ed25519::pkcs8::DecodePublicKey;
#[cfg(feature = "sign")]
use sigstore_protobuf_specs::dev::sigstore::common::v1::{HashAlgorithm, PublicKeyDetails};

/// Public key type classification.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PublicKeyType {
    /// RSA public key
    RSA,
    /// ECDSA public key
    ECDSA,
    /// Ed25519 public key
    ED25519,
    /// Post-Quantum Cryptography public key
    PQC,
}

/// Algorithm details for signature algorithms.
///
/// This struct contains all the information needed to work with a signature algorithm,
/// including the hash algorithm, protobuf enum values, and flag values for CLI usage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlgorithmDetails {
    /// The protobuf PublicKeyDetails enum value
    pub known_algorithm: u32,
    /// The public key type
    pub key_type: PublicKeyType,
    /// The hash algorithm used (as a u32 representing crypto::Hash)
    pub hash_type: u32,
    /// The protobuf HashAlgorithm enum value
    pub proto_hash_type: u32,
    /// Extra key parameters (e.g., curve name, key size)
    /// Stored as a string for simplicity in FFI
    pub extra_key_params: Option<String>,
    /// Flag value for CLI usage (e.g., "ecdsa-p256-sha256", "ml-dsa-65")
    pub flag_value: String,
}

impl AlgorithmDetails {
    /// Create a new AlgorithmDetails instance.
    pub fn new(
        known_algorithm: u32,
        key_type: PublicKeyType,
        hash_type: u32,
        proto_hash_type: u32,
        extra_key_params: Option<String>,
        flag_value: String,
    ) -> Self {
        Self {
            known_algorithm,
            key_type,
            hash_type,
            proto_hash_type,
            extra_key_params,
            flag_value,
        }
    }
}

/// Get algorithm details for a given PublicKeyDetails enum value.
///
/// # Arguments
/// * `algorithm` - The protobuf PublicKeyDetails enum value (as u32)
///
/// # Returns
/// * `Ok(AlgorithmDetails)` if the algorithm is supported
/// * `Err(SigstoreError)` if the algorithm is not supported
#[cfg(feature = "sign")]
pub fn get_algorithm_details(algorithm: u32) -> Result<AlgorithmDetails> {
    // Convert to PublicKeyDetails enum first to validate
    let algo_i32 = algorithm as i32;
    let pub_key_details = PublicKeyDetails::try_from(algo_i32)
        .map_err(|_| SigstoreError::UnexpectedError(format!("Unknown algorithm: {}", algorithm)))?;

    // Match on numeric values directly (protobuf enum values)
    // Using numeric matching works regardless of Rust enum variant naming
    let algo_value = pub_key_details as i32;

    // Helper function to create algorithm details
    macro_rules! make_details {
        ($key_type:expr, $hash_type:expr, $proto_hash:expr, $params:expr, $flag:expr) => {
            Ok(AlgorithmDetails::new(
                algorithm,
                $key_type,
                $hash_type,
                $proto_hash as u32,
                $params,
                $flag.to_string(),
            ))
        };
    }

    match algo_value {
        // PUBLIC_KEY_DETAILS_UNSPECIFIED = 0
        0 => make_details!(
            PublicKeyType::RSA,
            1,
            HashAlgorithm::Sha2256,
            None,
            "unspecified"
        ),

        // Try to use enum variants where they exist, fall back to numeric matching
        x if x == PublicKeyDetails::PkixRsaPkcs1v152048Sha256 as i32 => make_details!(
            PublicKeyType::RSA,
            1, // crypto::SHA256
            HashAlgorithm::Sha2256,
            Some("2048".to_string()),
            "rsa-pkcs1v15-2048-sha256"
        ),
        x if x == PublicKeyDetails::PkixRsaPkcs1v153072Sha256 as i32 => make_details!(
            PublicKeyType::RSA,
            1,
            HashAlgorithm::Sha2256,
            Some("3072".to_string()),
            "rsa-pkcs1v15-3072-sha256"
        ),
        x if x == PublicKeyDetails::PkixRsaPkcs1v154096Sha256 as i32 => make_details!(
            PublicKeyType::RSA,
            1,
            HashAlgorithm::Sha2256,
            Some("4096".to_string()),
            "rsa-pkcs1v15-4096-sha256"
        ),
        // PKIX_RSA_PKCS1V15_4096_SHA512 - use numeric value
        4 => make_details!(
            PublicKeyType::RSA,
            5, // crypto::SHA512
            HashAlgorithm::Sha2512,
            Some("4096".to_string()),
            "rsa-pkcs1v15-4096-sha512"
        ),
        x if x == PublicKeyDetails::PkixRsaPss2048Sha256 as i32 => make_details!(
            PublicKeyType::RSA,
            1,
            HashAlgorithm::Sha2256,
            Some("2048".to_string()),
            "rsa-pss-2048-sha256"
        ),
        x if x == PublicKeyDetails::PkixRsaPss3072Sha256 as i32 => make_details!(
            PublicKeyType::RSA,
            1,
            HashAlgorithm::Sha2256,
            Some("3072".to_string()),
            "rsa-pss-3072-sha256"
        ),
        x if x == PublicKeyDetails::PkixRsaPss4096Sha256 as i32 => make_details!(
            PublicKeyType::RSA,
            1,
            HashAlgorithm::Sha2256,
            Some("4096".to_string()),
            "rsa-pss-4096-sha256"
        ),
        // PKIX_RSA_PSS_4096_SHA512 - use numeric value
        8 => make_details!(
            PublicKeyType::RSA,
            5,
            HashAlgorithm::Sha2512,
            Some("4096".to_string()),
            "rsa-pss-4096-sha512"
        ),
        x if x == PublicKeyDetails::PkixEcdsaP256Sha256 as i32 => make_details!(
            PublicKeyType::ECDSA,
            1,
            HashAlgorithm::Sha2256,
            Some("P-256".to_string()),
            "ecdsa-p256-sha256"
        ),
        x if x == PublicKeyDetails::PkixEcdsaP384Sha384 as i32 => make_details!(
            PublicKeyType::ECDSA,
            2, // crypto::SHA384
            HashAlgorithm::Sha2384,
            Some("P-384".to_string()),
            "ecdsa-p384-sha384"
        ),
        x if x == PublicKeyDetails::PkixEd25519 as i32 => make_details!(
            PublicKeyType::ED25519,
            5, // crypto::SHA512
            HashAlgorithm::Sha2512,
            None,
            "ed25519"
        ),
        // PQC algorithms
        x if x == PublicKeyDetails::MlDsa65 as i32 => make_details!(
            PublicKeyType::PQC,
            1,
            HashAlgorithm::Sha2256,
            None,
            "ml-dsa-65"
        ),
        x if x == PublicKeyDetails::MlDsa87 as i32 => make_details!(
            PublicKeyType::PQC,
            1,
            HashAlgorithm::Sha2256,
            None,
            "ml-dsa-87"
        ),
        x if x == PublicKeyDetails::MlDsa44 as i32 => make_details!(
            PublicKeyType::PQC,
            1,
            HashAlgorithm::Sha2256,
            None,
            "ml-dsa-44"
        ),
        x if x == PublicKeyDetails::Falcon512 as i32 => make_details!(
            PublicKeyType::PQC,
            1,
            HashAlgorithm::Sha2256,
            None,
            "falcon-512"
        ),
        x if x == PublicKeyDetails::Falcon1024 as i32 => make_details!(
            PublicKeyType::PQC,
            1,
            HashAlgorithm::Sha2256,
            None,
            "falcon-1024"
        ),
        x if x == PublicKeyDetails::SphincsPlus128f as i32 => make_details!(
            PublicKeyType::PQC,
            1,
            HashAlgorithm::Sha2256,
            None,
            "sphincs-plus-128f"
        ),
        x if x == PublicKeyDetails::SphincsPlus192f as i32 => make_details!(
            PublicKeyType::PQC,
            1,
            HashAlgorithm::Sha2256,
            None,
            "sphincs-plus-192f"
        ),
        x if x == PublicKeyDetails::SphincsPlus256f as i32 => make_details!(
            PublicKeyType::PQC,
            1,
            HashAlgorithm::Sha2256,
            None,
            "sphincs-plus-256f"
        ),
        _ => Err(SigstoreError::UnexpectedError(format!(
            "Unsupported algorithm: {} (enum value: {})",
            algorithm, algo_value
        ))),
    }
}

/// Get algorithm details from public key bytes by detecting the key type.
///
/// This function attempts to parse the public key bytes and determine the algorithm
/// based on the key structure. It tries classical algorithms first, then PQC algorithms.
///
/// # Arguments
/// * `pub_key_bytes` - Raw public key bytes (DER-encoded or raw format)
///
/// # Returns
/// * `Ok(AlgorithmDetails)` if the key type can be detected
/// * `Err(SigstoreError)` if the key cannot be parsed or detected
pub fn get_default_algorithm_details(pub_key_bytes: &[u8]) -> Result<AlgorithmDetails> {
    use const_oid::db::rfc5912::ID_EC_PUBLIC_KEY;
    use pkcs8::der::asn1::ObjectIdentifier as Pkcs8ObjectIdentifier;
    use x509_cert::spki::SubjectPublicKeyInfoOwned;

    // Try to parse as DER-encoded SubjectPublicKeyInfo
    if let Ok(spki) = SubjectPublicKeyInfoOwned::try_from(pub_key_bytes) {
        // Check algorithm OID
        let algorithm_oid = spki.algorithm.oid;

        // Convert const_oid 0.10.1 OIDs to pkcs8 format for comparison
        // These are well-known OIDs, so conversion should never fail
        let rsa_encryption_pkcs8 = {
            let bytes = const_oid::db::rfc5912::RSA_ENCRYPTION.as_bytes();
            Pkcs8ObjectIdentifier::from_bytes(bytes).map_err(|_| {
                SigstoreError::UnexpectedError("Failed to convert RSA_ENCRYPTION OID".to_string())
            })?
        };
        let id_ec_public_key_pkcs8 = {
            let bytes = ID_EC_PUBLIC_KEY.as_bytes();
            Pkcs8ObjectIdentifier::from_bytes(bytes).map_err(|_| {
                SigstoreError::UnexpectedError("Failed to convert ID_EC_PUBLIC_KEY OID".to_string())
            })?
        };

        // Check for RSA
        if algorithm_oid == rsa_encryption_pkcs8 {
            // Default to RSA_PKCS1_SHA256 for RSA keys
            #[cfg(feature = "sign")]
            {
                return get_algorithm_details(PublicKeyDetails::PkixRsaPkcs1v152048Sha256 as u32);
            }
            #[cfg(not(feature = "sign"))]
            {
                return Err(SigstoreError::UnexpectedError(
                    "RSA algorithm detection requires 'sign' feature".to_string(),
                ));
            }
        }

        // Check for ECDSA
        if algorithm_oid == id_ec_public_key_pkcs8 {
            // Try to determine curve from key bytes
            // P-256 keys are typically 65 bytes (0x04 + 64 bytes)
            // P-384 keys are typically 97 bytes (0x04 + 96 bytes)
            let public_key_der = &spki.subject_public_key;
            match public_key_der.raw_bytes().len() {
                65 => {
                    #[cfg(feature = "sign")]
                    {
                        return get_algorithm_details(PublicKeyDetails::PkixEcdsaP256Sha256 as u32);
                    }
                }
                97 => {
                    #[cfg(feature = "sign")]
                    {
                        return get_algorithm_details(PublicKeyDetails::PkixEcdsaP384Sha384 as u32);
                    }
                }
                _ => {}
            }
        }

        // Check for Ed25519
        if ed25519::pkcs8::PublicKeyBytes::from_public_key_der(pub_key_bytes).is_ok() {
            #[cfg(feature = "sign")]
            {
                return get_algorithm_details(PublicKeyDetails::PkixEd25519 as u32);
            }
        }
    }

    // Try to detect PQC algorithms by key size
    // This is a heuristic approach - actual detection would require parsing PQC-specific formats
    // For now, we'll return an error and let the caller specify the algorithm explicitly
    Err(SigstoreError::InvalidKeyFormat {
        error:
            "Could not detect algorithm from public key bytes. Please specify algorithm explicitly."
                .to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ============================================================================
    // Tests for get_algorithm_details()
    // ============================================================================

    #[cfg(feature = "sign")]
    mod get_algorithm_details_tests {
        use super::*;

        // RSA PKCS1v15 algorithms
        #[test]
        fn test_rsa_pkcs1v15_2048_sha256() {
            let details =
                get_algorithm_details(PublicKeyDetails::PkixRsaPkcs1v152048Sha256 as u32).unwrap();
            assert_eq!(details.key_type, PublicKeyType::RSA);
            assert_eq!(details.hash_type, 1); // SHA256
            assert_eq!(details.proto_hash_type, HashAlgorithm::Sha2256 as u32);
            assert_eq!(details.extra_key_params, Some("2048".to_string()));
            assert_eq!(details.flag_value, "rsa-pkcs1v15-2048-sha256");
            assert_eq!(
                details.known_algorithm,
                PublicKeyDetails::PkixRsaPkcs1v152048Sha256 as u32
            );
        }

        #[test]
        fn test_rsa_pkcs1v15_3072_sha256() {
            let details =
                get_algorithm_details(PublicKeyDetails::PkixRsaPkcs1v153072Sha256 as u32).unwrap();
            assert_eq!(details.key_type, PublicKeyType::RSA);
            assert_eq!(details.hash_type, 1);
            assert_eq!(details.proto_hash_type, HashAlgorithm::Sha2256 as u32);
            assert_eq!(details.extra_key_params, Some("3072".to_string()));
            assert_eq!(details.flag_value, "rsa-pkcs1v15-3072-sha256");
        }

        #[test]
        fn test_rsa_pkcs1v15_4096_sha256() {
            let details =
                get_algorithm_details(PublicKeyDetails::PkixRsaPkcs1v154096Sha256 as u32).unwrap();
            assert_eq!(details.key_type, PublicKeyType::RSA);
            assert_eq!(details.hash_type, 1);
            assert_eq!(details.proto_hash_type, HashAlgorithm::Sha2256 as u32);
            assert_eq!(details.extra_key_params, Some("4096".to_string()));
            assert_eq!(details.flag_value, "rsa-pkcs1v15-4096-sha256");
        }

        #[test]
        fn test_rsa_pkcs1v15_4096_sha512() {
            let details = get_algorithm_details(4).unwrap();
            assert_eq!(details.key_type, PublicKeyType::RSA);
            assert_eq!(details.hash_type, 5); // SHA512
            assert_eq!(details.proto_hash_type, HashAlgorithm::Sha2512 as u32);
            assert_eq!(details.extra_key_params, Some("4096".to_string()));
            assert_eq!(details.flag_value, "rsa-pkcs1v15-4096-sha512");
        }

        // RSA PSS algorithms
        #[test]
        fn test_rsa_pss_2048_sha256() {
            let details =
                get_algorithm_details(PublicKeyDetails::PkixRsaPss2048Sha256 as u32).unwrap();
            assert_eq!(details.key_type, PublicKeyType::RSA);
            assert_eq!(details.hash_type, 1);
            assert_eq!(details.proto_hash_type, HashAlgorithm::Sha2256 as u32);
            assert_eq!(details.extra_key_params, Some("2048".to_string()));
            assert_eq!(details.flag_value, "rsa-pss-2048-sha256");
        }

        #[test]
        fn test_rsa_pss_3072_sha256() {
            let details =
                get_algorithm_details(PublicKeyDetails::PkixRsaPss3072Sha256 as u32).unwrap();
            assert_eq!(details.key_type, PublicKeyType::RSA);
            assert_eq!(details.hash_type, 1);
            assert_eq!(details.proto_hash_type, HashAlgorithm::Sha2256 as u32);
            assert_eq!(details.extra_key_params, Some("3072".to_string()));
            assert_eq!(details.flag_value, "rsa-pss-3072-sha256");
        }

        #[test]
        fn test_rsa_pss_4096_sha256() {
            let details =
                get_algorithm_details(PublicKeyDetails::PkixRsaPss4096Sha256 as u32).unwrap();
            assert_eq!(details.key_type, PublicKeyType::RSA);
            assert_eq!(details.hash_type, 1);
            assert_eq!(details.proto_hash_type, HashAlgorithm::Sha2256 as u32);
            assert_eq!(details.extra_key_params, Some("4096".to_string()));
            assert_eq!(details.flag_value, "rsa-pss-4096-sha256");
        }

        #[test]
        fn test_rsa_pss_4096_sha512() {
            let details = get_algorithm_details(8).unwrap();
            assert_eq!(details.key_type, PublicKeyType::RSA);
            assert_eq!(details.hash_type, 5);
            assert_eq!(details.proto_hash_type, HashAlgorithm::Sha2512 as u32);
            assert_eq!(details.extra_key_params, Some("4096".to_string()));
            assert_eq!(details.flag_value, "rsa-pss-4096-sha512");
        }

        // ECDSA algorithms
        #[test]
        fn test_ecdsa_p256_sha256() {
            let details =
                get_algorithm_details(PublicKeyDetails::PkixEcdsaP256Sha256 as u32).unwrap();
            assert_eq!(details.key_type, PublicKeyType::ECDSA);
            assert_eq!(details.hash_type, 1);
            assert_eq!(details.proto_hash_type, HashAlgorithm::Sha2256 as u32);
            assert_eq!(details.extra_key_params, Some("P-256".to_string()));
            assert_eq!(details.flag_value, "ecdsa-p256-sha256");
        }

        #[test]
        fn test_ecdsa_p384_sha384() {
            let details =
                get_algorithm_details(PublicKeyDetails::PkixEcdsaP384Sha384 as u32).unwrap();
            assert_eq!(details.key_type, PublicKeyType::ECDSA);
            assert_eq!(details.hash_type, 2); // SHA384
            assert_eq!(details.proto_hash_type, HashAlgorithm::Sha2384 as u32);
            assert_eq!(details.extra_key_params, Some("P-384".to_string()));
            assert_eq!(details.flag_value, "ecdsa-p384-sha384");
        }

        // Ed25519
        #[test]
        fn test_ed25519() {
            let details = get_algorithm_details(PublicKeyDetails::PkixEd25519 as u32).unwrap();
            assert_eq!(details.key_type, PublicKeyType::ED25519);
            assert_eq!(details.hash_type, 5); // SHA512
            assert_eq!(details.proto_hash_type, HashAlgorithm::Sha2512 as u32);
            assert_eq!(details.extra_key_params, None);
            assert_eq!(details.flag_value, "ed25519");
        }

        // PQC algorithms
        #[test]
        fn test_ml_dsa_65() {
            let details = get_algorithm_details(PublicKeyDetails::MlDsa65 as u32).unwrap();
            assert_eq!(details.key_type, PublicKeyType::PQC);
            assert_eq!(details.hash_type, 1);
            assert_eq!(details.proto_hash_type, HashAlgorithm::Sha2256 as u32);
            assert_eq!(details.extra_key_params, None);
            assert_eq!(details.flag_value, "ml-dsa-65");
        }

        #[test]
        fn test_ml_dsa_87() {
            let details = get_algorithm_details(PublicKeyDetails::MlDsa87 as u32).unwrap();
            assert_eq!(details.key_type, PublicKeyType::PQC);
            assert_eq!(details.hash_type, 1);
            assert_eq!(details.proto_hash_type, HashAlgorithm::Sha2256 as u32);
            assert_eq!(details.extra_key_params, None);
            assert_eq!(details.flag_value, "ml-dsa-87");
        }

        #[test]
        fn test_ml_dsa_44() {
            let details = get_algorithm_details(PublicKeyDetails::MlDsa44 as u32).unwrap();
            assert_eq!(details.key_type, PublicKeyType::PQC);
            assert_eq!(details.hash_type, 1);
            assert_eq!(details.proto_hash_type, HashAlgorithm::Sha2256 as u32);
            assert_eq!(details.extra_key_params, None);
            assert_eq!(details.flag_value, "ml-dsa-44");
        }

        #[test]
        fn test_falcon_512() {
            let details = get_algorithm_details(PublicKeyDetails::Falcon512 as u32).unwrap();
            assert_eq!(details.key_type, PublicKeyType::PQC);
            assert_eq!(details.hash_type, 1);
            assert_eq!(details.proto_hash_type, HashAlgorithm::Sha2256 as u32);
            assert_eq!(details.extra_key_params, None);
            assert_eq!(details.flag_value, "falcon-512");
        }

        #[test]
        fn test_falcon_1024() {
            let details = get_algorithm_details(PublicKeyDetails::Falcon1024 as u32).unwrap();
            assert_eq!(details.key_type, PublicKeyType::PQC);
            assert_eq!(details.hash_type, 1);
            assert_eq!(details.proto_hash_type, HashAlgorithm::Sha2256 as u32);
            assert_eq!(details.extra_key_params, None);
            assert_eq!(details.flag_value, "falcon-1024");
        }

        #[test]
        fn test_sphincs_plus_128f() {
            let details = get_algorithm_details(PublicKeyDetails::SphincsPlus128f as u32).unwrap();
            assert_eq!(details.key_type, PublicKeyType::PQC);
            assert_eq!(details.hash_type, 1);
            assert_eq!(details.proto_hash_type, HashAlgorithm::Sha2256 as u32);
            assert_eq!(details.extra_key_params, None);
            assert_eq!(details.flag_value, "sphincs-plus-128f");
        }

        #[test]
        fn test_sphincs_plus_192f() {
            let details = get_algorithm_details(PublicKeyDetails::SphincsPlus192f as u32).unwrap();
            assert_eq!(details.key_type, PublicKeyType::PQC);
            assert_eq!(details.hash_type, 1);
            assert_eq!(details.proto_hash_type, HashAlgorithm::Sha2256 as u32);
            assert_eq!(details.extra_key_params, None);
            assert_eq!(details.flag_value, "sphincs-plus-192f");
        }

        #[test]
        fn test_sphincs_plus_256f() {
            let details = get_algorithm_details(PublicKeyDetails::SphincsPlus256f as u32).unwrap();
            assert_eq!(details.key_type, PublicKeyType::PQC);
            assert_eq!(details.hash_type, 1);
            assert_eq!(details.proto_hash_type, HashAlgorithm::Sha2256 as u32);
            assert_eq!(details.extra_key_params, None);
            assert_eq!(details.flag_value, "sphincs-plus-256f");
        }

        // Edge cases
        #[test]
        fn test_unspecified_algorithm() {
            let details = get_algorithm_details(0).unwrap();
            assert_eq!(details.key_type, PublicKeyType::RSA);
            assert_eq!(details.hash_type, 1);
            assert_eq!(details.proto_hash_type, HashAlgorithm::Sha2256 as u32);
            assert_eq!(details.extra_key_params, None);
            assert_eq!(details.flag_value, "unspecified");
        }

        #[test]
        fn test_invalid_algorithm() {
            let result = get_algorithm_details(9999);
            assert!(result.is_err());
            if let Err(SigstoreError::UnexpectedError(msg)) = result {
                assert!(msg.contains("Unknown algorithm") || msg.contains("Unsupported algorithm"));
            } else {
                panic!("Expected UnexpectedError, got different error type");
            }
        }

        #[test]
        fn test_boundary_value_high() {
            let result = get_algorithm_details(20);
            assert!(result.is_err());
        }

        #[test]
        fn test_boundary_value_low() {
            // Value 0 is valid (unspecified), so test -1 would require i32 conversion
            // Since we're using u32, we can't test negative values directly
            // But we can test that 0 works (already tested above)
            let details = get_algorithm_details(0).unwrap();
            assert_eq!(details.flag_value, "unspecified");
        }
    }

    // ============================================================================
    // Tests for get_default_algorithm_details()
    // ============================================================================

    mod get_default_algorithm_details_tests {
        use super::*;

        #[cfg(feature = "sign")]
        #[test]
        fn test_detect_rsa_key() {
            // Generate a minimal RSA public key in DER format
            // This is a simplified RSA public key SPKI structure
            // In practice, we'd use actual key generation, but for testing we'll use
            // a known valid RSA public key DER encoding
            use openssl::pkey::PKey;
            use openssl::rsa::Rsa;

            let rsa = Rsa::generate(2048).unwrap();
            let pkey = PKey::from_rsa(rsa).unwrap();
            let pub_key_der = pkey.public_key_to_der().unwrap();

            let details = get_default_algorithm_details(&pub_key_der).unwrap();
            assert_eq!(details.key_type, PublicKeyType::RSA);
            assert_eq!(details.flag_value, "rsa-pkcs1v15-2048-sha256");
        }

        #[cfg(feature = "sign")]
        #[test]
        fn test_detect_ecdsa_p256_key() {
            use openssl::ec::{EcGroup, EcKey};
            use openssl::nid::Nid;
            use openssl::pkey::PKey;

            let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
            let ec_key = EcKey::generate(&group).unwrap();
            let pkey = PKey::from_ec_key(ec_key).unwrap();
            let pub_key_der = pkey.public_key_to_der().unwrap();

            let details = get_default_algorithm_details(&pub_key_der).unwrap();
            assert_eq!(details.key_type, PublicKeyType::ECDSA);
            assert_eq!(details.flag_value, "ecdsa-p256-sha256");
        }

        #[cfg(feature = "sign")]
        #[test]
        fn test_detect_ecdsa_p384_key() {
            use openssl::ec::{EcGroup, EcKey};
            use openssl::nid::Nid;
            use openssl::pkey::PKey;

            let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
            let ec_key = EcKey::generate(&group).unwrap();
            let pkey = PKey::from_ec_key(ec_key).unwrap();
            let pub_key_der = pkey.public_key_to_der().unwrap();

            let details = get_default_algorithm_details(&pub_key_der).unwrap();
            assert_eq!(details.key_type, PublicKeyType::ECDSA);
            assert_eq!(details.flag_value, "ecdsa-p384-sha384");
        }

        #[cfg(feature = "sign")]
        #[test]
        fn test_detect_ed25519_key() {
            use openssl::pkey::PKey;

            let pkey = PKey::generate_ed25519().unwrap();
            let pub_key_der = pkey.public_key_to_der().unwrap();

            let details = get_default_algorithm_details(&pub_key_der).unwrap();
            assert_eq!(details.key_type, PublicKeyType::ED25519);
            assert_eq!(details.flag_value, "ed25519");
        }

        #[test]
        fn test_invalid_key_format() {
            let invalid_key = b"not a valid key";
            let result = get_default_algorithm_details(invalid_key);
            assert!(result.is_err());
            if let Err(SigstoreError::InvalidKeyFormat { error }) = result {
                assert!(error.contains("Could not detect algorithm"));
            } else {
                panic!("Expected InvalidKeyFormat error");
            }
        }

        #[test]
        fn test_empty_input() {
            let result = get_default_algorithm_details(&[]);
            assert!(result.is_err());
        }

        #[test]
        fn test_unsupported_key_type() {
            // Create a DER-encoded SPKI with an unsupported algorithm OID
            // This is a simplified test - in practice, we'd need a valid DER structure
            // with an unsupported OID, but for now we'll test with invalid data
            let invalid_key = b"\x30\x0a\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07"; // Invalid structure
            let result = get_default_algorithm_details(invalid_key);
            assert!(result.is_err());
        }
    }

    // ============================================================================
    // Tests for AlgorithmDetails::new()
    // ============================================================================

    mod algorithm_details_constructor_tests {
        use super::*;

        #[cfg(feature = "sign")]
        #[test]
        fn test_new_with_all_fields() {
            let details = AlgorithmDetails::new(
                1,
                PublicKeyType::RSA,
                1,
                HashAlgorithm::Sha2256 as u32,
                Some("2048".to_string()),
                "test-flag".to_string(),
            );

            assert_eq!(details.known_algorithm, 1);
            assert_eq!(details.key_type, PublicKeyType::RSA);
            assert_eq!(details.hash_type, 1);
            assert_eq!(details.proto_hash_type, HashAlgorithm::Sha2256 as u32);
            assert_eq!(details.extra_key_params, Some("2048".to_string()));
            assert_eq!(details.flag_value, "test-flag");
        }

        #[cfg(feature = "sign")]
        #[test]
        fn test_new_without_extra_params() {
            let details = AlgorithmDetails::new(
                2,
                PublicKeyType::ED25519,
                5,
                HashAlgorithm::Sha2512 as u32,
                None,
                "ed25519".to_string(),
            );

            assert_eq!(details.known_algorithm, 2);
            assert_eq!(details.key_type, PublicKeyType::ED25519);
            assert_eq!(details.hash_type, 5);
            assert_eq!(details.proto_hash_type, HashAlgorithm::Sha2512 as u32);
            assert_eq!(details.extra_key_params, None);
            assert_eq!(details.flag_value, "ed25519");
        }

        #[cfg(feature = "sign")]
        #[test]
        fn test_new_with_pqc_type() {
            let details = AlgorithmDetails::new(
                12,
                PublicKeyType::PQC,
                1,
                HashAlgorithm::Sha2256 as u32,
                None,
                "ml-dsa-65".to_string(),
            );

            assert_eq!(details.known_algorithm, 12);
            assert_eq!(details.key_type, PublicKeyType::PQC);
            assert_eq!(details.hash_type, 1);
            assert_eq!(details.proto_hash_type, HashAlgorithm::Sha2256 as u32);
            assert_eq!(details.extra_key_params, None);
            assert_eq!(details.flag_value, "ml-dsa-65");
        }

        #[cfg(feature = "sign")]
        #[test]
        fn test_new_with_ecdsa_type() {
            let details = AlgorithmDetails::new(
                10,
                PublicKeyType::ECDSA,
                2,
                HashAlgorithm::Sha2384 as u32,
                Some("P-384".to_string()),
                "ecdsa-p384-sha384".to_string(),
            );

            assert_eq!(details.known_algorithm, 10);
            assert_eq!(details.key_type, PublicKeyType::ECDSA);
            assert_eq!(details.hash_type, 2);
            assert_eq!(details.proto_hash_type, HashAlgorithm::Sha2384 as u32);
            assert_eq!(details.extra_key_params, Some("P-384".to_string()));
            assert_eq!(details.flag_value, "ecdsa-p384-sha384");
        }

        #[test]
        fn test_new_basic() {
            // Test without HashAlgorithm enum (works without sign feature)
            let details = AlgorithmDetails::new(
                1,
                PublicKeyType::RSA,
                1,
                1, // SHA256 as u32
                Some("2048".to_string()),
                "test-flag".to_string(),
            );

            assert_eq!(details.known_algorithm, 1);
            assert_eq!(details.key_type, PublicKeyType::RSA);
            assert_eq!(details.hash_type, 1);
            assert_eq!(details.proto_hash_type, 1);
            assert_eq!(details.extra_key_params, Some("2048".to_string()));
            assert_eq!(details.flag_value, "test-flag");
        }
    }
}
