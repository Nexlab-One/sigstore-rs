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

//! FFI bindings for C interoperability.
//!
//! This module provides C-compatible functions to expose sigstore-rs functionality
//! to other languages via CGO or other FFI mechanisms.

#![allow(unsafe_code)]

use std::ffi::{CStr, CString};
use std::os::raw::c_char;

use crate::crypto::algorithm_registry::AlgorithmDetails;

/// C-compatible algorithm details structure.
///
/// This struct matches the Rust `AlgorithmDetails` but uses C-compatible types.
/// All strings are null-terminated C strings. The caller is responsible for
/// freeing all string pointers using the corresponding free functions.
#[repr(C)]
pub struct AlgorithmDetailsFFI {
    /// The protobuf PublicKeyDetails enum value
    pub known_algorithm: u32,
    /// The public key type (0=RSA, 1=ECDSA, 2=ED25519, 3=PQC)
    pub key_type: u32,
    /// The hash algorithm used (as a u32 representing crypto::Hash)
    pub hash_type: u32,
    /// The protobuf HashAlgorithm enum value
    pub proto_hash_type: u32,
    /// Extra key parameters (e.g., curve name, key size) as null-terminated C string
    /// NULL if not applicable
    pub extra_key_params: *mut c_char,
    /// Flag value for CLI usage (e.g., "ecdsa-p256-sha256", "ml-dsa-65") as null-terminated C string
    pub flag_value: *mut c_char,
}

impl From<AlgorithmDetails> for AlgorithmDetailsFFI {
    fn from(details: AlgorithmDetails) -> Self {
        let extra_key_params = details
            .extra_key_params
            .map(|s| CString::new(s).unwrap().into_raw())
            .unwrap_or(std::ptr::null_mut());

        let flag_value = CString::new(details.flag_value).unwrap().into_raw();

        Self {
            known_algorithm: details.known_algorithm,
            key_type: details.key_type as u32,
            hash_type: details.hash_type,
            proto_hash_type: details.proto_hash_type,
            extra_key_params,
            flag_value,
        }
    }
}

/// Get algorithm details for a given PublicKeyDetails enum value.
///
/// # Safety
/// This function is unsafe because it returns a raw pointer. The caller must
/// call `free_algorithm_details_ffi` to free the returned pointer.
///
/// # Arguments
/// * `algorithm` - The protobuf PublicKeyDetails enum value (as u32)
///
/// # Returns
/// * A pointer to `AlgorithmDetailsFFI` on success, or null on error
#[unsafe(no_mangle)]
pub unsafe extern "C" fn get_algorithm_details_ffi(algorithm: u32) -> *mut AlgorithmDetailsFFI {
    #[cfg(feature = "sign")]
    {
        match crate::crypto::algorithm_registry::get_algorithm_details(algorithm) {
            Ok(details) => {
                let ffi_details = AlgorithmDetailsFFI::from(details);
                Box::into_raw(Box::new(ffi_details))
            }
            Err(_) => std::ptr::null_mut(),
        }
    }
    #[cfg(not(feature = "sign"))]
    {
        std::ptr::null_mut()
    }
}

/// Get algorithm details from public key bytes by detecting the key type.
///
/// # Safety
/// This function is unsafe because it takes a raw pointer and returns a raw pointer.
/// The caller must:
/// - Ensure `pub_key_bytes` points to a valid buffer of at least `len` bytes
/// - Call `free_algorithm_details_ffi` to free the returned pointer
///
/// # Arguments
/// * `pub_key_bytes` - Pointer to raw public key bytes (DER-encoded or raw format)
/// * `len` - Length of the public key bytes buffer
///
/// # Returns
/// * A pointer to `AlgorithmDetailsFFI` on success, or null on error
#[unsafe(no_mangle)]
pub unsafe extern "C" fn get_default_algorithm_details_ffi(
    pub_key_bytes: *const u8,
    len: usize,
) -> *mut AlgorithmDetailsFFI {
    if pub_key_bytes.is_null() || len == 0 {
        return std::ptr::null_mut();
    }

    let slice = std::slice::from_raw_parts(pub_key_bytes, len);

    match crate::crypto::algorithm_registry::get_default_algorithm_details(slice) {
        Ok(details) => {
            let ffi_details = AlgorithmDetailsFFI::from(details);
            Box::into_raw(Box::new(ffi_details))
        }
        Err(_) => std::ptr::null_mut(),
    }
}

/// Free an AlgorithmDetailsFFI structure allocated by the FFI functions.
///
/// # Safety
/// This function is unsafe because it takes a raw pointer. The caller must:
/// - Only call this with a pointer returned by `get_algorithm_details_ffi` or
///   `get_default_algorithm_details_ffi`
/// - Not call this function more than once with the same pointer
/// - Not use the pointer after calling this function
///
/// # Arguments
/// * `details` - Pointer to AlgorithmDetailsFFI to free (can be null)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn free_algorithm_details_ffi(details: *mut AlgorithmDetailsFFI) {
    if details.is_null() {
        return;
    }

    let boxed = Box::from_raw(details);

    // Free the C strings
    if !boxed.extra_key_params.is_null() {
        let _ = CString::from_raw(boxed.extra_key_params as *mut c_char);
    }

    if !boxed.flag_value.is_null() {
        let _ = CString::from_raw(boxed.flag_value as *mut c_char);
    }

    // Box is dropped here, freeing the struct
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "sign")]
    #[test]
    fn test_get_algorithm_details_ffi() {
        use sigstore_protobuf_specs::dev::sigstore::common::v1::PublicKeyDetails;

        unsafe {
            let result = get_algorithm_details_ffi(PublicKeyDetails::PkixEcdsaP256Sha256 as u32);
            assert!(!result.is_null());

            let details = &*result;
            assert_eq!(
                details.known_algorithm,
                PublicKeyDetails::PkixEcdsaP256Sha256 as u32
            );
            assert_eq!(details.key_type, 1u32); // ECDSA = 1

            // Verify flag_value is not null and can be read
            assert!(!details.flag_value.is_null());
            let flag_cstr = CStr::from_ptr(details.flag_value);
            assert_eq!(flag_cstr.to_str().unwrap(), "ecdsa-p256-sha256");

            free_algorithm_details_ffi(result);
        }
    }

    #[test]
    fn test_free_null_pointer() {
        unsafe {
            // Should not panic
            free_algorithm_details_ffi(std::ptr::null_mut());
        }
    }
}
