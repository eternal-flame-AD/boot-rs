//! Libraries for marshaling and unmarshaling of cryptographic data.
#![cfg_attr(not(test), no_std)]
use boot_lib::io;

extern crate alloc;

/// The algorithm module contains types for instantiating cryptographic algorithms for encryption and sealing.
///
/// It is the lower-level abstration for this crate.
pub mod algorithm;
mod legacy;

/// The parcel module defines a more user-friendly header
/// that simplified instantiating cryptographic systems.
///
/// For validation and decryption.
///
/// # Parcel High-Level Example
/// ```
/// use boot_crypt::{Warning, Result,  parcel::{ParcelHeader}, algorithm::{Argon2Cfg, InitParams, KEYSPEC_DEFAULT}};
///
/// pub fn decode_parcel_bytes(data: &[u8]) -> Result<(Vec<u8>, Option<Vec<Warning>>)> {
///     let (_, algo, enc, warnings) =
///         ParcelHeader::open_parcel_and_unseal(data, b"password", None, None, Argon2Cfg::default())?;
///
///     // copied for simplicity
///     let mut enc = enc.to_owned();
///     let decrypted = algo.decrypt(enc.as_mut())?;
///
///     Ok((decrypted.to_owned(), warnings))
/// }
///
/// pub fn encode_parcel_bytes(data: &[u8]) -> Result<Vec<u8>> {
///     let mut header = ParcelHeader::new();
///
///     header.set_algorithm_spec(KEYSPEC_DEFAULT);
///     header.randomize_salt()?;
///
///     let mut parcel = header.encode();
///
///     let cipher = header.instantiate_cipher(b"password", None, Argon2Cfg::default())?;
///
///
///     let encrypted = cipher.encrypt(data.to_vec())?;
///     
///     let detached_seal = cipher
///         .seal(encrypted.as_ref())
///         .expect("seal should succeed");  
///     if let Some(detached_seal) = detached_seal {
///         parcel.extend(detached_seal);
///     }
///
///     parcel.extend_from_slice(encrypted.as_ref());
///
///     Ok(parcel)
/// }
///
/// let data = b"some data";
/// let parcel = encode_parcel_bytes(data).unwrap();
/// let (decrypted, warnings) = decode_parcel_bytes(parcel.as_ref()).unwrap();
/// assert_eq!(data, decrypted.as_slice());
///
/// ```
pub mod parcel;

/// Errors that can occur
#[derive(PartialEq, Debug, Clone, Copy)]
pub enum Error {
    /// The keyspec triplet is invalid
    InvalidKeySpec,
    /// The seal is invalid
    ///
    /// This can be caused by a bad key, bad data, or bad parameters.
    InvalidSeal,
    /// The padding is invalid
    ///
    /// This can be caused by a bad key, bad data, or bad parameters.
    InvalidPadding,
    /// Early EOF
    EarlyEOF,
    /// Error occured while decrypting data.
    ///
    /// For AEAD ciphers, this can be caused by a bad key, bad data, or bad parameters.
    DecryptionError,
    /// Error occured while encrypting data.
    ///
    /// This is usually caused by bad instantiation parameters.
    EncryptionError,
    /// IO error
    IOError(io::IOError),
    /// The parcel format is invalid
    InvalidParcelFormat,
    /// Other less common errors
    Other(&'static str),
}

/// Result wrapper for `Error`
pub type Result<T> = core::result::Result<T, Error>;

/// Warnings that can occur
///
/// Usually indicate insecure or deprecated usage.
#[derive(PartialEq, Eq, Debug, Clone, Copy, PartialOrd, Ord)]
pub enum Warning {
    /// The data is not sealed securely and can not be validated.
    UnsafeSeal,
    /// The parcel format is legacy (no header, raw cipher text).
    LegacyFormat,
}
