use super::algorithm::*;
use super::*;
use alloc::vec;
use alloc::vec::Vec;
use boot_lib::io::{self, ReadAt};
use ring::rand::{SecureRandom, SystemRandom};

/// Parcel header magic for identification
pub const PARCEL_HEADER: &[u8] = b"BOOTRS-parcel";

pub(crate) const ALGORITHM_SPEC_MAX_LEN: usize = 64;

/// ParcelHeader refers to the data that is stored at the beginning,
/// preceding the encrypted stream.
///
/// It contains the cipher triplet and the salt used to derive keys.
pub struct ParcelHeader {
    magic: [u8; PARCEL_HEADER.len()],
    version: u8,
    algorithm_spec_len: u8,
    algorithm_spec: [u8; ALGORITHM_SPEC_MAX_LEN],
    salt: [u8; 32],
}

impl ParcelHeader {
    /// New creates a new ParcelHeader with zeroed out fields.
    pub fn new() -> Self {
        Self {
            magic: [0u8; PARCEL_HEADER.len()],
            version: 1,
            algorithm_spec_len: 0,
            algorithm_spec: [0u8; ALGORITHM_SPEC_MAX_LEN],
            salt: [0u8; 32],
        }
    }

    /// Randomizes the salt field from the system's CSPRNG.
    pub fn randomize_salt(&mut self) -> Result<()> {
        let rand = SystemRandom::new();
        rand.fill(&mut self.salt)
            .or_else(|_| Err(Error::Other("CPRNG failed")))
    }

    /// Set the salt field.
    pub fn set_salt(&mut self, salt: &[u8]) {
        self.salt.copy_from_slice(salt);
    }

    /// Set the cipher triplet.
    pub fn set_algorithm_spec(&mut self, algorithm_spec: &[u8]) {
        self.algorithm_spec_len = algorithm_spec.len() as u8;
        self.algorithm_spec[..algorithm_spec.len()].copy_from_slice(algorithm_spec);
    }

    /// Decode decodes a header from `reader`.
    ///
    /// The returned boolean indicates whether the header was decoded successfully.
    /// If the return value is false, the struct is set to the legacy format
    /// and can be used to encrypt/decrypt legacy (raw) streams.
    ///
    /// At the end of the operation, the reader will be positioned at the
    /// beginning of the encrypted stream.
    pub fn decode<R: ReadAt>(&mut self, reader: &mut io::Cursor<R>) -> Result<bool> {
        let origin = reader.offset();
        let magic_read_len = reader
            .read(&mut self.magic)
            .or_else(|e| Err(Error::IOError(e)))?;

        if magic_read_len != PARCEL_HEADER.len() || self.magic != PARCEL_HEADER {
            reader.seek(origin);
            self.algorithm_spec_len = KEYSPEC_LEGACY.len() as u8;
            self.algorithm_spec[..KEYSPEC_LEGACY.len()].copy_from_slice(KEYSPEC_LEGACY);
            return Ok(false);
        }

        let mut version_buf = [0u8; 1];
        if reader
            .read(&mut version_buf)
            .or_else(|e| Err(Error::IOError(e)))?
            != 1
        {
            return Err(Error::EarlyEOF);
        }

        self.version = version_buf[0];
        if self.version == 0 {
            return Err(Error::InvalidParcelFormat);
        }

        let mut algorithm_spec_len = [0u8; 1];
        if reader
            .read(&mut algorithm_spec_len)
            .or_else(|e| Err(Error::IOError(e)))?
            != 1
        {
            return Err(Error::EarlyEOF);
        }
        self.algorithm_spec_len = algorithm_spec_len[0];
        if self.algorithm_spec_len as usize > ALGORITHM_SPEC_MAX_LEN {
            return Err(Error::Other("Algorithm spec too long"));
        }

        reader
            .read(&mut self.algorithm_spec[..self.algorithm_spec_len as usize])
            .or_else(|e| Err(Error::IOError(e)))?;

        reader
            .read(&mut self.salt)
            .or_else(|e| Err(Error::IOError(e)))?;

        Ok(true)
    }

    /// Encodes the header into a byte vector.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(PARCEL_HEADER);
        buf.push(self.version);
        buf.push(self.algorithm_spec_len);
        buf.extend_from_slice(&self.algorithm_spec[..self.algorithm_spec_len as usize]);
        buf.extend_from_slice(&self.salt);
        buf
    }

    /// Encodes the header into a writer.
    pub fn encode_to(&self, writer: &mut dyn io::Write) -> Result<()> {
        writer
            .write(&self.magic)
            .or_else(|e| Err(Error::IOError(e)))?;
        writer
            .write(&[self.version])
            .or_else(|e| Err(Error::IOError(e)))?;
        writer
            .write(&[self.algorithm_spec_len])
            .or_else(|e| Err(Error::IOError(e)))?;
        writer
            .write(&self.algorithm_spec[..self.algorithm_spec_len as usize])
            .or_else(|e| Err(Error::IOError(e)))?;
        Ok(())
    }

    /// Instantiate an [Algorithm] based on the header.
    ///
    /// The resulting [Algorithm] can be used to encrypt and seal data.
    ///
    /// To encode parcel data, encrypt and then seal the data with the [Algorithm] returned.
    ///
    /// To decode parcel data, unseal and then decrypt the data with the [Algorithm] returned.
    pub fn instantiate_cipher(
        &self,
        pass: &[u8],
        fixed_iv: Option<&[u8]>,
        argon2_config: Argon2Cfg,
    ) -> Result<Algorithm> {
        let keyspec = &self.algorithm_spec[..self.algorithm_spec_len as usize];

        let mut init = InitParams::new_from_keyspec(keyspec)?;
        init.derive_from_password(pass, self.salt, fixed_iv.is_some(), argon2_config)
            .expect("password derivation failed");

        if let Some(fixed_iv) = fixed_iv {
            init.iv = Some(fixed_iv.to_vec());
        }

        Ok(Algorithm::instantiate(keyspec, init)?)
    }
}

impl ParcelHeader {
    /// Convenience function to open a parcel, unseal it and return
    /// the resulting [Algorithm], unsealed data for decryption, and
    /// generates user-facing warnings for unsafe operations.
    pub fn open_parcel_and_unseal<'a, 'b>(
        buf: &'a [u8],
        pass: &'b [u8],
        fixed_salt: Option<[u8; 32]>,
        fixed_iv: Option<&[u8]>,
        argon2_config: Argon2Cfg,
    ) -> Result<(Self, Algorithm, &'a [u8], Option<Vec<Warning>>)> {
        let mut cursor = io::Cursor::new(buf.as_ref());

        let mut header = ParcelHeader::new();
        let is_new_format = header.decode(&mut cursor)?;

        let mut warnings: Option<Vec<Warning>> = None;

        if !is_new_format {
            warnings = warnings.map_or(Some(vec![Warning::LegacyFormat]), |mut v| {
                v.push(Warning::LegacyFormat);
                Some(v)
            });
        }

        if let Some(fixed_salt) = fixed_salt {
            header.set_salt(fixed_salt.as_ref());
        }
        let cipher = header.instantiate_cipher(pass, fixed_iv, argon2_config)?;

        let sealed_data = &buf[cursor.offset() as usize..];

        let (seal_is_secure, encrypted_data) = cipher.unseal(sealed_data)?;

        if !seal_is_secure {
            warnings = warnings.map_or(Some(vec![Warning::UnsafeSeal]), |mut v| {
                v.push(Warning::UnsafeSeal);
                Some(v)
            });
        }

        let offset = unsafe { encrypted_data.as_ptr().offset_from(sealed_data.as_ptr()) };
        assert!(
            offset >= 0 && offset <= sealed_data.len() as isize,
            "offset out of bounds"
        );

        let payload = &sealed_data[offset as usize..];

        Ok((header, cipher, payload, warnings))
    }
}

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeSet;

    use super::*;
    use core::fmt::Debug;

    use crate::algorithm::{Argon2Cfg, InitParams, KEYSPEC_LEGACY};

    fn check_encode_decode<'a, P>(
        encode: Box<dyn Fn(&P) -> Vec<u8>>,
        decode: Box<dyn Fn(&[u8], &P) -> Option<String>>,
        params: &'a [P],
    ) where
        P: Debug,
    {
        for param in params {
            let encoded = encode(param.clone());
            let dec_err = decode(&encoded, param);
            assert_eq!(
                dec_err, None,
                "decode error: {:?}, param: {:?}",
                dec_err, param
            );
        }
    }

    #[test]
    fn parcel_header_encode_decode() {
        use super::*;

        #[derive(Debug, Clone)]
        struct TestCase {
            version: u8,
            algorithm_spec: Vec<u8>,
            should_instantiate: bool,
        }

        let test_params = vec![
            TestCase {
                version: 1,
                algorithm_spec: b"AES256-CFB8-None".to_vec(),
                should_instantiate: true,
            },
            TestCase {
                version: 1,
                algorithm_spec: b"Something-I-Just-Made-Up".to_vec(),
                should_instantiate: false,
            },
            TestCase {
                version: 1,
                algorithm_spec: KEYSPEC_LEGACY.to_vec(),
                should_instantiate: true,
            },
            TestCase {
                version: 1,
                algorithm_spec: KEYSPEC_DEFAULT.to_vec(),
                should_instantiate: true,
            },
        ];

        let pass = b"password";

        check_encode_decode(
            Box::new(|test_case: &TestCase| {
                let mut header = ParcelHeader::new();
                header.version = test_case.version;
                header.algorithm_spec_len = test_case.algorithm_spec.len() as u8;
                header.algorithm_spec[..test_case.algorithm_spec.len()]
                    .copy_from_slice(&test_case.algorithm_spec);
                header.encode()
            }),
            Box::new(|encoded, test_case| {
                let mut header = ParcelHeader::new();

                let is_new_header = header
                    .decode(&mut io::Cursor::new(encoded))
                    .expect("decode should succeed");
                assert_eq!(is_new_header, true, "is_new_header should be true");

                assert_eq!(header.version, test_case.version, "version should match");

                assert_eq!(
                    header.algorithm_spec_len,
                    test_case.algorithm_spec.len() as u8,
                    "algorithm_spec_len should match"
                );

                assert_eq!(
                    &header.algorithm_spec[..test_case.algorithm_spec.len()],
                    &test_case.algorithm_spec[..],
                    "algorithm_spec should match"
                );

                let cipher_init = header.instantiate_cipher(pass, None, Argon2Cfg::tiny());

                match (cipher_init, test_case.should_instantiate) {
                    (Ok(_), false) => Some("cipher should not instantiate".to_string()),
                    (Err(_), true) => Some("cipher should instantiate".to_string()),
                    _ => None,
                }
            }),
            &test_params,
        );
    }

    #[test]
    fn decrypt_legacy_parcel() {
        use crate::legacy;

        let pass = b"password";
        let salt = [2u8; 32];
        let iv = [1u8; 16];
        let data = b"Some data@".repeat(15);

        let legacy_key =
            legacy::derive_with_salt(&pass[..], salt, &legacy::Argon2Config::default()).unwrap();

        {
            let mut init = InitParams::new_from_keyspec(KEYSPEC_LEGACY).unwrap();
            init.derive_from_password(pass, salt, true, Argon2Cfg::default())
                .unwrap();
            init.iv = Some(iv.to_vec());

            assert_eq!(
                legacy_key.key,
                init.key.as_ref(),
                "Derived keys should match"
            );
        }

        let legacy_encrypted =
            legacy::encrypt_boot_image(data.as_ref(), legacy_key.key.as_ref(), iv);

        let mut legacy_encrypted_cursor = io::Cursor::new(&legacy_encrypted[..]);

        let mut parcel_header = ParcelHeader::new();
        let is_new_format = parcel_header.decode(&mut legacy_encrypted_cursor).unwrap();
        assert_eq!(is_new_format, false, "is_new_format should be false");
        parcel_header.set_salt(&salt);

        let cipher = parcel_header
            .instantiate_cipher(pass, Some(iv.as_ref()), Argon2Cfg::default())
            .unwrap();

        let (seal_is_secure, unsealed) = cipher
            .unseal(legacy_encrypted_cursor.remaining_data())
            .expect("unseal should succeed");

        assert_eq!(seal_is_secure, false, "seal_is_secure should be false");

        let mut decrypted = unsealed.to_vec();

        let decrypted = cipher.decrypt(decrypted.as_mut()).unwrap();

        assert_eq!(decrypted, data, "Decrypted data should match");
    }

    #[test]
    fn parcel_marshal_unmarshal() {
        #[derive(Debug, Clone)]
        struct TestCase {
            version: u8,
            algorithm_spec: Vec<u8>,
            fixed_iv: Option<Vec<u8>>,
            fixed_salt: Option<[u8; 32]>,
            data: Vec<u8>,
            expect_warnings: BTreeSet<Warning>,
        }

        let data = b"Some data@".repeat(15);
        let cases = vec![
            TestCase {
                version: 1,
                algorithm_spec: b"AES256-CFB8-None".to_vec(),
                fixed_iv: None,
                fixed_salt: None,
                data: data.clone(),
                expect_warnings: BTreeSet::from([Warning::UnsafeSeal]),
            },
            TestCase {
                version: 1,
                algorithm_spec: b"AES256-GCMSIV-HMACSHA256".to_vec(),
                fixed_iv: None,
                fixed_salt: None,
                data: data.clone(),
                expect_warnings: BTreeSet::new(),
            },
            TestCase {
                version: 1,
                algorithm_spec: KEYSPEC_LEGACY.to_vec(),
                fixed_iv: Some(vec![2u8; 16]),
                fixed_salt: Some([3u8; 32]),
                data: data.clone(),
                expect_warnings: BTreeSet::from([Warning::UnsafeSeal]),
            },
            TestCase {
                version: 1,
                algorithm_spec: KEYSPEC_DEFAULT.to_vec(),
                fixed_iv: None,
                fixed_salt: None,
                data: data.clone(),
                expect_warnings: BTreeSet::new(),
            },
            TestCase {
                version: 1,
                algorithm_spec: KEYSPEC_DEFAULT.to_vec(),
                fixed_iv: Some(vec![2u8; 16]),
                fixed_salt: Some([3u8; 32]),
                data: data.clone(),
                expect_warnings: BTreeSet::new(),
            },
        ];

        check_encode_decode(
            Box::new(|test_case: &TestCase| {
                let mut header = ParcelHeader::new();
                header.version = test_case.version;
                header.set_algorithm_spec(&test_case.algorithm_spec);
                if let Some(fixed_salt) = test_case.fixed_salt {
                    header.set_salt(&fixed_salt);
                }

                let mut parcel = header.encode();

                let iv_clone = test_case.fixed_iv.clone();

                let cipher = header
                    .instantiate_cipher(b"password", iv_clone.as_deref(), Argon2Cfg::tiny())
                    .unwrap();

                let data_clone = test_case.data.clone();

                let encrypted = cipher.encrypt(data_clone).expect("encrypt should succeed");

                let detached_seal = cipher
                    .seal(encrypted.as_ref())
                    .expect("seal should succeed");

                if let Some(detached_seal) = detached_seal {
                    parcel.extend(detached_seal);
                }
                parcel.extend(encrypted);

                parcel
            }),
            Box::new(|parcel, test_case| {
                let (_header, cipher, crypt_data, warnings) = ParcelHeader::open_parcel_and_unseal(
                    parcel,
                    b"password",
                    test_case.fixed_salt,
                    test_case.fixed_iv.as_deref(),
                    Argon2Cfg::tiny(),
                )
                .expect("open_parcel_and_unseal should succeed");

                if test_case.expect_warnings.len() == 0 {
                    assert_eq!(
                        warnings, None,
                        "warnings should be None, but was {:?}",
                        warnings
                    );
                } else {
                    assert!(warnings.is_some(), "warnings should be Some, but was None");
                    assert_eq!(
                        BTreeSet::from_iter(warnings.unwrap().iter().cloned()),
                        test_case.expect_warnings,
                        "warnings should match"
                    );
                }

                let mut decrypted = crypt_data.to_vec();

                let decrypted = cipher
                    .decrypt(decrypted.as_mut())
                    .expect("decrypt should succeed");

                assert_eq!(decrypted, test_case.data, "Decrypted data should match");

                None
            }),
            &cases,
        );
    }
}
