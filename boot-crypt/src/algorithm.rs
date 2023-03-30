use aes::cipher::{BlockDecryptMut, BlockEncryptMut, InnerIvInit, KeyInit};
use aes_gcm_siv::aead::Aead;
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use hmac::{Hmac, Mac};

use super::*;

pub(crate) const MAGIC_SEAL: [u8; 16] = *b"DECRYPTED_KERNEL";

/// The legacy, unsafe, magic-then-cfb8 encryption scheme.
pub const KEYSPEC_LEGACY: &[u8] = b"AES256-CFB8-UNSAFEMAGIC";

/// The preferred encryption scheme.
pub const KEYSPEC_DEFAULT: &[u8] = b"AES256-CFB8-HMACSHA256";

pub(crate) fn pkcs7_pad(data: &mut Vec<u8>, block_size: usize) {
    if block_size < 2 {
        return;
    }

    let padding_len = block_size - (data.len() % block_size);
    data.resize(data.len() + padding_len, padding_len as u8);
}

pub(crate) fn pkcs7_unpad<'a>(data: &'a [u8], block_size: usize) -> Result<&'a [u8]> {
    if block_size < 2 {
        return Ok(data);
    }

    let padding_len = data[data.len() - 1] as usize;

    if padding_len == 0 {
        for i in (data.len() - 1)..1 {
            if data[i] != 0 {
                return Ok(&data[..i + 1]);
            }
        }
    }

    if padding_len > block_size {
        return Err(Error::InvalidPadding);
    }
    for i in 1..=padding_len {
        if data[data.len() - i] != padding_len as u8 {
            return Err(Error::InvalidPadding);
        }
    }
    Ok(&data[..data.len() - padding_len])
}

/// Parameters for Argon2 KDF.
pub struct Argon2Cfg {
    /// p_cost
    pub lanes: u32,
    /// m_cost
    pub mem_cost: u32,
    /// t_cost
    pub time_cost: u32,
}

impl core::default::Default for Argon2Cfg {
    fn default() -> Self {
        Self {
            lanes: 4,
            mem_cost: 65536,
            time_cost: 10,
        }
    }
}

#[cfg(test)]
impl Argon2Cfg {
    /// Fast configuration for testing.
    pub fn tiny() -> Self {
        Self {
            lanes: 4,
            mem_cost: 64,
            time_cost: 1,
        }
    }
}

/// Parameters for instantiating stream ciphers.
#[derive(Debug, Clone)]
pub struct InitParams {
    pub(crate) key: Vec<u8>,
    pub(crate) iv: Option<Vec<u8>>,
    pub(crate) nonce: Option<Vec<u8>>,
}

impl InitParams {
    /// From raw key and parameters.
    pub fn from_slice(key: &[u8], iv: Option<&[u8]>, nonce: Option<&[u8]>) -> Self {
        Self {
            key: key.to_vec(),
            iv: iv.map(|v| v.to_vec()),
            nonce: nonce.map(|v| v.to_vec()),
        }
    }

    /// Create a template for the given keyspec.
    ///
    /// All necessary fields will be zeroed.
    /// They need to be filled in before use.
    pub fn new_from_keyspec(keyspec: &[u8]) -> Result<Self> {
        let keyspec_str = core::str::from_utf8(keyspec).or_else(|_| Err(Error::InvalidKeySpec))?;
        let keyspec_split: Vec<&str> = keyspec_str.split('-').collect();

        if keyspec_split.len() != 3 {
            return Err(Error::InvalidKeySpec);
        }

        let (keyspec_cipher, keyspec_mode) = (keyspec_split[0], keyspec_split[1]);

        match (
            keyspec_cipher.to_uppercase().as_str(),
            keyspec_mode.to_uppercase().as_str(),
        ) {
            ("AES256", "GCMSIV") => Ok(InitParams {
                key: vec![0u8; 32],
                iv: None,
                nonce: Some(vec![0u8; 12]),
            }),
            ("AES256", "CFB8") => Ok(InitParams {
                key: vec![0u8; 32],
                iv: Some(vec![0u8; 16]),
                nonce: None,
            }),
            _ => Err(Error::InvalidKeySpec),
        }
    }

    /// Derive a set of parameters using a password and Argon2 KDF.
    ///
    /// The derivation is done by splitting the KDF output into the key and IV and nonce when needed.
    ///
    /// If fixed_iv is set, the IV will not be derived from the password.
    /// This is largely for backwards compatibility with the legacy encryption scheme.
    ///
    /// Salt should be different each time encryption is done.
    /// This ensures that the nonce is different each time.
    pub fn derive_from_password(
        &mut self,
        pass: &[u8],
        salt: [u8; 32],
        fixed_iv: bool,
        params: Argon2Cfg,
    ) -> core::result::Result<(), String> {
        let key_len = self.key.len();
        let iv_len = self.iv.as_ref().map(|x| x.len()).unwrap_or(0);
        let nonce_len = self.nonce.as_ref().map(|x| x.len()).unwrap_or(0);

        let derive_len = self.key.len() + if fixed_iv { 0 } else { iv_len } + nonce_len;

        let mut buf = vec![0u8; derive_len];

        argon2::Argon2::new(
            argon2::Algorithm::Argon2i,
            argon2::Version::V0x13,
            argon2::Params::new(
                params.mem_cost,
                params.time_cost,
                params.lanes,
                Some(derive_len),
            )
            .map_err(|e| format!("ERROR: Failed to instantiate argon2 parameters: {e}"))?,
        )
        .hash_password_into(pass, &salt, &mut buf)
        .unwrap();

        let mut offset = 0;
        self.key.copy_from_slice(&buf[offset..offset + key_len]);
        offset += self.key.len();

        if !fixed_iv {
            if let Some(iv) = self.iv.as_mut() {
                iv.copy_from_slice(&buf[offset..offset + iv_len]);
                offset += iv.len();
            }
        }

        if let Some(nonce) = self.nonce.as_mut() {
            nonce.copy_from_slice(&buf[offset..offset + nonce_len]);
            offset += nonce.len();
        }
        debug_assert_eq!(offset, derive_len);

        Ok(())
    }
}

/// Algorithm is the cipher-mode-seal triplet for authenticating and encrypting streams.
#[derive(Debug, Clone)]
pub struct Algorithm {
    /// the block cipher used
    pub cipher: CipherOption,
    /// the mode of operation
    pub mode: CipherModeOption,
    /// the seal used
    pub seal: SealOption,
}

impl core::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}-{}-{}", self.cipher, self.mode, self.seal)
    }
}

impl Algorithm {
    /// Seals the encrypted data, returning the detached seal,
    /// which is expected to be prepended before the encrypted data.
    pub fn seal(&self, encrypted: &[u8]) -> Result<Option<Vec<u8>>> {
        match &self.seal {
            SealOption::None => Ok(None),
            // handled in encryption
            SealOption::MagicThenEncrypt => {
                let seal = if MAGIC_SEAL.len() % self.block_size() != 0 {
                    let mut inner = MAGIC_SEAL.to_vec();
                    pkcs7_pad(&mut inner, self.block_size());
                    inner
                } else {
                    MAGIC_SEAL.to_vec()
                };

                let mut buf = seal.to_vec();

                self.encrypt_nopad(&mut buf, false)?;

                Ok(Some(buf))
            }
            SealOption::HMACSHA256(hmac) => {
                let mut hmac = hmac.clone();

                hmac.update(encrypted);

                let result = hmac.finalize().into_bytes();

                Ok(Some(result.to_vec()))
            }
        }
    }

    pub fn unseal_mut<'b>(&self, sealed: &'b mut [u8]) -> Result<(bool, &'b mut [u8])> {
        let (verified, data) = self.unseal(sealed)?;
        let offset = unsafe {
            let data_ptr = data.as_ptr();
            let sealed_ptr = sealed.as_ptr();
            data_ptr.offset_from(sealed_ptr) as usize
        };
        assert!(offset <= sealed.len());

        Ok((verified, &mut sealed[offset..]))
    }

    /// Takes the expected seal from the stream, verifies it, and returns the raw encrypted data
    /// which is guaranteed to be a sub slice of the input.
    ///
    /// The first return value is true if the seal is verified securely.
    /// For AEAD ciphers this is always true and authentication errors are returned as decryption errors.
    pub fn unseal<'b>(&self, sealed: &'b [u8]) -> Result<(bool, &'b [u8])> {
        let ret = match &self.seal {
            SealOption::None => match self.mode {
                CipherModeOption::GCMSIV(_) => Ok((true, sealed)),
                _ => Ok((false, sealed)),
            },

            SealOption::MagicThenEncrypt => {
                let seal = MAGIC_SEAL.to_vec();
                assert_eq!(
                    0,
                    seal.len() % self.output_block_size(),
                    "seal must be a multiple of output block size"
                );

                let mut buf = vec![0u8; seal.len()];
                buf.copy_from_slice(sealed[..seal.len()].as_ref());

                self.decrypt_nopad(&mut buf, false)?;

                if buf[..seal.len()] != seal[..] {
                    Err(Error::InvalidSeal)
                } else {
                    Ok((false, &sealed[seal.len()..]))
                }
            }

            SealOption::HMACSHA256(hmac) => {
                let mut hmac = hmac.clone();

                let hmac_read = &sealed[..32];

                hmac.update(&sealed[32..]);

                hmac.verify_slice(&hmac_read)
                    .or_else(|_| Err(Error::InvalidSeal))?;

                Ok((true, &sealed[32..]))
            }
        }?;

        debug_assert!(
            {
                let offset = unsafe {
                    let data_ptr = ret.1.as_ptr();
                    let sealed_ptr = sealed.as_ptr();
                    data_ptr.offset_from(sealed_ptr)
                };
                offset >= 0 && offset <= sealed.len() as isize
            },
            "unseal must return a sub slice of the input"
        );

        Ok(ret)
    }
}

impl Algorithm {
    pub(crate) fn block_size(&self) -> usize {
        match &self.cipher {
            CipherOption::AES256(_) => 16,
        }
    }

    pub(crate) fn output_block_size(&self) -> usize {
        match &self.cipher {
            CipherOption::AES256(_) => match &self.mode {
                CipherModeOption::CFB8(_) => 1,
                CipherModeOption::GCMSIV(_) => 16,
            },
        }
    }

    pub(crate) fn decrypt_nopad<'a>(
        &self,
        data: &'a mut [u8],
        opaque_seal: bool,
    ) -> Result<&'a mut [u8]> {
        match &self.cipher {
            CipherOption::AES256(cipher_key) => match &self.mode {
                CipherModeOption::CFB8(iv) => {
                    let mut cipher =
                        cfb8::Decryptor::inner_iv_slice_init(cipher_key, iv.as_ref()).unwrap();

                    if opaque_seal {
                        match &self.seal {
                            SealOption::MagicThenEncrypt => {
                                let mut magic_copy = MAGIC_SEAL.to_vec();

                                self.encrypt_nopad(&mut magic_copy, false)?;

                                for block in magic_copy.chunks_exact_mut(self.output_block_size()) {
                                    cipher.decrypt_block_mut(block.into());
                                }
                            }
                            _ => {}
                        }
                    }

                    for block in data.chunks_exact_mut(self.output_block_size()) {
                        cipher.decrypt_block_mut(block.into());
                    }

                    Ok(data)
                }
                CipherModeOption::GCMSIV(nonce) => {
                    let cipher = aes_gcm_siv::AesGcmSiv::from(cipher_key.clone());
                    let nonce: &[u8] = nonce.as_ref();

                    let decrypted = cipher
                        .decrypt(nonce.into(), data.as_ref())
                        .or_else(|_| Err(Error::DecryptionError))?;

                    data[..decrypted.len()].copy_from_slice(&decrypted[..decrypted.len()]);

                    Ok(&mut data[..decrypted.len()])
                }
            },
        }
    }

    /// Decrypts the data in place, returning a slice of the decrypted data.
    pub fn decrypt<'a>(&self, data: &'a mut [u8]) -> Result<&'a [u8]> {
        let data = self.decrypt_nopad(data, true)?;

        Ok(pkcs7_unpad(data, self.output_block_size())?)
    }

    pub(crate) fn encrypt_nopad(
        &self,
        data: &mut [u8],
        opaque_seql: bool,
    ) -> Result<Option<Vec<u8>>> {
        match &self.cipher {
            CipherOption::AES256(cipher) => match &self.mode {
                CipherModeOption::CFB8(iv) => {
                    let mut cipher = cfb8::Encryptor::inner_iv_slice_init(cipher, iv.as_ref())
                        .or_else(|_| Err(Error::EncryptionError))?;

                    if opaque_seql {
                        match &self.seal {
                            SealOption::MagicThenEncrypt => {
                                let mut magic_copy = MAGIC_SEAL.to_vec();

                                for block in magic_copy.chunks_exact_mut(self.output_block_size()) {
                                    cipher.encrypt_block_mut(block.into());
                                }
                            }
                            _ => {}
                        }
                    }

                    for block in data.chunks_exact_mut(self.output_block_size()) {
                        cipher.encrypt_block_mut(block.into());
                    }

                    Ok(None)
                }
                CipherModeOption::GCMSIV(nonce) => {
                    let cipher = aes_gcm_siv::AesGcmSiv::from(cipher.clone());
                    let nonce: &[u8] = nonce.as_ref();

                    let encrypt_result = cipher
                        .encrypt(nonce.into(), data.as_ref())
                        .or_else(|_| Err(Error::EncryptionError))?;

                    Ok(Some(encrypt_result))
                }
            },
        }
    }

    /// Encrypts the data maybe in place, return encrypted data.
    ///
    /// This is needed because AEAD ciphers need more space.
    pub fn encrypt(&self, data: Vec<u8>) -> Result<Vec<u8>> {
        let mut data = data;
        pkcs7_pad(&mut data, self.output_block_size());
        match self.encrypt_nopad(&mut data, true)? {
            Some(encrypted) => Ok(encrypted),
            None => Ok(data),
        }
    }
}

impl Algorithm {
    /// Instantiates the algorithm based on the triplet string and initialization parameters.
    pub fn instantiate(keyspec: &[u8], params: InitParams) -> Result<Self> {
        let key = params.key.as_ref();
        let iv = params.iv;
        let nonce = params.nonce;

        let keyspec_str =
            core::str::from_utf8(keyspec).or_else(|_| Err(Error::Other("Invalid key spec")))?;

        let keyspec_split: Vec<&str> = keyspec_str.split('-').collect();

        if keyspec_split.len() != 3 {
            return Err(Error::InvalidKeySpec);
        }

        let (keyspec_cipher, keyspec_mode, keyspec_seal) =
            (keyspec_split[0], keyspec_split[1], keyspec_split[2]);

        let field_cipher: CipherOption;
        let field_mode: CipherModeOption;
        let field_seal: SealOption;

        match keyspec_cipher.to_uppercase().as_str() {
            "AES256" => {
                field_cipher = CipherOption::AES256(aes::Aes256::new_from_slice(key).unwrap());
            }
            _ => return Err(Error::InvalidKeySpec),
        }

        match keyspec_mode.to_uppercase().as_str() {
            "CFB8" => {
                if let Some(iv) = iv {
                    field_mode = CipherModeOption::CFB8(iv);
                } else {
                    return Err(Error::InvalidKeySpec);
                }
            }
            "GCMSIV" => {
                if let Some(nonce) = nonce {
                    if nonce.len() != 12 {
                        return Err(Error::InvalidKeySpec);
                    }
                    field_mode = CipherModeOption::GCMSIV(nonce);
                } else {
                    return Err(Error::InvalidKeySpec);
                }
            }
            _ => return Err(Error::InvalidKeySpec),
        }

        match keyspec_seal.to_uppercase().as_str() {
            "NONE" => {
                field_seal = SealOption::None;
            }
            "UNSAFEMAGIC" => {
                field_seal = SealOption::MagicThenEncrypt;

                // Magic then encrypt is only possible for non AEAD modes
                if keyspec_mode.to_uppercase().as_str() != "CFB8" {
                    return Err(Error::InvalidKeySpec);
                }
            }
            "HMACSHA256" => {
                field_seal = SealOption::HMACSHA256(Mac::new_from_slice(key).unwrap());
            }
            _ => return Err(Error::InvalidKeySpec),
        }

        Ok(Self {
            cipher: field_cipher,
            mode: field_mode,
            seal: field_seal,
        })
    }
}

/// The first part of the triplet. The block cipher used.
#[derive(Debug, Clone)]
pub enum CipherOption {
    AES256(aes::Aes256),
}

impl core::fmt::Display for CipherOption {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CipherOption::AES256(_) => write!(f, "AES256"),
        }
    }
}

/// The second part of the triplet. The mode of operation.
#[derive(Debug, Clone)]
pub enum CipherModeOption {
    CFB8(IV),
    GCMSIV(Nonce),
}

impl core::fmt::Display for CipherModeOption {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CipherModeOption::CFB8(_) => write!(f, "CFB8"),
            CipherModeOption::GCMSIV(_) => write!(f, "GCMSIV"),
        }
    }
}

type HmacSha256 = Hmac<sha2::Sha256>;

/// The third part of the triplet. The seal method.
#[derive(Debug, Clone)]
pub enum SealOption {
    /// No seal, usually used for AEAD ciphers
    None,
    /// The old magic method,
    /// only implemented for CFB8
    ///
    /// For backwards compatibility
    MagicThenEncrypt,
    HMACSHA256(HmacSha256),
}

impl core::fmt::Display for SealOption {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SealOption::None => write!(f, "None"),
            SealOption::MagicThenEncrypt => write!(f, "UNSAFEMAGIC"),
            SealOption::HMACSHA256(_) => write!(f, "HMACSHA256"),
        }
    }
}

pub type IV = Vec<u8>;
pub type Nonce = Vec<u8>;

#[cfg(test)]
mod tests {
    use core::borrow::BorrowMut;

    use super::*;

    const KEYSPEC_AES256_CFB8_NONE: &[u8] = b"AES256-CFB8-None";
    const KEYSPEC_AES256_CFB8_MAGIC: &[u8] = b"AES256-CFB8-UNSAFEMAGIC";
    const KEYSPEC_AES256_CFB8_HMACSHA256: &[u8] = b"AES256-CFB8-HMACSHA256";
    const KEYSPEC_AES256_GCMSIV_NONE: &[u8] = b"AES256-GCMSIV-None";
    const KEYSPEC_INVALID_AES256: &[u8] = b"AES256--";

    #[test]
    pub fn test_algorithm_instantiation() {
        let key = b"0123456789abcdef0123456789abcdef";
        let iv = b"0123456789abcdef";
        let nonce = b"0123456789ab";

        let init = InitParams::from_slice(key, Some(iv), None);
        let ret = Algorithm::instantiate(KEYSPEC_AES256_CFB8_NONE, init);

        assert!(ret.is_ok(), "Algorithm instantiation failed: {:?}", ret);

        let init = InitParams::from_slice(key, Some(iv), None);
        let ret = Algorithm::instantiate(KEYSPEC_AES256_CFB8_MAGIC, init);

        assert!(ret.is_ok(), "Algorithm instantiation failed: {:?}", ret);

        let init = InitParams::from_slice(key, Some(iv), None);
        let ret = Algorithm::instantiate(KEYSPEC_AES256_CFB8_HMACSHA256, init);
        assert!(ret.is_ok(), "Algorithm instantiation failed: {:?}", ret);

        let init = InitParams::from_slice(key, None, Some(nonce));
        let ret = Algorithm::instantiate(KEYSPEC_AES256_GCMSIV_NONE, init);
        assert!(ret.is_ok(), "Algorithm instantiation failed: {:?}", ret);

        let init = InitParams::from_slice(key, None, Some(nonce));
        let ret = Algorithm::instantiate(KEYSPEC_INVALID_AES256, init);
        assert!(ret.is_err(), "Algorithm instantiation succeeded");
        assert_eq!(
            ret.unwrap_err(),
            Error::InvalidKeySpec,
            "Algorithm instantiation succeeded"
        );
    }

    pub fn random_data(size: usize) -> Vec<u8> {
        let mut data = Vec::with_capacity(size);
        for i in 0..size {
            data.push((i * i / 2 + i + i << 2 * (i % 4)) as u8);
        }
        data
    }

    pub fn algo_consistency_test(algo: Algorithm, aead: bool, sealed: bool, seal_safe: bool) {
        eprintln!("Testing algorithm consistency: {}", algo);
        for datasize in [16, 7, 1, 23, 1024, 2047, 12345].iter() {
            let data = random_data(*datasize);

            let encrypted = algo.encrypt(data.clone()).unwrap();

            let mut encrypted_copy = encrypted.clone();
            let decrypted = algo.decrypt(encrypted_copy.borrow_mut()).unwrap();

            assert_eq!(
                data, decrypted,
                "Decrypted data is not the same as original"
            );

            if aead {
                for place_to_flip in (0..encrypted.len()).step_by(12) {
                    let mut encrypted_mut = encrypted.clone();
                    encrypted_mut[place_to_flip] ^= 0b10101010;
                    let decrypted = algo.decrypt(encrypted_mut.borrow_mut());
                    assert!(
                        decrypted.is_err(),
                        "Decryption succeeded with corrupted data"
                    );
                }
            }

            let detached_seal = algo.seal(&encrypted).expect("sealing should not fail");

            if sealed {
                assert!(detached_seal.is_some(), "seal should be present");
                let detached_seal = detached_seal.unwrap();

                let mut full_payload = detached_seal.clone();
                full_payload.extend_from_slice(&encrypted);

                let (seal_secure, unsealed) = algo
                    // unseal_mut is not necessary here, just to go for the extra coverage
                    .unseal_mut(&mut full_payload)
                    .expect("unsealing should not fail");

                if seal_safe {
                    assert_eq!(seal_secure, true, "seal should be secure");

                    for place_to_flip in 0..(detached_seal.len()) {
                        let mut mutated_seal = detached_seal.clone();

                        mutated_seal[place_to_flip] ^= 0b10101010;

                        let mut full_payload = mutated_seal;
                        full_payload.extend_from_slice(&encrypted);

                        let unseal_result = algo.unseal(&full_payload);
                        assert!(
                            unseal_result.is_err(),
                            "unsealing should fail with corrupted seal"
                        );
                    }

                    for place_to_flip in (0..(encrypted.len())).step_by(12) {
                        let mut mutated_payload = encrypted.clone();

                        mutated_payload[place_to_flip] ^= 0b10101010;

                        let mut full_payload = detached_seal.clone();
                        full_payload.extend_from_slice(&mutated_payload);

                        let unseal_result = algo.unseal(&full_payload);
                        assert!(
                            unseal_result.is_err(),
                            "unsealing should fail with corrupted payload"
                        );
                    }
                }

                assert_eq!(unsealed, encrypted, "unsealed data should match");
            } else {
                assert!(detached_seal.is_none(), "seal should not be present");
            }
        }
        eprintln!("Pass");
    }

    #[test]
    pub fn test_algorithm_consistency() {
        let key = b"0123456789abcdef0123456789abcdef";
        let iv = b"0123456789abcdef";
        let nonce = b"0123456789ab";

        let init = InitParams::from_slice(key, Some(iv), None);
        let algo = Algorithm::instantiate(KEYSPEC_AES256_CFB8_NONE, init).unwrap();
        algo_consistency_test(algo, false, false, false);

        let init = InitParams::from_slice(key, Some(iv), None);
        let algo = Algorithm::instantiate(KEYSPEC_AES256_CFB8_MAGIC, init).unwrap();
        algo_consistency_test(algo, false, true, false);

        let init = InitParams::from_slice(key, Some(iv), None);
        let algo = Algorithm::instantiate(KEYSPEC_AES256_CFB8_HMACSHA256, init).unwrap();
        algo_consistency_test(algo, false, true, true);

        let init = InitParams::from_slice(key, None, Some(nonce));
        let algo = Algorithm::instantiate(KEYSPEC_AES256_GCMSIV_NONE, init).unwrap();
        algo_consistency_test(algo, true, false, true);
    }
}
