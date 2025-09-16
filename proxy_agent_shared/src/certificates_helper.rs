use base64::Engine;
use uuid::Uuid;
use windows::{
    core::{BOOL, PCWSTR, PSTR},
    Win32::{
        Security::Cryptography::{
            szOID_KEY_USAGE, szOID_SUBJECT_KEY_IDENTIFIER, CertCloseStore,
            CertCreateSelfSignCertificate, CertFindCertificateInStore, CertFreeCertificateContext,
            CertOpenStore, CertStrToNameW, CryptAcquireCertificatePrivateKey, CryptEncodeObjectEx,
            CryptExportPublicKeyInfo, CryptHashPublicKeyInfo, CryptMsgClose, CryptMsgControl,
            CryptMsgGetParam, CryptMsgOpenToDecode, CryptMsgUpdate, NCryptCreatePersistedKey,
            NCryptFinalizeKey, NCryptFreeObject, NCryptOpenStorageProvider, NCryptSetProperty,
            CALG_SHA1, CERT_CONTEXT, CERT_DATA_ENCIPHERMENT_KEY_USAGE,
            CERT_DIGITAL_SIGNATURE_KEY_USAGE, CERT_EXTENSION, CERT_EXTENSIONS, CERT_FIND_HASH,
            CERT_KEY_CERT_SIGN_KEY_USAGE, CERT_KEY_ENCIPHERMENT_KEY_USAGE, CERT_KEY_SPEC,
            CERT_OFFLINE_CRL_SIGN_KEY_USAGE, CERT_PUBLIC_KEY_INFO, CERT_STORE_MAXIMUM_ALLOWED_FLAG,
            CERT_STORE_PROV_SYSTEM_W, CERT_SYSTEM_STORE_LOCAL_MACHINE, CERT_X500_NAME_STR,
            CMSG_CTRL_DECRYPT, CMSG_CTRL_DECRYPT_PARA, CMSG_CTRL_DECRYPT_PARA_0,
            CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG, CRYPT_ACQUIRE_COMPARE_KEY_FLAG,
            CRYPT_ACQUIRE_FLAGS, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG, CRYPT_BIT_BLOB,
            CRYPT_INTEGER_BLOB, HCRYPTPROV_OR_NCRYPT_KEY_HANDLE, MS_KEY_STORAGE_PROVIDER,
            NCRYPT_ALLOW_EXPORT_FLAG, NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG,
            NCRYPT_EXPORT_POLICY_PROPERTY, NCRYPT_HANDLE, NCRYPT_KEY_HANDLE,
            NCRYPT_LENGTH_PROPERTY, NCRYPT_PROV_HANDLE, NCRYPT_RSA_ALGORITHM, PKCS_7_ASN_ENCODING,
            X509_ASN_ENCODING,
        },
        System::SystemInformation::GetSystemTime,
    },
};

use crate::client::data_model::error::ErrorDetails;

pub struct CertificateDetails {
    pub public_key_der: Vec<u8>,
    #[cfg(windows)]
    pub p_cert_ctx: *mut CERT_CONTEXT,
    #[cfg(not(windows))]
    pub private_key_der: Vec<u8>,
}

impl Drop for CertificateDetails {
    fn drop(&mut self) {
        if !self.p_cert_ctx.is_null() {
            if !unsafe { CertFreeCertificateContext(Some(self.p_cert_ctx)) }.as_bool() {
                eprintln!("Failed to free certificate context.")
            }
        }
    }
}

pub fn generate_self_signed_certificate(
    subject_name: &str,
) -> Result<CertificateDetails, ErrorDetails> {
    #[cfg(windows)]
    {
        return generate_self_signed_certificate_windows(subject_name);
    }
    #[cfg(not(windows))]
    {
        todo!()
    }
}

#[cfg(windows)]
fn generate_self_signed_certificate_windows(
    subject_name: &str,
) -> Result<CertificateDetails, ErrorDetails> {
    // Open KSP
    let mut h_prov = NCRYPT_PROV_HANDLE(0);
    unsafe {
        NCryptOpenStorageProvider(&mut h_prov, MS_KEY_STORAGE_PROVIDER, 0)?;
    }

    // Create an RSA key
    let key_name: Vec<u16> = Uuid::new_v4().to_string().encode_utf16().collect();
    let mut h_key = NCRYPT_KEY_HANDLE(0);
    unsafe {
        NCryptCreatePersistedKey(
            h_prov,
            &mut h_key,
            NCRYPT_RSA_ALGORITHM,
            PCWSTR(key_name.as_ptr()), // not NULL
            windows::Win32::Security::Cryptography::CERT_KEY_SPEC(0),
            windows::Win32::Security::Cryptography::NCRYPT_FLAGS(0),
        )?;
    }

    let key_length: u32 = 2048;
    unsafe {
        // Set key length property to 2048 bits
        NCryptSetProperty(
            h_key.into(),
            NCRYPT_LENGTH_PROPERTY,
            &key_length.to_ne_bytes(),
            windows::Win32::Security::Cryptography::NCRYPT_FLAGS(0),
        )?;

        // Set key export policy
        NCryptSetProperty(
            h_key.into(),
            NCRYPT_EXPORT_POLICY_PROPERTY,
            &(NCRYPT_ALLOW_EXPORT_FLAG | NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG).to_ne_bytes(),
            windows::Win32::Security::Cryptography::NCRYPT_FLAGS(0),
        )?;

        // Finalize the key
        NCryptFinalizeKey(
            h_key,
            windows::Win32::Security::Cryptography::NCRYPT_FLAGS(0),
        )?;
    }

    // Set up subject name for cert
    let subject = format!("CN={}", subject_name);
    let subject_w: Vec<u16> = subject.encode_utf16().chain(Some(0)).collect();
    let mut size = 0u32;
    unsafe {
        CertStrToNameW(
            X509_ASN_ENCODING,
            PCWSTR(subject_w.as_ptr()),
            CERT_X500_NAME_STR,
            Some(std::ptr::null_mut()),
            Some(std::ptr::null_mut()),
            &mut size,
            Some(std::ptr::null_mut()),
        )?;
    }
    let mut name_buf = vec![0u8; size as usize];
    unsafe {
        CertStrToNameW(
            X509_ASN_ENCODING,
            PCWSTR(subject_w.as_ptr()),
            CERT_X500_NAME_STR,
            None,
            Some(name_buf.as_mut_ptr()),
            &mut size,
            Some(std::ptr::null_mut()),
        )?;
    }

    let subject_blob = CRYPT_INTEGER_BLOB {
        cbData: size,
        pbData: name_buf.as_mut_ptr(),
    };

    // Validity period
    let mut start = unsafe { GetSystemTime() };
    start.wYear -= 1;
    let mut end = unsafe { GetSystemTime() };
    end.wYear += 3;

    let mut exts = build_cert_extensions(HCRYPTPROV_OR_NCRYPT_KEY_HANDLE(h_key.0))?;

    let cert_exts = CERT_EXTENSIONS {
        cExtension: exts.len() as u32,
        rgExtension: exts.as_mut_ptr(),
    };

    // Create cert
    let cert_ctx = unsafe {
        CertCreateSelfSignCertificate(
            Some(HCRYPTPROV_OR_NCRYPT_KEY_HANDLE(h_key.0)),
            &subject_blob,
            windows::Win32::Security::Cryptography::CERT_CREATE_SELFSIGN_FLAGS(0),
            None,
            None,
            Some(&start),
            Some(&end),
            Some(&cert_exts),
        )
    };

    // Get cert data
    let cert_der = unsafe {
        std::slice::from_raw_parts(
            (*cert_ctx).pbCertEncoded,
            (*cert_ctx).cbCertEncoded as usize,
        )
    };

    let res = CertificateDetails {
        public_key_der: cert_der.to_vec(),
        p_cert_ctx: cert_ctx,
    };

    // Cleanup
    unsafe {
        NCryptFreeObject(h_prov.into())?;
        NCryptFreeObject(h_key.into())?;
    };
    Ok(res)
}

#[cfg(windows)]
fn build_cert_extensions(
    h_key: HCRYPTPROV_OR_NCRYPT_KEY_HANDLE,
) -> Result<Vec<CERT_EXTENSION>, ErrorDetails> {
    let mut extensions: Vec<CERT_EXTENSION> = Vec::new();

    // Key Usage
    let key_usage: u8 = CERT_DIGITAL_SIGNATURE_KEY_USAGE as u8
        | CERT_KEY_CERT_SIGN_KEY_USAGE as u8
        | CERT_OFFLINE_CRL_SIGN_KEY_USAGE as u8
        | CERT_KEY_ENCIPHERMENT_KEY_USAGE as u8
        | CERT_DATA_ENCIPHERMENT_KEY_USAGE as u8;

    let key_usage_blob = CRYPT_BIT_BLOB {
        cbData: 1,
        pbData: &key_usage as *const u8 as *mut u8,
        cUnusedBits: 0,
    };

    let mut encoded_key_usage_len: u32 = 0;
    unsafe {
        CryptEncodeObjectEx(
            X509_ASN_ENCODING,
            szOID_KEY_USAGE,
            &key_usage_blob as *const _ as *const _,
            windows::Win32::Security::Cryptography::CRYPT_ENCODE_OBJECT_FLAGS(0),
            None,
            None,
            &mut encoded_key_usage_len,
        )?;
    }

    let mut encoded_key_usage = vec![0u8; encoded_key_usage_len as usize];

    unsafe {
        CryptEncodeObjectEx(
            X509_ASN_ENCODING,
            szOID_KEY_USAGE,
            &key_usage_blob as *const _ as *const _,
            windows::Win32::Security::Cryptography::CRYPT_ENCODE_OBJECT_FLAGS(0),
            None,
            Some(encoded_key_usage.as_mut_ptr() as *mut _),
            &mut encoded_key_usage_len,
        )?;
    }

    extensions.push(CERT_EXTENSION {
        pszObjId: PSTR(szOID_KEY_USAGE.as_ptr() as *mut _),
        fCritical: BOOL(0), // FALSE
        Value: CRYPT_INTEGER_BLOB {
            cbData: encoded_key_usage_len,
            pbData: encoded_key_usage.as_mut_ptr(),
        },
    });

    let mut size = 0;
    unsafe {
        CryptExportPublicKeyInfo(h_key, Some(0), X509_ASN_ENCODING, None, &mut size)?;
    }
    let mut buffer = vec![0u8; size as usize];

    let p_info = buffer.as_mut_ptr() as *mut CERT_PUBLIC_KEY_INFO;

    // Subject Key Identifier (let Windows generate it)
    unsafe {
        CryptExportPublicKeyInfo(h_key, Some(0), X509_ASN_ENCODING, Some(p_info), &mut size)
    }?;

    let mut ski_hash = [0u8; 20];
    let mut ski_size = ski_hash.len() as u32;
    unsafe {
        CryptHashPublicKeyInfo(
            None,
            CALG_SHA1,
            0,
            X509_ASN_ENCODING,
            p_info,
            Some(ski_hash.as_mut_ptr()),
            &mut ski_size,
        )
    }?;

    let ski_blob = CRYPT_INTEGER_BLOB {
        cbData: ski_size,
        pbData: ski_hash.as_mut_ptr(),
    };

    let mut encoded_ski_size = 0;
    unsafe {
        CryptEncodeObjectEx(
            X509_ASN_ENCODING,
            szOID_SUBJECT_KEY_IDENTIFIER,
            &ski_blob as *const _ as *const _,
            windows::Win32::Security::Cryptography::CRYPT_ENCODE_OBJECT_FLAGS(0),
            None,
            None,
            &mut encoded_ski_size,
        )
    }?;

    let mut encoded_ski = vec![0u8; encoded_ski_size as usize];

    unsafe {
        CryptEncodeObjectEx(
            X509_ASN_ENCODING,
            szOID_SUBJECT_KEY_IDENTIFIER,
            &ski_blob as *const _ as *const _,
            windows::Win32::Security::Cryptography::CRYPT_ENCODE_OBJECT_FLAGS(0),
            None,
            Some(encoded_ski.as_mut_ptr() as *mut _),
            &mut encoded_ski_size,
        )
    }?;

    extensions.push(CERT_EXTENSION {
        pszObjId: PSTR(szOID_SUBJECT_KEY_IDENTIFIER.as_ptr() as *mut _),
        fCritical: BOOL(0), // FALSE
        Value: CRYPT_INTEGER_BLOB {
            cbData: encoded_ski_size,
            pbData: encoded_ski.as_mut_ptr(),
        },
    });
    Ok(extensions)
}

pub fn decrypt_from_base64(
    base64_input: &str,
    cert_details: &CertificateDetails,
) -> Result<String, ErrorDetails> {
    #[cfg(windows)]
    {
        return decrypt_from_base64_windows(base64_input, cert_details);
    }
    #[cfg(not(windows))]
    {
        todo!()
    }
}

#[cfg(windows)]
fn decrypt_from_base64_windows(
    base64_input: &str,
    cert_details: &CertificateDetails,
) -> Result<String, ErrorDetails> {
    let encrypted = base64_input.replace("\r", "").replace("\n", "");
    let encrypted_payload = &base64::engine::general_purpose::STANDARD.decode(encrypted)?;
    let p_cert_ctx = cert_details.p_cert_ctx;

    // Acquire the private key handle using the CNG-compatible function.
    let mut h_key = HCRYPTPROV_OR_NCRYPT_KEY_HANDLE(0);
    let mut key_spec = CERT_KEY_SPEC(0u32);
    let mut must_free = BOOL(0);
    unsafe {
        CryptAcquireCertificatePrivateKey(
            p_cert_ctx,
            CRYPT_ACQUIRE_FLAGS(
                CRYPT_ACQUIRE_COMPARE_KEY_FLAG.0
                    | CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG.0
                    | CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG.0,
            ),
            None,
            &mut h_key,
            Some(&mut key_spec),
            Some(&mut must_free),
        )
    }?;

    // Decode the encrypted message.
    let msg_handle = unsafe {
        CryptMsgOpenToDecode(
            X509_ASN_ENCODING.0 | PKCS_7_ASN_ENCODING.0,
            0,
            0,
            None,
            None,
            None,
        )
    };

    if msg_handle.is_null() {
        return Err(ErrorDetails {
            code: -1,
            message: "Failed to open message handle to decrypt.".to_string(),
        });
    }
    unsafe { CryptMsgUpdate(msg_handle, Some(encrypted_payload), true) }?;
    // Create an instance of the nested struct (the union)
    let anonymous_union = CMSG_CTRL_DECRYPT_PARA_0 {
        hCryptProv: h_key.0,
    };

    // Create the main struct instance
    let mut decrypt_para = CMSG_CTRL_DECRYPT_PARA {
        cbSize: std::mem::size_of::<CMSG_CTRL_DECRYPT_PARA>() as u32,
        Anonymous: anonymous_union,
        dwKeySpec: key_spec.0,
        dwRecipientIndex: 0,
    };

    unsafe {
        CryptMsgControl(
            msg_handle,
            0,
            CMSG_CTRL_DECRYPT,
            Some(&mut decrypt_para as *mut _ as *mut _),
        )
    }?;

    // Get the decrypted message size.
    let mut content_size = 0;
    unsafe { CryptMsgGetParam(msg_handle, 2, 0, None, &mut content_size) }?;

    // Get the decrypted message content.
    let mut decrypted_data_buffer = vec![0u8; content_size as usize];
    unsafe {
        CryptMsgGetParam(
            msg_handle,
            2,
            0,
            Some(decrypted_data_buffer.as_mut_ptr() as *mut _),
            &mut content_size,
        )
    }?;

    unsafe { CryptMsgClose(Some(msg_handle)) }?;
    if must_free.as_bool() {
        unsafe { NCryptFreeObject(NCRYPT_HANDLE(h_key.0)) }?;
    }

    let res = String::from_utf8(decrypted_data_buffer)?;
    Ok(res)
}

#[cfg(windows)]
pub fn has_private_key(cert_ctx: *const CERT_CONTEXT) -> bool {
    let mut h_key = HCRYPTPROV_OR_NCRYPT_KEY_HANDLE(0);
    let mut key_spec = CERT_KEY_SPEC(0u32);
    let mut must_free = BOOL(0);

    match unsafe {
        CryptAcquireCertificatePrivateKey(
            cert_ctx,
            CRYPT_ACQUIRE_FLAGS(
                CRYPT_ACQUIRE_COMPARE_KEY_FLAG.0
                    | CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG.0
                    | CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG.0,
            ),
            None,
            &mut h_key,
            Some(&mut key_spec),
            Some(&mut must_free),
        )
    } {
        Ok(_) => {}
        Err(e) => {
            eprintln!("Acquire key error: {}", e);
            return false;
        }
    }

    if h_key.is_invalid() {
        return false;
    }

    if must_free.as_bool() {
        unsafe { NCryptFreeObject(NCRYPT_HANDLE(h_key.0)).unwrap_or(()) };
    }
    return true;
}

/// Convert thumbprint hex string like "AB CD EF 12 ..." into Vec<u8>
fn parse_thumbprint(thumbprint: &str) -> Vec<u8> {
    thumbprint
        .as_bytes()
        .chunks(2)
        .map(|pair| {
            let s = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(s, 16).unwrap()
        })
        .collect()
}

pub fn get_cert_by_thumbprint(
    thumbprint_str: &str,
    store_name: &str,
) -> windows::core::Result<CertificateDetails> {
    let thumbprint = parse_thumbprint(thumbprint_str);
    let mut store_name: Vec<u16> = store_name.encode_utf16().chain(Some(0)).collect();
    unsafe {
        let h_store = CertOpenStore(
            CERT_STORE_PROV_SYSTEM_W,
            windows::Win32::Security::Cryptography::CERT_QUERY_ENCODING_TYPE(0),
            Some(windows::Win32::Security::Cryptography::HCRYPTPROV_LEGACY(0)),
            windows::Win32::Security::Cryptography::CERT_OPEN_STORE_FLAGS(
                CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_MAXIMUM_ALLOWED_FLAG.0,
            ),
            Some(store_name.as_mut_ptr() as *mut _),
        )?;

        if h_store.is_invalid() {
            return Err(windows::core::Error::from_win32());
        }

        let mut hash_blob = CRYPT_INTEGER_BLOB {
            cbData: thumbprint.len() as u32,
            pbData: thumbprint.as_ptr() as *mut u8,
        };

        // Find cert by thumbprint
        let p_cert_context = CertFindCertificateInStore(
            h_store,
            windows::Win32::Security::Cryptography::CERT_QUERY_ENCODING_TYPE(0),
            0,
            CERT_FIND_HASH,
            Some(&mut hash_blob as *mut _ as *const _),
            None,
        );

        CertCloseStore(Some(h_store), 0)?;

        // Get cert data
        let cert_der = std::slice::from_raw_parts(
            (*p_cert_context).pbCertEncoded,
            (*p_cert_context).cbCertEncoded as usize,
        );

        Ok(CertificateDetails {
            public_key_der: cert_der.to_vec(),
            p_cert_ctx: p_cert_context,
        })
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use windows::{
        core::PSTR,
        Win32::Security::Cryptography::{
            szOID_NIST_AES256_CBC, CryptEncryptMessage, CRYPT_ENCRYPT_MESSAGE_PARA,
        },
    };

    #[test]
    fn test_certificate_decryption() {
        let cert = generate_self_signed_certificate(&Uuid::new_v4().to_string()).unwrap();

        let org_str = "Hello, World!";
        let encrypted = encrypt(&cert, org_str);

        let decrypted = decrypt_from_base64(&encrypted, &cert).unwrap();

        assert!(decrypted.eq(org_str))
    }

    fn encrypt(cert: &CertificateDetails, org_str: &str) -> String {
        let mut info = CRYPT_ENCRYPT_MESSAGE_PARA::default();
        info.cbSize = std::mem::size_of::<CRYPT_ENCRYPT_MESSAGE_PARA>() as u32;
        info.dwMsgEncodingType = X509_ASN_ENCODING.0 | PKCS_7_ASN_ENCODING.0;
        info.ContentEncryptionAlgorithm.pszObjId = PSTR(szOID_NIST_AES256_CBC.as_ptr() as *mut _);
        info.dwFlags = 0;
        let cert_ctx_ptrs = [cert.p_cert_ctx as *const _];
        let mut encrypted_size: u32 = 0;
        unsafe {
            CryptEncryptMessage(
                &info,
                &cert_ctx_ptrs,
                Some(org_str.as_bytes()),
                None,
                &mut encrypted_size as *mut u32,
            )
            .unwrap();
        }
        let mut encrypted_data = vec![0u8; encrypted_size as usize];
        unsafe {
            CryptEncryptMessage(
                &info,
                &cert_ctx_ptrs,
                Some(org_str.as_bytes()),
                Some(encrypted_data.as_mut_ptr()),
                &mut encrypted_size as *mut u32,
            )
            .unwrap();
        }
        return base64::engine::general_purpose::STANDARD.encode(&encrypted_data);
    }
}
