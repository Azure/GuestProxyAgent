#[cfg(windows)]
use crate::certificate::certificate_helper_windows::CertificateDetailsWindows;
use crate::common::formatted_error::FormattedError;

#[cfg(windows)]
type CertDetailsType = CertificateDetailsWindows;

#[cfg(not(windows))]
type CertDetailsType = ();

pub struct CertificateDetailsWrapper {
    pub cert_details: CertDetailsType,
}

impl CertificateDetailsWrapper {
    pub fn get_public_cert_der(&self) -> &[u8] {
        #[cfg(windows)]
        {
            &self.cert_details.public_key_der
        }
        #[cfg(not(windows))]
        {
            todo!()
        }
    }
}

pub fn generate_self_signed_certificate(
    _subject_name: &str,
) -> Result<CertificateDetailsWrapper, FormattedError> {
    #[cfg(windows)]
    {
        use crate::certificate::certificate_helper_windows::generate_self_signed_certificate_windows;

        generate_self_signed_certificate_windows(_subject_name)
    }
    #[cfg(not(windows))]
    {
        Err("Linux version is not implemented.".to_string().into())
    }
}

pub fn decrypt_from_base64(
    _base64_input: &str,
    _cert_details: &CertificateDetailsWrapper,
) -> Result<String, FormattedError> {
    #[cfg(windows)]
    {
        use crate::certificate::certificate_helper_windows::decrypt_from_base64_windows;

        decrypt_from_base64_windows(_base64_input, _cert_details)
    }
    #[cfg(not(windows))]
    {
        Err("Linux version is not implemented.".to_string().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn certificate_details_wrapper_test() {
        #[cfg(windows)]
        {
            let subject_name = "TestSubject";
            let cert_details_result = generate_self_signed_certificate(subject_name);
            assert!(cert_details_result.is_ok());
            let cert_details = cert_details_result.unwrap();
            let public_cert_der = cert_details.get_public_cert_der();
            assert!(!public_cert_der.is_empty());
        }
        #[cfg(not(windows))]
        {
            // On non-Windows platforms, the function is not implemented.
            // This test will simply ensure that the function is called without panic.
            let subject_name = "TestSubject";
            let cert_details_result = generate_self_signed_certificate(subject_name);
            assert!(cert_details_result.is_err());
        }
    }
}
