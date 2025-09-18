use crate::client::data_model::error::ErrorDetails;

#[cfg(windows)]
use crate::certificate::certificate_helper_windows::CertificateDetailsWindows;

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
) -> Result<CertificateDetailsWrapper, ErrorDetails> {
    #[cfg(windows)]
    {
        use crate::certificate::certificate_helper_windows::generate_self_signed_certificate_windows;

        generate_self_signed_certificate_windows(_subject_name)
    }
    #[cfg(not(windows))]
    {
        todo!()
    }
}

pub fn decrypt_from_base64(
    _base64_input: &str,
    _cert_details: &CertificateDetailsWrapper,
) -> Result<String, ErrorDetails> {
    #[cfg(windows)]
    {
        use crate::certificate::certificate_helper_windows::decrypt_from_base64_windows;

        decrypt_from_base64_windows(_base64_input, _cert_details)
    }

    #[cfg(not(windows))]
    {
        todo!()
    }
}
