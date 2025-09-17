
use crate::{client::data_model::error::ErrorDetails};

pub trait CertificateDetails {
    type CertificateContext;
    fn get_certificate_context(&self) -> &Self::CertificateContext;
    fn set_certificate_context(&mut self, cert_context: Self::CertificateContext);
    fn get_public_cert_der(&self) -> &[u8];
}

#[cfg(windows)]
use windows::Win32::Security::Cryptography::CERT_CONTEXT;
#[cfg(windows)] 
type CertCtxType = *mut CERT_CONTEXT;

#[cfg(not(windows))]
type CertCtxType = ();

pub fn generate_self_signed_certificate(subject_name: &str) -> Result<impl CertificateDetails<CertificateContext = CertCtxType>, ErrorDetails> {
    #[cfg(windows)]
    {
        use crate::certificate::certificate_helper_windows::generate_self_signed_certificate_windows;

        return generate_self_signed_certificate_windows(subject_name);
    }
    
    #[cfg(not(windows))]
    {
        Err(ErrorDetails { message: "Not Implemented.".to_string(), code: -1 })
    }
}

pub fn decrypt_from_base64(
    base64_input: &str,
    cert_details: &impl CertificateDetails<CertificateContext = CertCtxType>
) -> Result<String, ErrorDetails> {
    #[cfg(windows)]
    {
        use crate::certificate::certificate_helper_windows::decrypt_from_base64_windows;

        return decrypt_from_base64_windows(base64_input, cert_details);
    }

    #[cfg(not(windows))]
    {
        Err(ErrorDetails { message: "Not Implemented.".to_string(), code: -1 })
    }
}
