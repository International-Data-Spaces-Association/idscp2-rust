use crate::driver::ra_driver::{DriverId, RaRegistry};
use crate::{RaProverType, RaVerifierType};
use openssl::x509::X509;
use std::time::Duration;

pub(crate) type Certificate = X509;

pub struct IdscpConfig<'a> {
    pub resend_timeout: Duration,
    pub ra_config: &'a AttestationConfig<'a>,
}

pub struct AttestationConfig<'a> {
    // TODO integrate this with IDSCP2Configuration?
    pub ra_timeout: Duration,
    pub supported_provers: Vec<DriverId>,
    pub expected_verifiers: Vec<DriverId>,
    pub prover_registry: &'a RaRegistry<RaProverType>,
    pub verifier_registry: &'a RaRegistry<RaVerifierType>,
    pub peer_cert: X509,
}
