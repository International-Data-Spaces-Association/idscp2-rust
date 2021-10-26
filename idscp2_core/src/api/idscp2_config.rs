use std::time::Duration;

pub struct IdscpConfig<'a> {
    pub resend_timeout: Duration,
    pub ra_config: &'a AttestationConfig,
}

pub struct AttestationConfig {
    // TODO integrate this with IDSCP2Configuration?
    // TODO: rename to "supported_provers" and "supported verifiers"
    pub supported_attestation_suite: Vec<String>,
    pub expected_attestation_suite: Vec<String>,
    pub ra_timeout: Duration,
}
