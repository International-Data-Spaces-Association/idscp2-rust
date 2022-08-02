use crate::driver::ra_driver::RaRegistry;
use std::time::Duration;

pub struct IdscpConfig<'a> {
    pub resend_timeout: Duration,
    pub ra_config: &'a AttestationConfig,
    pub ra_timeout: Duration,
}

pub struct AttestationConfig {
    // TODO integrate this with IDSCP2Configuration?
    pub ra_timeout: Duration,
    pub supported_provers: RaRegistry,
    pub supported_verifiers: RaRegistry,
}
