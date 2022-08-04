use crate::driver::ra_driver::{RaDriver, RatIcm, RatMessage};
use openssl::x509::X509;
use rust_tpm_verifier::attest::{attest, attest_sync};
use rust_tpm_verifier::verify::verify_attestation_report;
use std::str::from_utf8;
use std::sync::mpsc::{Receiver, Sender};
use tokio::runtime::Runtime;

#[derive(Clone)]
pub struct TpmProver {}

#[cfg(feature = "ra_tpm")]
impl RaDriver for TpmProver {
    fn execute(&self, tx: Sender<RatMessage>, rx: Receiver<RatMessage>, cert: X509) {
        let rt = Runtime::new().unwrap();

        // wait for incoming message from verifier
        match rx.recv() {
            Ok(RatMessage::RawData(data)) => {
                // TODO analyze message
            }
            Ok(RatMessage::ControlMessage(_)) => {
                // TODO what to do with this? Should a control message from the connection/fsm
                // happen?
                return;
            }
            Err(_) => {
                return;
            }
        }

        let host = "";
        let id = "";
        let port = 0;
        let nonce = [0; 0];

        // TODO
        match attest_sync(host, id, port, &nonce).await {
            Ok(..) => {
                let msg = [0; 0]; // TODO
                tx.send(RatMessage::RawData(msg.to_vec()));
                tx.send(RatMessage::ControlMessage(RatIcm::OK));
            }
            Err(_) => {}
        }
    }

    fn get_id(&self) -> &'static str {
        "tpm.prover" // TODO
    }
}

#[derive(Clone)]
pub struct TpmVerifier {}

#[cfg(feature = "ra_tpm")]
impl RaDriver for TpmVerifier {
    fn execute(&self, tx: Sender<RatMessage>, rx: Receiver<RatMessage>, cert: X509) {
        let cert_pem = match cert.to_pem() {
            Ok(vec) => vec,
            Err(_) => {
                return;
            }
        };
        let nonce = [0; 0];
        let msg = [0; 0]; // TODO

        if let Err(_) = tx.send(RatMessage::RawData(msg.to_vec())) {
            return;
        }

        let report = match rx.recv() {
            Ok(RatMessage::RawData(data)) => match from_utf8(data.as_slice()) {
                Ok(data) => data,
                Err(_) => {
                    return;
                }
            },
            Ok(RatMessage::ControlMessage(_)) => {
                // TODO what to do with this? Should a control message from the connection/fsm
                // happen?
                return;
            }
            Err(_) => {
                return;
            }
        };

        let result = verify_attestation_report(report, &cert_pem, &nonce);

        if result.success {
            tx.send(RatMessage::ControlMessage(RatIcm::OK));
        } else {
            tx.send(RatMessage::ControlMessage(RatIcm::Failed));
        }
    }

    fn get_id(&self) -> &'static str {
        "tpm.prover" // TODO
    }
}
