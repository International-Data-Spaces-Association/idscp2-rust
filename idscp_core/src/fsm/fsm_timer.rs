// Copyright (c) 2020, Fraunhofer AISEC. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use super::{FiniteStateMachine, FsmEvent};
use cancellable_timer::*;
use std::marker::PhantomData;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

pub(super) struct HandshakeTimer;
pub(super) struct RaTimer;
pub(super) struct DatTimer;
pub(super) struct AckTimer;

pub(super) trait TimerImpl {
    fn create_event() -> FsmEvent;
}

impl TimerImpl for HandshakeTimer {
    fn create_event() -> FsmEvent {
        FsmEvent::HandshakeTimeout
    }
}

impl TimerImpl for RaTimer {
    fn create_event() -> FsmEvent {
        FsmEvent::RaTimeout
    }
}

impl TimerImpl for DatTimer {
    fn create_event() -> FsmEvent {
        FsmEvent::DatTimeout
    }
}

impl TimerImpl for AckTimer {
    fn create_event() -> FsmEvent {
        FsmEvent::AckTimeout
    }
}

pub(super) struct StaticTimer<T: 'static + TimerImpl + Send + Sync> {
    duration: Duration,
    inner: FsmTimer<T>,
}

impl<T: 'static + TimerImpl + Send + Sync> StaticTimer<T> {
    pub(super) fn new(duration: Duration) -> StaticTimer<T> {
        StaticTimer {
            duration,
            inner: FsmTimer::new(),
        }
    }

    pub(super) fn set_fsm(&mut self, fsm: Weak<Mutex<FiniteStateMachine>>) {
        self.inner.fsm = fsm;
    }

    pub(super) fn cancel(&mut self) {
        self.inner.cancel();
    }

    pub(super) fn start(&mut self) {
        self.inner.start(self.duration);
    }
}

pub(super) struct DynamicTimer<T: 'static + TimerImpl + Send + Sync> {
    inner: FsmTimer<T>,
}

impl<T: 'static + TimerImpl + Send + Sync> DynamicTimer<T> {
    pub(super) fn new() -> DynamicTimer<T> {
        DynamicTimer {
            inner: FsmTimer::new(),
        }
    }

    pub(super) fn set_fsm(&mut self, fsm: Weak<Mutex<FiniteStateMachine>>) {
        self.inner.fsm = fsm;
    }

    pub(super) fn cancel(&mut self) {
        self.inner.cancel();
    }

    pub(super) fn start(&mut self, duration: Duration) {
        self.inner.start(duration);
    }
}

struct Content {
    canceller: Canceller,
    cancelled: Arc<Mutex<bool>>,
}

struct FsmTimer<T: 'static + TimerImpl + Send + Sync> {
    content: Option<Content>,
    fsm: Weak<Mutex<FiniteStateMachine>>,
    phantom: PhantomData<T>,
}

impl<T: 'static + TimerImpl + Send + Sync> FsmTimer<T> {
    fn new() -> FsmTimer<T> {
        FsmTimer {
            content: None,
            fsm: Weak::new(),
            phantom: PhantomData,
        }
    }

    fn cancel(&mut self) {
        match self.content.take() {
            None => {}
            Some(c) => {
                {
                    let mut b = c.cancelled.lock().unwrap();
                    (*b) = true;
                }
                let _ = c.canceller.cancel();
                drop(c);
            }
        }
    }

    fn start(&mut self, duration: Duration) {
        // cancel old fsm_timer
        self.cancel();

        let fsm_clone = Weak::clone(&self.fsm);

        let cancelled = Arc::new(Mutex::new(false));
        let cancelled_clone = Arc::clone(&cancelled);

        let (mut timer, canceller) = Timer::new2().unwrap();

        // Spawn a thread that will cancel the timer after `duration`.
        std::thread::spawn(move || {
            let _ = timer.sleep(duration);

            // check if it was cancelled to avoid unnecessary fsm lock
            if *cancelled_clone.lock().unwrap() {
                return;
            }

            // get fsm lock
            match fsm_clone.upgrade() {
                None => {
                    log::error!("Cannot upgrade fsm");
                }
                Some(fsm) => match fsm.lock() {
                    Err(e) => {
                        log::error!("Cannot get fsm lock {}", e);
                    }

                    Ok(mut guard) => {
                        // check once again within in mutex if it was cancelled
                        if !(*cancelled_clone.lock().unwrap()) {
                            let _ = (*guard).process_event(T::create_event());
                        }
                    }
                },
            };
        });

        self.content = Some(Content {
            canceller,
            cancelled,
        });
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use std::io::ErrorKind;
    use std::thread;

    #[test]
    fn test_timer() {
        let (mut timer, canceller) = Timer::new2().unwrap();

        thread::spawn(move || {
            thread::sleep(Duration::from_secs(2));
            let _ = canceller.cancel();
        });

        match timer.sleep(Duration::from_secs(10)) {
            Err(e) => {
                assert_eq!(e.kind(), ErrorKind::Interrupted);
            }
            _ => {}
        }
    }
}
