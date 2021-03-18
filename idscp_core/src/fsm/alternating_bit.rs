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

// Implementing an Alternating Bit Protocol for reliability
// see (https://en.wikipedia.org/wiki/Alternating_bit_protocol)

use thiserror::Error;

#[derive(Error, Debug)]
#[error("Received wrong alternating bit")]
pub(crate) struct AlternatingBitError {}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum AlternatingBit {
    Zero,
    One,
}

impl AlternatingBit {
    pub(crate) fn new() -> AlternatingBit {
        AlternatingBit::Zero
    }

    pub(crate) fn as_bool(&self) -> bool {
        match self {
            AlternatingBit::Zero => false,
            AlternatingBit::One => true,
        }
    }

    pub(crate) fn from_bool(b: bool) -> AlternatingBit {
        match b {
            false => AlternatingBit::Zero,
            true => AlternatingBit::One,
        }
    }

    pub(crate) fn alternate(&mut self) {
        *self = match self {
            AlternatingBit::Zero => AlternatingBit::One,
            AlternatingBit::One => AlternatingBit::Zero,
        };
    }
}
