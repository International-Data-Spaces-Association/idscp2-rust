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

// public IDSCP2 API
// Daps Driver for accessing and verifying DynamicAttributeToken

use std::time::Duration;

pub trait DapsDriver {
    //type for security requirement validation in the verify token method
    //toDo type SecurityReq;

    fn is_valid(&self) -> bool;

    //get token as string
    fn get_token(&self) -> String;

    //verify token and receive validity_period in seconds in an Option<u64>
    //None if token is not valid
    fn verify_token(
        &mut self,
        token: &[u8],
        //toDo security_requirements: Option<Self::SecurityReq>,
    ) -> Option<Duration>; //TODO return std::Duration

    fn invalidate(&mut self);
}
