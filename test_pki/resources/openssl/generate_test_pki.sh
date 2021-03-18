#!/bin/bash -x
# Copyright (c) 2020, Fraunhofer AISEC. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


# We want to create a RootCA with 2 intermediate CAs that create the client and server credentials

set -e

# Delete previously generated files
for C in `echo root-ca intermediate_test_server intermediate_test_client out`; do
  if [ -d "$C" ]; then rm -Rf $C; fi
done

for C in `echo root-ca intermediate_test_client intermediate_test_server`; do
  mkdir $C
  cd $C
  mkdir certs crl newcerts private
  cd ..

  echo 1000 > $C/serial
  touch $C/index.txt $C/index.txt.attr

  echo '
[ ca ]
default_ca = CA_default
[ CA_default ]
dir            = '$C'                     # Where everything is kept
certs          = $dir/certs               # Where the issued certs are kept
crl_dir        = $dir/crl                 # Where the issued crl are kept
database       = $dir/index.txt           # database index file.
new_certs_dir  = $dir/newcerts            # default place for new certs.
certificate    = $dir/cacert.pem          # The CA certificate
serial         = $dir/serial              # The current serial number
crl            = $dir/crl.pem             # The current CRL
private_key    = $dir/private/rootCA.key.pem  # The private key
RANDFILE       = $dir/.rnd                # private random number file
nameopt        = default_ca
certopt        = default_ca
policy         = policy_match
default_days   = 365
default_md     = sha256

[ policy_match ]
countryName            = optional
stateOrProvinceName    = optional
organizationName       = optional
organizationalUnitName = optional
commonName             = supplied
emailAddress           = optional

[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name

[req_distinguished_name]

[v3_req]
basicConstraints = CA:TRUE
' > $C/openssl.conf
done

# Generate RootCA credentials
openssl genrsa -out root-ca/private/rootCA.key 2048
openssl req -config root-ca/openssl.conf -new -x509 -days 3650 -key root-ca/private/rootCA.key -sha256 -extensions v3_req -out root-ca/certs/rootCA.crt -subj '/C=US/ST=CA/O=MyOrg, Inc./CN=rootca.idscp-tests.de'

# Generate intermediate credentials
for C in `echo test_client test_server`; do
  openssl genrsa -out intermediate_$C/private/intermediate_$C.key 2048
  openssl req -config intermediate_$C/openssl.conf -sha256 -new -key intermediate_$C/private/intermediate_$C.key -out intermediate_$C/certs/intermediate_$C.csr -subj "/C=US/ST=CA/O=MyOrg.inter.$C, Inc./CN=idscp-test.de"
  openssl ca -batch -config root-ca/openssl.conf -keyfile root-ca/private/rootCA.key -cert root-ca/certs/rootCA.crt -extensions v3_req -notext -md sha256 -in intermediate_$C/certs/intermediate_$C.csr -out intermediate_$C/certs/intermediate_$C.crt
done


mkdir out

# Generate client (depending on intermediant client ca) and server credentials (depending on intermediant server ca)
for C in `echo test_client test_server`; do
  openssl req -new -keyout out/$C.key -out out/$C.request -days 365 -nodes -subj "/C=US/ST=CA/O=MyOrg.$C, Inc./CN=idscp-test.de" -newkey rsa:2048
  openssl ca -batch -config root-ca/openssl.conf -keyfile intermediate_$C/private/intermediate_$C.key -cert intermediate_$C/certs/intermediate_$C.crt -out out/$C.crt -infiles out/$C.request
  cat out/$C.crt intermediate_$C/certs/intermediate_$C.crt root-ca/certs/rootCA.crt > out/$C.chain
done

cp root-ca/certs/rootCA.crt out

# Sign golden values file with rootCA priv key
if test -f "golden_values"; then
	openssl dgst -sha256 -sign root-ca/private/rootCA.key -out signed_golden_values golden_values
fi
