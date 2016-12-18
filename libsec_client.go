// Copyright 2015 ZeroStack, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Client is an object that can be used to generate signed certificates
// using a provided CA. It has an internal serial number that auto-increments
// on each call. TODO: store this SerialNumber in etcd?
//

package libsec

import (
  "crypto/rand"
  "crypto/rsa"
  "crypto/x509/pkix"
  "fmt"
  "math/big"
)

const (
  cDefaultKeySize int = 2048
  cDefaultDays    int = 10 * 365
)

// Client is a libsec client that can be used to generate customer(client)
// certificates.
// TODO: SerialNumber in a more persistent distributed location(etcd?).
type Client struct {
  SerialNumber *big.Int
}

// NewClient creates a new client.
func NewClient() (*Client, error) {
  return &Client{SerialNumber: big.NewInt(1)}, nil
}

// GenKeyAndCert generates a key-pair and signed certificate signed by the
// provided CA. The values are returned as DER encoded slices.
func (c *Client) GenKeyAndCert(ca *CA, name string, client bool) (
  *rsa.PrivateKey, []byte, error) {

  key, err := rsa.GenerateKey(rand.Reader, cDefaultKeySize)
  if err != nil || key == nil {
    return nil, nil, fmt.Errorf("could not generate rsa key: %v", err)
  }

  // auto-increment the serial number.
  defer c.SerialNumber.Add(c.SerialNumber, big.NewInt(1))

  opts := &SignOpts{
    Days:         cDefaultDays,
    SerialNumber: c.SerialNumber,
    ClientAuth:   client,
  }

  cert, err := ca.SignKey(pkix.Name{CommonName: name}, &key.PublicKey, opts)
  if err != nil {
    return nil, nil, fmt.Errorf("error signing key: %v", err)
  }

  return key, cert, nil
}
