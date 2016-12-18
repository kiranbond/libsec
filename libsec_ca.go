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
// Package with the utility functions for servers and clients to manage
// certificates and keys.
//
// This file contains the routines for Certificate Authority. We should not
// need to create CA on the fly but it is there so we can use it in tests.

package libsec

import (
  "bytes"
  "fmt"
  "math/big"
  "time"

  "crypto/rand"
  "crypto/rsa"
  "crypto/x509"
  "crypto/x509/pkix"
  "encoding/pem"
)

// A CA represents a CA certificate and private key.
type CA struct {
  *x509.Certificate
  PrivateKey *rsa.PrivateKey
}

// CAOpts encapsulates lesser-used options for NewCA.
type CAOpts struct {
  KeyBits      int      // key length in bits (default is 4096)
  ValidDays    int      // validity period in days (default is 365)
  SerialNumber *big.Int // serial number (default is 1)
  AltNames     []string // subject alternate names
  AltEmails    []string // subject email addresses
}

// SetDefaults sets zeroed values of the options struct to their default values.
// A newly allocated CAOpts is returned if opts was nil.
func (opts *CAOpts) SetDefaults() *CAOpts {
  if opts == nil {
    opts = new(CAOpts)
  }
  if opts.KeyBits == 0 {
    opts.KeyBits = 4096
  }
  if opts.ValidDays == 0 {
    opts.ValidDays = cDefaultDays
  }
  if opts.SerialNumber == nil {
    opts.SerialNumber = big.NewInt(1)
  }
  return opts
}

// NewCA generates a CA certificate with the given DN using the given options.
// If opts is nil, the default options are used. This is usually done only
// once manually and then the CA is stored in Cassandra. Each process which
// needs to generate a client key and sign it needs to securely load this
// CA from Cassandra and use it to generate client keys.
//
// If opts is provided, zeroed fields are set to their defaults.  The serial
// number will be incremented before NewCA returns, so it will be suitable for
// subsequent calls to Gen.
func NewCA(name pkix.Name, opts *CAOpts) (*CA, error) {
  if len(name.CommonName) == 0 {
    return nil, fmt.Errorf("name must specify CN (common name)")
  }
  if len(name.Organization) == 0 {
    return nil, fmt.Errorf("name must specify O (organization)")
  }

  // Set the default options for unset fields
  opts = opts.SetDefaults()

  // Add 1 to the serial number after generation
  defer opts.SerialNumber.Add(opts.SerialNumber, big.NewInt(1))

  // Generate the CA key
  priv, err := rsa.GenerateKey(rand.Reader, opts.KeyBits)
  if err != nil {
    return nil, fmt.Errorf("error in generating key :: %v", err)
  }
  keyID, err := sha1Pub(&priv.PublicKey)
  if err != nil {
    return nil, err
  }

  now := time.Now().UTC()
  template := x509.Certificate{
    Subject:      name,
    SerialNumber: opts.SerialNumber,
    SubjectKeyId: keyID,
    NotBefore:    now.Add(-5 * time.Minute),
    NotAfter:     now.AddDate(0, 0, opts.ValidDays),
    KeyUsage: x509.KeyUsageKeyEncipherment |
      x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
    DNSNames:       opts.AltNames,
    EmailAddresses: opts.AltEmails,
    IsCA:           true,
    BasicConstraintsValid: true,
  }

  // set parent also to template.
  // TODO: set parent to a Verisign key (input) when we want to do
  // production CA?
  derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template,
    &priv.PublicKey, priv)
  if err != nil {
    return nil, fmt.Errorf("error creating certificate: %v", err)
  }

  cert, err := x509.ParseCertificate(derBytes)
  if err != nil {
    return nil, fmt.Errorf("error parsing certificate: %v", err)
  }

  return &CA{
    PrivateKey:  priv,
    Certificate: cert,
  }, nil
}

// Encrypt marshals the DER-encoded certificate and private key after
// encrypting them using the provided secret. We only provide this method
// instead of plain marshaling into text to make sure the private keys are
// always stored on disk/db in encrypted form and not in plain form. The
// secret should be something that is well taken care of or at least
// obfuscated in code.
func (ca *CA) Encrypt(secret []byte) ([]byte, error) {

  buf := new(bytes.Buffer)

  // First the cert.
  cblock, err := x509.EncryptPEMBlock(rand.Reader, "CERTIFICATE",
    ca.Raw, secret, x509.PEMCipherAES256)
  if err != nil {
    return nil, fmt.Errorf("error in cert encrypt: %v", err)
  }

  err = pem.Encode(buf, cblock)
  if err != nil {
    return nil, fmt.Errorf("error in cert encode: %v", err)
  }

  // Now the private key
  key := x509.MarshalPKCS1PrivateKey(ca.PrivateKey)

  kblock, err := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY",
    key, secret, x509.PEMCipherAES256)
  if err != nil {
    return nil, fmt.Errorf("error in key encrypt: %v", err)
  }

  err = pem.Encode(buf, kblock)
  if err != nil {
    return nil, fmt.Errorf("error in key encode: %v", err)
  }

  return buf.Bytes(), nil
}

// Decrypt reads a CA from the given bytes using the provided secret. This
// will decode a CA that is stored in file/db in ecnrypted form so that it
// can be loaded into memory and used to sign certificates. The usage should
// try to minimize the presence of this decrypted CA in memory and sanitize
// the  memory(rather than leave it for garbage collection) once it is done
// generating any keys using the CA.
func (ca *CA) Decrypt(data []byte, secret []byte) error {

  if len(data) < 1 {
    return fmt.Errorf("empty buffer for unmarshaling CA")
  }

  for len(data) > 0 {
    block, rest := pem.Decode(data)
    if block == nil {
      break
    }

    switch block.Type {
    case "CERTIFICATE":
      der, err := x509.DecryptPEMBlock(block, secret)
      if err != nil {
        return fmt.Errorf("error decrypting cert: ", err)
      }
      cert, err := x509.ParseCertificate(der)
      if err != nil {
        return fmt.Errorf("error in parsing certificate: %v", err)
      }
      ca.Certificate = cert
    case "RSA PRIVATE KEY":
      der, err := x509.DecryptPEMBlock(block, secret)
      if err != nil {
        return fmt.Errorf("error decrypting key: ", err)
      }
      key, err := x509.ParsePKCS1PrivateKey(der)
      if err != nil {
        return fmt.Errorf("error in parsing private key: %v", err)
      }
      ca.PrivateKey = key
    default:
      return fmt.Errorf("unexpected type in unmarshal: %s", block.Type)
    }

    data = rest
  }

  if ca.Certificate == nil {
    return fmt.Errorf("missing CERTIFICAE")
  }
  if ca.PrivateKey == nil {
    return fmt.Errorf("missing RSA PRIVATE KEY")
  }
  return nil
}

// SignOpts contains the options used for SignKey.
type SignOpts struct {
  SerialNumber *big.Int // Serial Number for CA.
  Days         int      // Days of validity (default is 60)
  ClientAuth   bool     // if this cert will be used for client auth
}

// SetDefaults sets the default values of the struct and returns
// a newly allocated options struct if it was nil.
func (o *SignOpts) SetDefaults() *SignOpts {
  if o == nil {
    o = new(SignOpts)
  }
  if o.Days == 0 {
    o.Days = 60
  }
  return o
}

// SignKey signs the key and returns the ASN1 DER-encoded certificate.
//
// The returned encoding is suitable for being distributed to a client via the
// mime-type "application/x-x509-user-cert".
func (ca *CA) SignKey(name pkix.Name, pub *rsa.PublicKey, opts *SignOpts) (
  []byte, error) {

  // Check the given name
  if len(name.CommonName) == 0 {
    return nil, fmt.Errorf("missing CN (common name)")
  }

  opts = opts.SetDefaults()

  keyID, err := sha1Pub(pub)
  if err != nil {
    return nil, err
  }

  var extKeyUsage []x509.ExtKeyUsage
  // The extended key usage attributes of the cert/key are set based on
  // whether this is intended to be used for server or client side. If this
  // is not set, tls accept will fail with errors.
  if opts.ClientAuth {
    extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
  } else {
    extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
  }

  now := time.Now().UTC()
  template := x509.Certificate{
    Subject:      name,
    SerialNumber: opts.SerialNumber,
    SubjectKeyId: keyID,
    NotBefore:    now.Add(-5 * time.Minute),
    NotAfter:     now.AddDate(0, 0, opts.Days),
    KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
    ExtKeyUsage:  extKeyUsage,
  }

  // Create certificate
  cert, err := x509.CreateCertificate(rand.Reader, &template, ca.Certificate,
    pub, ca.PrivateKey)
  if err != nil {
    return nil, fmt.Errorf("error creating certificate: %v", err)
  }

  return cert, nil
}
