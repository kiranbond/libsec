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

package libsec

import (
  "bytes"
  "crypto/rand"
  "crypto/rsa"
  "crypto/sha1"
  "crypto/tls"
  "crypto/x509"
  "encoding/pem"
  "fmt"
  "io/ioutil"
  "net"

  "github.com/pkg/errors"
)

// LoadCAPEM loads the CA from a PEM block.
func LoadCAPEM(pem []byte) (*x509.CertPool, error) {
  certPool := x509.NewCertPool()
  if !certPool.AppendCertsFromPEM(pem) {
    return nil, fmt.Errorf("error appending certs")
  }
  return certPool, nil
}

// LoadCAFile loads the CA from a file. It reads the PEM block from file and
// calls LoadCAPEM.
func LoadCAFile(caFile string) (*x509.CertPool, error) {
  pem, err := ioutil.ReadFile(caFile)
  if err != nil {
    return nil, fmt.Errorf("error reading CA file")
  }
  return LoadCAPEM(pem)

}

// TLSConfigWithCAFromFile takes the three files - CA, CERT, and PrivateKey
// and a secret to decrypt the data and creates the TLS config that can be used
// on the client or server side for secure tls connections.
func TLSConfigWithCAFromFile(caFile, certFile, keyFile string, secret []byte) (
  *tls.Config, error) {

  // CA certificate
  caData, err := ioutil.ReadFile(caFile)
  if err != nil {
    return nil, err
  }
  caBytes, _, err := DecryptPEMBlock(caData, secret)
  if err != nil {
    return nil, err
  }
  caPEM, err := EncodePEMCert(caBytes)
  if err != nil {
    return nil, err
  }
  // Certificate
  certData, err := ioutil.ReadFile(certFile)
  if err != nil {
    return nil, err
  }
  certBytes, _, err := DecryptPEMBlock(certData, secret)
  if err != nil {
    return nil, err
  }
  certPEM, err := EncodePEMCert(certBytes)
  if err != nil {
    return nil, err
  }
  // Private Key
  keyData, err := ioutil.ReadFile(keyFile)
  if err != nil {
    return nil, err
  }
  keyBytes, _, err := DecryptPEMBlock(keyData, secret)
  if err != nil {
    return nil, err
  }
  keyPEM, err := EncodePEMKey(keyBytes)
  if err != nil {
    return nil, err
  }
  return TLSConfigFromPEM(caPEM, certPEM, keyPEM)
}

// TLSConfigFromPEM takes the three PEM blocks - CA, CERT and PrivateKey - and
// creates the tls config that can be used to create secure tls connections.
func TLSConfigFromPEM(caPEM, certPEM, keyPEM []byte) (*tls.Config, error) {
  cert, err := tls.X509KeyPair(certPEM, keyPEM)
  if err != nil {
    return nil, err
  }

  config := &tls.Config{}
  config.Certificates = make([]tls.Certificate, 1)
  config.Certificates[0] = cert

  certPool, err := LoadCAPEM(caPEM)
  if err != nil || certPool == nil {
    return nil, err
  }

  config.RootCAs = certPool
  config.ClientCAs = certPool

  // This makes sure that a server will force verify client cert.
  config.ClientAuth = tls.RequireAndVerifyClientCert

  // Use only modern ciphers
  config.CipherSuites = []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA,
    tls.TLS_RSA_WITH_AES_256_CBC_SHA,
    tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
    tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
    tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
    tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
    tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}

  // Use only TLS v1.2
  config.MinVersion = tls.VersionTLS12

  // Don't allow session resumption
  config.SessionTicketsDisabled = true
  return config, nil
}

// TLSConfigFromFile creates a server tls configuration from the provided
// cert and key files.
func TLSConfigFromFile(certFile, keyFile string) (*tls.Config, error) {
  cert, err := tls.LoadX509KeyPair(certFile, keyFile)
  if err != nil {
    return nil, errors.Wrapf(err, "error loading TLS certs")
  }
  config := tls.Config{Certificates: []tls.Certificate{cert}}
  config.Rand = rand.Reader
  return &config, nil
}

// TLSClientConfigFromServerCert creates a client tls config to connect to the
// server based on using the server cert to setup the CA etc.
func TLSClientConfigFromServerCert(file string) (*tls.Config, error) {
  tlsConfig := &tls.Config{RootCAs: x509.NewCertPool()}
  // Load our trusted certificate path
  pemData, err := ioutil.ReadFile(file)
  if err != nil {
    return nil, errors.Wrapf(err, "error reading certificate file")
  }
  ok := tlsConfig.RootCAs.AppendCertsFromPEM(pemData)
  if !ok {
    return nil, errors.Wrapf(err, "error appending certs to CA")
  }
  return tlsConfig, nil
}

// EncrptPEMBlock encrypts the input block of data.
func EncryptPEMBlock(data, secret []byte, blockTpe string) ([]byte, error) {
  block, err := x509.EncryptPEMBlock(rand.Reader, blockTpe,
    data, secret, x509.PEMCipherAES256)
  if err != nil {
    return nil, fmt.Errorf("error in encrypt: %v", err)
  }

  buf := new(bytes.Buffer)
  err = pem.Encode(buf, block)
  if err != nil {
    return nil, fmt.Errorf("error in encode: %v", err)
  }
  return buf.Bytes(), nil
}

// DecryptPEMBlock decrypts the block of data.
func DecryptPEMBlock(data, secret []byte) ([]byte, []byte, error) {
  block, rest := pem.Decode(data)
  if block == nil || len(block.Bytes) < 1 {
    return nil, rest, fmt.Errorf("error in decoding block")
  }
  decoded, err := x509.DecryptPEMBlock(block, secret)
  if err != nil {
    return nil, rest, fmt.Errorf("error decrypting block: ", err)
  }
  return decoded, rest, nil
}

// EncodePEMCert marshals the DER-encoded certificate.
func EncodePEMCert(cert []byte) ([]byte, error) {
  buf := new(bytes.Buffer)
  err := pem.Encode(buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert})
  if err != nil {
    return nil, fmt.Errorf("error in cert encode: %s", err)
  }
  return buf.Bytes(), nil
}

// DecodePEMCert unmarshals the DER-encoded certificate.
func DecodePEMCert(data []byte) ([]byte, []byte, error) {
  block, rest := pem.Decode(data)
  if block == nil || len(block.Bytes) < 1 {
    return nil, rest, fmt.Errorf("error in decoding certificate")
  }
  return block.Bytes, rest, nil
}

// EncrptPEMCert encrypts the DER-encoded certificate.
func EncryptPEMCert(cert, secret []byte) ([]byte, error) {
  return EncryptPEMBlock(cert, secret, "CERTIFICATE")
}

// DecryptPEMCert decrypts the DER-encoded certificate.
func DecryptPEMCert(data, secret []byte) (*x509.Certificate, error) {
  certBytes, _, err := DecryptPEMBlock(data, secret)
  if err != nil || certBytes == nil {
    return nil, fmt.Errorf("error decrypting cert: ", err)
  }
  cert, err := x509.ParseCertificate(certBytes)
  if err != nil {
    return nil, fmt.Errorf("error in parsing certificate: %v", err)
  }
  return cert, nil
}

// EncodePEMKey marshals the DER-encoded private key.
func EncodePEMKey(data []byte) ([]byte, error) {
  buf := new(bytes.Buffer)
  err := pem.Encode(buf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: data})
  if err != nil {
    return nil, fmt.Errorf("error in key encode: %s", err)
  }
  return buf.Bytes(), nil
}

// EncryptPEMKey encrypts and marshals the DER-encoded private key.
func EncryptPEMKey(key *rsa.PrivateKey, secret []byte) ([]byte, error) {
  keyBytes := x509.MarshalPKCS1PrivateKey(key)
  return EncryptPEMBlock(keyBytes, secret, "RSA PRIVATE KEY")
}

// DecryptPEMKey decrypts the DER-encoded private key.
func DecryptPEMKey(data, secret []byte) (*rsa.PrivateKey, error) {
  keyBytes, _, err := DecryptPEMBlock(data, secret)
  if err != nil {
    return nil, fmt.Errorf("error decrypting key: ", err)
  }
  key, err := x509.ParsePKCS1PrivateKey(keyBytes)
  if err != nil {
    return nil, fmt.Errorf("error in parsing private key: %v", err)
  }
  return key, nil
}

// MarshalPEMCertAndKey marshals the DER-encoded certificate and private key.
func EncodePEMCertAndKey(cert []byte, key *rsa.PrivateKey) ([]byte, error) {
  buf := new(bytes.Buffer)
  err := pem.Encode(buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert})
  if err != nil {
    return nil, fmt.Errorf("error in cert encode: %s", err)
  }
  keyBytes := x509.MarshalPKCS1PrivateKey(key)
  err = pem.Encode(buf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes})
  if err != nil {
    return nil, fmt.Errorf("error in key encode: %s", err)
  }
  return buf.Bytes(), nil
}

// ExtractConnCertificate extracts a certificate from the server accepted
// tls connection so it can be compared against expected certificate.
// Note that the extracted cert is not something to validate connection,
// tls has already completed the connection before we access the certificate.
func ExtractClientCert(conn net.Conn) (*x509.Certificate, error) {
  tlscon, ok := conn.(*tls.Conn)
  if !ok {
    return nil, fmt.Errorf("conn is not a tls connection")
  }

  state := tlscon.ConnectionState()
  if !state.HandshakeComplete {
    return nil, fmt.Errorf("handshake not complete")
  }

  if len(state.PeerCertificates) < 1 {
    return nil, fmt.Errorf("no valid certificate to extract")
  }

  return state.PeerCertificates[0], nil
}

// SameCertificate compares two certificates to check if they are the same.
func SameCertificate(pem1 []byte, pem2 []byte) bool {
  return true
}

////////////////////////////////////////////////////////////////////////////////

// sha1Pub is a utility function to take a SHA1 of the public key.
func sha1Pub(pub *rsa.PublicKey) ([]byte, error) {
  pkixPub, err := x509.MarshalPKIXPublicKey(pub)
  if err != nil {
    return nil, fmt.Errorf("error marshaling public key: %v", err)
  }

  h := sha1.New()
  h.Write(pkixPub)
  return h.Sum(nil), nil
}
