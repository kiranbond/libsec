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

package libsec

import (
  "bytes"
  "crypto/tls"
  "crypto/x509"
  "crypto/x509/pkix"
  "fmt"
  "io"
  "net"
  "testing"

  "github.com/golang/glog"
  "github.com/stretchr/testify/assert"
)

var ca *CA

// TestNewCA makes a CA using the information in the options.
func TestNewCA(t *testing.T) {
  name := pkix.Name{
    Country:            []string{"US"},
    Organization:       []string{"Example Inc."},
    OrganizationalUnit: []string{"Security"},
    CommonName:         "security.corp.example.net",
  }
  opts := new(CAOpts)

  // Test generating the cert
  cert, err := NewCA(name, opts)
  assert.NoError(t, err)
  assert.NotNil(t, cert)
  assert.Equal(t, len(cert.SubjectKeyId), 20)
  assert.Equal(t, cert.SerialNumber.Int64(), 1)

  // Make sure the opts was modified
  assert.Equal(t, opts.SerialNumber.Int64(), 2)

  ca = cert
}

// TestEncryptDecryptPEMBlock tests the encryption/decryption using PEM block.
func TestEncryptDecryptPEMBlock(t *testing.T) {
  credential := []byte("hide-me")
  secret := []byte("ssh!secret#")

  bytes, errE := EncryptPEMBlock(credential, secret, "CERTIFICATE")
  assert.NoError(t, errE)

  decoded, _, errD := DecryptPEMBlock(bytes, secret)
  assert.NoError(t, errD)

  assert.Equal(t, credential, decoded, "decrypted PEM block did not match")
}

// TestEncryptDecrypt tests marshaling and unmarshaling with ecnryption of CA.
func TestEncryptDecrypt(t *testing.T) {
  assert.NotNil(t, ca)

  bytes, err := ca.Encrypt([]byte("shh!secret#"))
  assert.NoError(t, err)

  newCA := new(CA)
  err = newCA.Decrypt(bytes, []byte("shh!secret#"))
  assert.NoError(t, err)

  assert.Equal(t, newCA, ca, "ca did not match")
}

// Generate a certificate using a Client.
func TestGenCert(t *testing.T) {
  assert.NotNil(t, ca)

  client, err := NewClient()
  assert.NoError(t, err)
  assert.NotNil(t, client)

  key, cert, err := client.GenKeyAndCert(ca, "customer", false)
  assert.NoError(t, err)
  assert.NotNil(t, cert)
  assert.True(t, len(cert) > 0)
  assert.NotNil(t, key)
}

func handler(t *testing.T, conn net.Conn) {
  _, err := fmt.Fprintf(conn, "Hello World\n")
  assert.NoError(t, err)
  conn.Close()
}

func startServer(t *testing.T, addr string, config *tls.Config) error {
  listener, err := tls.Listen("tcp", addr, config)
  assert.NoError(t, err)

  glog.Infof("started server")

  go func() {
    for {
      conn, err := listener.Accept()
      assert.NoError(t, err)

      glog.Infof("accepted new connection")
      go handler(t, conn)
    }
  }()

  return nil
}

func MakeTLSConfig(t *testing.T, name string, clientAuth bool) *tls.Config {
  assert.NotNil(t, ca)

  client, err := NewClient()
  assert.NoError(t, err)
  assert.NotNil(t, client)

  key, cert, err := client.GenKeyAndCert(ca, name, clientAuth)
  assert.NoError(t, err)
  assert.NotNil(t, cert)
  assert.True(t, len(cert) > 0)
  assert.NotNil(t, key)

  keyBytes := x509.MarshalPKCS1PrivateKey(key)

  keyPEM, err := EncodePEMKey(keyBytes)
  assert.NoError(t, err)
  assert.NotNil(t, keyPEM)
  assert.True(t, len(keyPEM) > 0)

  certPEM, err := EncodePEMCert(cert)
  assert.NoError(t, err)
  assert.NotNil(t, certPEM)
  assert.True(t, len(certPEM) > 0)

  // NOTE(kiran): This is important. We check that for client side we only
  // use the CA cert in the tls config and not private key since we do not
  // expect to ship the private key to clients. Server needs the private key
  // also in config since it needs to decrypt on server side.
  caPEM, err := EncodePEMCert(ca.Raw)
  assert.NoError(t, err)
  assert.NotNil(t, caPEM)

  glog.V(1).Infof("\nCA:\n%s\nServer CERT:\n%s\nServer KEY:\n%s\n",
    caPEM, certPEM, keyPEM)

  config, err := TLSConfigFromPEM(caPEM, certPEM, keyPEM)
  assert.NoError(t, err)
  assert.NotNil(t, config)
  assert.NotNil(t, config.Certificates)
  assert.Equal(t, 1, len(config.Certificates))
  assert.NotNil(t, config.Certificates[0])

  return config
}

func TestTLSClientServer(t *testing.T) {
  addr := "localhost:50020"

  sConfig := MakeTLSConfig(t, "localhost", false)
  err := startServer(t, addr, sConfig)
  assert.NoError(t, err)

  cConfig := MakeTLSConfig(t, "client", true)

  conn, err := tls.Dial("tcp", addr, cConfig)
  assert.NoError(t, err)
  err = conn.Handshake()
  assert.NoError(t, err)

  glog.Infof("completed handshake")

  buf := new(bytes.Buffer)
  _, err = io.Copy(buf, conn)
  assert.NoError(t, err)
  assert.Equal(t, buf.Bytes(), []byte("Hello World\n"))
  conn.Close()
}
