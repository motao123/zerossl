package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
)

func GenerateRSA(domain string) (csr []byte, pk []byte, err error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	pk = pem.EncodeToMemory(privateKeyPEM)

	subject := pkix.Name{
		CommonName: domain,
		Country:    []string{"CN"},
		Province:   []string{"Beijing"},
		Locality:   []string{"Beijing"},
	}

	csrTemplate := x509.CertificateRequest{
		Subject:            subject,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, privateKey)
	if err != nil {
		return nil, nil, err
	}

	csrPEM := &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	}
	csr = pem.EncodeToMemory(csrPEM)

	return csr, pk, nil
}

func GenerateECDSA(domain string) (csr []byte, pk []byte, err error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	privateKeyPEM, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}
	pk = pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyPEM,
	})

	subject := pkix.Name{
		CommonName: domain,
		Country:    []string{"CN"},
		Province:   []string{"Beijing"},
		Locality:   []string{"Beijing"},
	}

	csrTemplate := x509.CertificateRequest{
		Subject:            subject,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, privateKey)
	if err != nil {
		return nil, nil, err
	}

	csrPEM := &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	}
	csr = pem.EncodeToMemory(csrPEM)

	return csr, pk, nil
}
