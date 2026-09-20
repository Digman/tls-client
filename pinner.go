package tls_client

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	http "github.com/bogdanfinn/fhttp"
	tls "github.com/bogdanfinn/utls"
	"github.com/tam7t/hpkp"
)

var DefaultBadPinHandler = func(req *http.Request) {
	fmt.Println("this is the default bad pin handler")
}

var ErrBadPinDetected = errors.New("bad ssl pin detected")

var pinMismatchInfoKey struct{}

// PinMismatchInfo describes the expected and observed certificate pins for a failed connection.
type PinMismatchInfo struct {
	Host         string               `json:"host"`
	ExpectedPins []string             `json:"expected_pins"`
	Certificates []CertificateSummary `json:"certificates"`
}

// CertificateSummary contains non-sensitive certificate metadata suitable for diagnostics.
type CertificateSummary struct {
	SPKIPin    string `json:"spki_pin"`
	CertSHA256 string `json:"cert_sha256"`
	Subject    string `json:"subject"`
	Issuer     string `json:"issuer"`
	Serial     string `json:"serial"`
	NotBefore  string `json:"not_before"`
	NotAfter   string `json:"not_after"`
}

type pinMismatchError struct {
	Info PinMismatchInfo
}

func (e *pinMismatchError) Error() string {
	return ErrBadPinDetected.Error()
}

func (e *pinMismatchError) Unwrap() error {
	return ErrBadPinDetected
}

// PinMismatchInfoFromRequest returns diagnostics attached to the request passed
// to the legacy BadPinHandler after a certificate pin mismatch.
func PinMismatchInfoFromRequest(req *http.Request) (PinMismatchInfo, bool) {
	if req == nil {
		return PinMismatchInfo{}, false
	}
	info, ok := req.Context().Value(pinMismatchInfoKey).(PinMismatchInfo)
	return info, ok
}

var certificatePinStorage = hpkp.NewMemStorage()

type certificatePinner struct {
	certificatePins map[string][]string
}

type CertificatePinner interface {
	Pin(conn *tls.UConn, host string) error
}

func NewCertificatePinner(certificatePins map[string][]string) (CertificatePinner, error) {
	pinner := &certificatePinner{
		certificatePins: certificatePins,
	}

	err := pinner.init()
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate certificate pinner: %w", err)
	}

	return pinner, nil
}

func (cp *certificatePinner) init() error {
	if len(cp.certificatePins) == 0 {
		return nil
	}

	for host, pinsByHost := range cp.certificatePins {
		includeSubdomains := false
		if strings.Contains(host, "*.") {
			includeSubdomains = true
			host = strings.ReplaceAll(host, "*.", "")
		}

		pinnedHost := certificatePinStorage.Lookup(host)

		if pinnedHost != nil && reflect.DeepEqual(pinnedHost.Sha256Pins, pinsByHost) {
			// another pinner instance with the same Pins already initialized the host. we do not need to pin again
			continue
		}

		certificatePinStorage.Add(host, &hpkp.Header{
			Permanent:         true,
			Sha256Pins:        pinsByHost,
			IncludeSubDomains: includeSubdomains,
		})
	}

	return nil
}

func (cp *certificatePinner) Pin(conn *tls.UConn, host string) error {
	validPin := false

	if len(cp.certificatePins) == 0 {
		return nil
	}

	pinnedHost := certificatePinStorage.Lookup(host)

	if pinnedHost == nil {
		// host is not pinned, we treat it as valid
		return nil
	}

	peerCertificates := conn.ConnectionState().PeerCertificates
	for _, peerCert := range peerCertificates {
		peerPin := hpkp.Fingerprint(peerCert)

		if pinnedHost.Matches(peerPin) {
			validPin = true
			break
		}
	}

	if !validPin {
		info := PinMismatchInfo{
			Host:         host,
			ExpectedPins: append([]string(nil), pinnedHost.Sha256Pins...),
		}
		for _, cert := range peerCertificates {
			spkiPin := hpkp.Fingerprint(cert)
			certDigest := sha256.Sum256(cert.Raw)
			serial := ""
			if cert.SerialNumber != nil {
				serial = cert.SerialNumber.String()
			}
			info.Certificates = append(info.Certificates, CertificateSummary{
				SPKIPin:    spkiPin,
				CertSHA256: hex.EncodeToString(certDigest[:]),
				Subject:    cert.Subject.String(),
				Issuer:     cert.Issuer.String(),
				Serial:     serial,
				NotBefore:  cert.NotBefore.UTC().Format(time.RFC3339),
				NotAfter:   cert.NotAfter.UTC().Format(time.RFC3339),
			})
		}
		return &pinMismatchError{Info: info}
	}

	return nil
}
