package profiles

import (
	"testing"

	tls "github.com/bogdanfinn/utls"
)

func TestChrome152ProfileDiffersFromChrome150(t *testing.T) {
	tests := []struct {
		name    string
		profile ClientProfile
		psk     bool
	}{
		{name: "chrome 152", profile: Chrome_152},
		{name: "chrome 152 psk", profile: Chrome_152_PSK, psk: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec, err := tt.profile.GetClientHelloSpec()
			if err != nil {
				t.Fatalf("GetClientHelloSpec() error = %v", err)
			}

			hasGreaseSignature := false
			hasTrustAnchorExtension := false
			preSharedKeyIndex := -1
			for i, extension := range spec.Extensions {
				if extension == nil {
					continue
				}
				switch extension := extension.(type) {
				case *tls.SignatureAlgorithmsExtension:
					for _, algorithm := range extension.SupportedSignatureAlgorithms {
						if algorithm == tls.GREASE_PLACEHOLDER {
							hasGreaseSignature = true
						}
					}
				case *tls.GenericExtension:
					if extension.Id == 0xca34 {
						hasTrustAnchorExtension = true
					}
				case *tls.UtlsPreSharedKeyExtension:
					preSharedKeyIndex = i
				}
			}

			if !hasGreaseSignature {
				t.Error("Chrome 152 profile does not include a GREASE signature algorithm")
			}
			if !hasTrustAnchorExtension {
				t.Error("Chrome 152 profile does not include the trust-anchor extension")
			}
			if tt.psk && preSharedKeyIndex != len(spec.Extensions)-1 {
				t.Fatalf("PSK extension index = %d, want %d", preSharedKeyIndex, len(spec.Extensions)-1)
			}
		})
	}
}

func TestNewGREASEECHCopiesPayloadLens(t *testing.T) {
	payloadLens := []uint16{128, 160}
	ech := newGREASEECH(payloadLens...)
	payloadLens[0] = 224

	if got := ech.CandidatePayloadLens; len(got) != 2 || got[0] != 128 || got[1] != 160 {
		t.Fatalf("CandidatePayloadLens = %v, want [128 160]", got)
	}
}

func TestChrome152GREASEECHUsesConfiguredPayloadLens(t *testing.T) {
	for _, profile := range []ClientProfile{Chrome_152, Chrome_152_PSK} {
		spec, err := profile.GetClientHelloSpec()
		if err != nil {
			t.Fatalf("GetClientHelloSpec() error = %v", err)
		}

		found := false
		for _, extension := range spec.Extensions {
			ech, ok := extension.(*tls.GREASEEncryptedClientHelloExtension)
			if !ok {
				continue
			}
			found = true
			if len(ech.CandidatePayloadLens) != 2 || ech.CandidatePayloadLens[0] != 128 || ech.CandidatePayloadLens[1] != 160 {
				t.Fatalf("CandidatePayloadLens = %v, want [128 160]", ech.CandidatePayloadLens)
			}
		}
		if !found {
			t.Fatal("Chrome 152 profile does not include an ECH GREASE extension")
		}
	}
}

func TestChrome153Profiles(t *testing.T) {
	tests := []struct {
		name    string
		profile ClientProfile
		version string
	}{
		{name: "chrome 153", profile: Chrome_153, version: "153"},
		{name: "chrome 153 psk", profile: Chrome_153_PSK, version: "153_PSK"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.profile.GetClientHelloId().Version; got != tt.version {
				t.Fatalf("ClientHello version = %q, want %q", got, tt.version)
			}

			spec, err := tt.profile.GetClientHelloSpec()
			if err != nil {
				t.Fatalf("GetClientHelloSpec() error = %v", err)
			}

			found := false
			for _, extension := range spec.Extensions {
				ech, ok := extension.(*tls.GREASEEncryptedClientHelloExtension)
				if !ok {
					continue
				}
				found = true
				want := []uint16{128, 160, 192, 224}
				if len(ech.CandidatePayloadLens) != len(want) {
					t.Fatalf("CandidatePayloadLens = %v, want %v", ech.CandidatePayloadLens, want)
				}
				for i := range want {
					if ech.CandidatePayloadLens[i] != want[i] {
						t.Fatalf("CandidatePayloadLens = %v, want %v", ech.CandidatePayloadLens, want)
					}
				}
			}
			if !found {
				t.Fatal("Chrome 153 profile does not include an ECH GREASE extension")
			}
		})
	}
}

func TestChrome150ProfileDoesNotIncludeChrome152Extensions(t *testing.T) {
	spec, err := Chrome_150.GetClientHelloSpec()
	if err != nil {
		t.Fatalf("GetClientHelloSpec() error = %v", err)
	}

	for _, extension := range spec.Extensions {
		switch extension := extension.(type) {
		case *tls.SignatureAlgorithmsExtension:
			for _, algorithm := range extension.SupportedSignatureAlgorithms {
				if algorithm == tls.GREASE_PLACEHOLDER {
					t.Error("Chrome 150 profile unexpectedly includes a GREASE signature algorithm")
				}
			}
		case *tls.GenericExtension:
			if extension.Id == 0xca34 {
				t.Error("Chrome 150 profile unexpectedly includes the trust-anchor extension")
			}
		}
	}
}
