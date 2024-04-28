package profiles

import (
	"github.com/bogdanfinn/fhttp/http2"
	tls "github.com/bogdanfinn/utls"
)

func NewChromeProfile(clientHelloId tls.ClientHelloID) ClientProfile {
	return ClientProfile{
		clientHelloId: clientHelloId,
		settings: map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:      65536,
			http2.SettingEnablePush:           0,
			http2.SettingMaxConcurrentStreams: 1000,
			http2.SettingInitialWindowSize:    6291456,
			http2.SettingMaxHeaderListSize:    262144,
		},
		settingsOrder: []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingEnablePush,
			http2.SettingMaxConcurrentStreams,
			http2.SettingInitialWindowSize,
			http2.SettingMaxHeaderListSize,
		},
		pseudoHeaderOrder: []string{
			":method",
			":authority",
			":scheme",
			":path",
		},
		connectionFlow: 15663105,
	}
}

func NewChromeProfileNonStreams(clientHelloId tls.ClientHelloID) ClientProfile {
	return ClientProfile{
		clientHelloId: clientHelloId,
		settings: map[http2.SettingID]uint32{
			http2.SettingHeaderTableSize:   65536,
			http2.SettingEnablePush:        0,
			http2.SettingInitialWindowSize: 6291456,
			http2.SettingMaxHeaderListSize: 262144,
		},
		settingsOrder: []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingEnablePush,
			http2.SettingInitialWindowSize,
			http2.SettingMaxHeaderListSize,
		},
		pseudoHeaderOrder: []string{
			":method",
			":authority",
			":scheme",
			":path",
		},
		connectionFlow: 15663105,
	}
}

var Chrome_112_PSK = NewChromeProfile(tls.HelloChrome_112_PSK)

var Chrome_114_PSK = NewChromeProfile(tls.HelloChrome_114_Padding_PSK)

var Chrome_115_PQ = NewChromeProfile(tls.HelloChrome_115_PQ)

var Chrome_115_PSK = NewChromeProfile(tls.HelloChrome_115_PQ_PSK)

var Chrome_117_PSK = NewChromeProfileNonStreams(tls.ClientHelloID{
	Client:               "Chrome",
	RandomExtensionOrder: false,
	Version:              "117_PSK",
	Seed:                 nil,
	SpecFactory: func() (tls.ClientHelloSpec, error) {
		return tls.ClientHelloSpec{
			CipherSuites: []uint16{
				tls.GREASE_PLACEHOLDER,
				tls.TLS_AES_128_GCM_SHA256,
				tls.TLS_AES_256_GCM_SHA384,
				tls.TLS_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_RSA_WITH_AES_128_CBC_SHA,
				tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			CompressionMethods: []uint8{
				tls.CompressionNone,
			},
			Extensions: []tls.TLSExtension{
				&tls.UtlsGREASEExtension{},
				&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
					tls.PskModeDHE,
				}},
				&tls.SNIExtension{},
				&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
					tls.ECDSAWithP256AndSHA256,
					tls.PSSWithSHA256,
					tls.PKCS1WithSHA256,
					tls.ECDSAWithP384AndSHA384,
					tls.PSSWithSHA384,
					tls.PKCS1WithSHA384,
					tls.PSSWithSHA512,
					tls.PKCS1WithSHA512,
				}},
				&tls.SupportedVersionsExtension{Versions: []uint16{
					tls.GREASE_PLACEHOLDER,
					tls.VersionTLS13,
					tls.VersionTLS12,
				}},
				&tls.ApplicationSettingsExtension{SupportedProtocols: []string{"h2"}},
				&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
					tls.CurveID(tls.GREASE_PLACEHOLDER),
					tls.X25519,
					tls.CurveP256,
					tls.CurveP384,
				}},
				&tls.ExtendedMasterSecretExtension{},
				&tls.SessionTicketExtension{},
				&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{
					tls.CertCompressionBrotli,
				}},
				&tls.SCTExtension{},
				&tls.StatusRequestExtension{},
				&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
					{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
					{Group: tls.X25519},
				}},
				&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
				&tls.SupportedPointsExtension{SupportedPoints: []byte{
					tls.PointFormatUncompressed,
				}},
				&tls.UtlsGREASEExtension{},
				&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
				&tls.UtlsPreSharedKeyExtension{},
			},
		}, nil
	},
})

var Chrome_120_PSK = NewChromeProfileNonStreams(tls.ClientHelloID{
	Client:               "Chrome",
	RandomExtensionOrder: false,
	Version:              "120_PSK",
	Seed:                 nil,
	SpecFactory: func() (tls.ClientHelloSpec, error) {
		return tls.ClientHelloSpec{
			CipherSuites: []uint16{
				tls.GREASE_PLACEHOLDER,
				tls.TLS_AES_128_GCM_SHA256,
				tls.TLS_AES_256_GCM_SHA384,
				tls.TLS_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_RSA_WITH_AES_128_CBC_SHA,
				tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			CompressionMethods: []uint8{
				tls.CompressionNone,
			},
			Extensions: []tls.TLSExtension{
				&tls.UtlsGREASEExtension{},
				&tls.SNIExtension{},
				&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
					tls.PskModeDHE,
				}},
				&tls.SupportedVersionsExtension{Versions: []uint16{
					tls.GREASE_PLACEHOLDER,
					tls.VersionTLS13,
					tls.VersionTLS12,
				}},
				&tls.StatusRequestExtension{},
				&tls.ExtendedMasterSecretExtension{},
				&tls.SessionTicketExtension{},
				&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
					tls.ECDSAWithP256AndSHA256,
					tls.PSSWithSHA256,
					tls.PKCS1WithSHA256,
					tls.ECDSAWithP384AndSHA384,
					tls.PSSWithSHA384,
					tls.PKCS1WithSHA384,
					tls.PSSWithSHA512,
					tls.PKCS1WithSHA512,
				}},
				&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
				&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				tls.BoringGREASEECH(),
				&tls.SCTExtension{},
				&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
					{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
					{Group: tls.X25519Kyber768Draft00},
					{Group: tls.X25519},
				}},
				&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
					tls.GREASE_PLACEHOLDER,
					tls.X25519Kyber768Draft00,
					tls.X25519,
					tls.CurveP256,
					tls.CurveP384,
				}},
				&tls.SupportedPointsExtension{SupportedPoints: []byte{
					tls.PointFormatUncompressed,
				}},
				&tls.ApplicationSettingsExtension{SupportedProtocols: []string{"h2"}},
				&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{
					tls.CertCompressionBrotli,
				}},
				&tls.UtlsGREASEExtension{},
				&tls.UtlsPreSharedKeyExtension{},
			},
		}, nil
	},
})
