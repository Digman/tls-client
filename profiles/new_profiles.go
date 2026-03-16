package profiles

import (
	"github.com/bogdanfinn/fhttp/http2"
	tls "github.com/bogdanfinn/utls"
)

// newALPSExtension returns the appropriate ALPS extension based on the useNew flag.
// useNew=true returns ApplicationSettingsExtensionNew (code point 17613),
// useNew=false returns ApplicationSettingsExtension (code point 17513).
func newALPSExtension(useNew bool) tls.TLSExtension {
	if useNew {
		return &tls.ApplicationSettingsExtensionNew{
			SupportedProtocols: []string{"h2"},
		}
	}
	return &tls.ApplicationSettingsExtension{
		SupportedProtocols: []string{"h2"},
	}
}

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
				&tls.ApplicationSettingsExtension{
					SupportedProtocols: []string{"h2"},
				},
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
					{Group: tls.X25519},
				}},
				&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
					tls.GREASE_PLACEHOLDER,
					tls.X25519,
					tls.CurveP256,
					tls.CurveP384,
				}},
				&tls.SupportedPointsExtension{SupportedPoints: []byte{
					tls.PointFormatUncompressed,
				}},
				&tls.ApplicationSettingsExtension{
					SupportedProtocols: []string{"h2"},
				},
				&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{
					tls.CertCompressionBrotli,
				}},
				&tls.UtlsGREASEExtension{},
				&tls.UtlsPreSharedKeyExtension{},
			},
		}, nil
	},
})

var Chrome_124_PSK = NewChromeProfileNonStreams(tls.ClientHelloID{
	Client:               "Chrome",
	RandomExtensionOrder: false,
	Version:              "124_PSK",
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
				&tls.ApplicationSettingsExtension{
					SupportedProtocols: []string{"h2"},
				},
				&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{
					tls.CertCompressionBrotli,
				}},
				&tls.UtlsGREASEExtension{},
				&tls.UtlsPreSharedKeyExtension{},
			},
		}, nil
	},
})

// newChromeMLKEMPSK 生成使用 X25519MLKEM768 後量子密鑰交換的 Chrome PSK profile。
// Chrome 131-132 使用舊 ALPS 代碼點（17513），Chrome 133+ 使用新 ALPS 代碼點（17613）。
// 所有版本的 cipher suites、signature algorithms、H2 settings 均相同。
// Extension 順序由 requests 庫的 WithRandomTLSExtensionOrder() 隨機排列，與真實 Chrome 行為一致。
func newChromeMLKEMPSK(version string, useNewALPS bool) ClientProfile {
	return ClientProfile{
		clientHelloId: tls.ClientHelloID{
			Client:               "Chrome",
			RandomExtensionOrder: false,
			Version:              version,
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
					CompressionMethods: []byte{
						tls.CompressionNone,
					},
					Extensions: []tls.TLSExtension{
						&tls.UtlsGREASEExtension{},
						newALPSExtension(useNewALPS),
						&tls.ALPNExtension{AlpnProtocols: []string{
							"h2",
							"http/1.1",
						}},
						&tls.RenegotiationInfoExtension{
							Renegotiation: tls.RenegotiateOnceAsClient,
						},
						&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
							tls.PskModeDHE,
						}},
						&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
							tls.GREASE_PLACEHOLDER,
							tls.X25519MLKEM768,
							tls.X25519,
							tls.CurveP256,
							tls.CurveP384,
						}},
						tls.BoringGREASEECH(),
						&tls.ExtendedMasterSecretExtension{},
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
						&tls.StatusRequestExtension{},
						&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{
							tls.CertCompressionBrotli,
						}},
						&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
							{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
							{Group: tls.X25519MLKEM768},
							{Group: tls.X25519},
						}},
						&tls.SupportedPointsExtension{SupportedPoints: []byte{
							tls.PointFormatUncompressed,
						}},
						&tls.SessionTicketExtension{},
						&tls.SupportedVersionsExtension{Versions: []uint16{
							tls.GREASE_PLACEHOLDER,
							tls.VersionTLS13,
							tls.VersionTLS12,
						}},
						&tls.SCTExtension{},
						&tls.SNIExtension{},
						&tls.UtlsGREASEExtension{},
						&tls.UtlsPreSharedKeyExtension{},
					},
				}, nil
			},
		},
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

// Chrome_132_PSK Chrome 132 PSK: X25519MLKEM768 + 舊 ALPS 代碼點（131→133 過渡版本）
var Chrome_132_PSK = newChromeMLKEMPSK("132", false)

// Chrome 134-145 PSK: X25519MLKEM768 + 新 ALPS 代碼點（與 Chrome 133 相同，由 Chrome 145 真實指紋驗證）
var Chrome_134_PSK = newChromeMLKEMPSK("134", true)
var Chrome_135_PSK = newChromeMLKEMPSK("135", true)
var Chrome_136_PSK = newChromeMLKEMPSK("136", true)
var Chrome_137_PSK = newChromeMLKEMPSK("137", true)
var Chrome_138_PSK = newChromeMLKEMPSK("138", true)
var Chrome_139_PSK = newChromeMLKEMPSK("139", true)
var Chrome_140_PSK = newChromeMLKEMPSK("140", true)
var Chrome_141_PSK = newChromeMLKEMPSK("141", true)
var Chrome_142_PSK = newChromeMLKEMPSK("142", true)
var Chrome_143_PSK = newChromeMLKEMPSK("143", true)
var Chrome_145_PSK = newChromeMLKEMPSK("145", true)

// Safari_26 基於真實 macOS Safari 26.3 指紋數據（Version/26.3 Safari/605.1.15）。
// 相比 Safari 18.5 的主要變化：
//   - TLS 1.3 cipher 順序: AES_256 → CHACHA20 → AES_128（18.x 是 AES_128 → AES_256 → CHACHA20）
//   - 新增 X25519MLKEM768 後量子密鑰交換（supported_groups + key_share）
//   - 移除 TLS 1.1/1.0 支持（僅保留 TLS 1.3 + 1.2）
//   - 移除 padding extension
//   - H2 層保持與 Safari 18.5 一致（NO_RFC7540_PRIORITIES 模式）
//   - HEADERS frame 不再帶 Priority flag（無 headerPriority）
var Safari_26 = ClientProfile{
	clientHelloId: tls.ClientHelloID{
		Client:               "Safari",
		RandomExtensionOrder: false,
		Version:              "26",
		Seed:                 nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
			return tls.ClientHelloSpec{
				CipherSuites: []uint16{
					tls.GREASE_PLACEHOLDER,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_CHACHA20_POLY1305_SHA256,
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_128_CBC_SHA,
					tls.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
					tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
				},
				CompressionMethods: []uint8{
					tls.CompressionNone,
				},
				Extensions: []tls.TLSExtension{
					&tls.UtlsGREASEExtension{},
					&tls.SNIExtension{},
					&tls.ExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
					&tls.SupportedCurvesExtension{[]tls.CurveID{
						tls.GREASE_PLACEHOLDER,
						tls.X25519MLKEM768,
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
						tls.CurveP521,
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []byte{
						tls.PointFormatUncompressed,
					}},
					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
					&tls.StatusRequestExtension{},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						tls.ECDSAWithP256AndSHA256,
						tls.PSSWithSHA256,
						tls.PKCS1WithSHA256,
						tls.ECDSAWithP384AndSHA384,
						tls.PSSWithSHA384,
						tls.PSSWithSHA384,
						tls.PKCS1WithSHA384,
						tls.PSSWithSHA512,
						tls.PKCS1WithSHA512,
						tls.PKCS1WithSHA1,
					}},
					&tls.SCTExtension{},
					&tls.KeyShareExtension{[]tls.KeyShare{
						{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
						{Group: tls.X25519MLKEM768},
						{Group: tls.X25519},
					}},
					&tls.PSKKeyExchangeModesExtension{[]uint8{
						tls.PskModeDHE,
					}},
					&tls.SupportedVersionsExtension{[]uint16{
						tls.GREASE_PLACEHOLDER,
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
					&tls.UtlsCompressCertExtension{[]tls.CertCompressionAlgo{
						tls.CertCompressionZlib,
					}},
					&tls.UtlsGREASEExtension{},
				},
			}, nil
		},
	},
	settings: map[http2.SettingID]uint32{
		http2.SettingEnablePush:           0,
		http2.SettingMaxConcurrentStreams: 100,
		http2.SettingInitialWindowSize:    2097152,
		http2.SettingNoRFC7540Priorities:  1,
	},
	settingsOrder: []http2.SettingID{
		http2.SettingEnablePush,
		http2.SettingMaxConcurrentStreams,
		http2.SettingInitialWindowSize,
		http2.SettingNoRFC7540Priorities,
	},
	pseudoHeaderOrder: []string{
		":method",
		":scheme",
		":authority",
		":path",
	},
	connectionFlow: 10420225,
}
