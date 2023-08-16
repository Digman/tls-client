module github.com/Digman/tls-client

go 1.18

require (
	github.com/bogdanfinn/fhttp v0.5.9
	github.com/bogdanfinn/utls v1.5.16
	github.com/google/uuid v1.3.0
	github.com/stretchr/testify v1.8.0
	golang.org/x/net v0.10.0
)

require (
	github.com/andybalholm/brotli v1.0.5 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/klauspost/compress v1.16.5 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/crypto v0.9.0 // indirect
	golang.org/x/sys v0.8.0 // indirect
	golang.org/x/text v0.9.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// replace github.com/bogdanfinn/utls => ../utls

replace github.com/bogdanfinn/fhttp => ../fhttp
