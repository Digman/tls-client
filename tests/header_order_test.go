package tests

import (
	"encoding/json"
	"io/ioutil"
	"testing"

	tls_client "github.com/Digman/tls-client"
	"github.com/Digman/tls-client/shared"
	http "github.com/bogdanfinn/fhttp"
	"github.com/stretchr/testify/assert"
)

func TestClient_HeaderOrder(t *testing.T) {
	options := []tls_client.HttpClientOption{
		tls_client.WithClientProfile(tls_client.Chrome_105),
	}

	client, err := tls_client.NewHttpClient(nil, options...)
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest(http.MethodGet, peetApiEndpoint, nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header = http.Header{
		"header4": {`value4`},
		"header2": {"value2"},
		"header1": {"value1"},
		"header3": {"value3"},
		http.HeaderOrderKey: {
			"header1",
			"header2",
			"header3",
			"header4",
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	defer resp.Body.Close()

	readBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	tlsApiResponse := shared.TlsApiResponse{}
	if err := json.Unmarshal(readBytes, &tlsApiResponse); err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "header1: value1", tlsApiResponse.HTTP2.SentFrames[2].Headers[4])
	assert.Equal(t, "header2: value2", tlsApiResponse.HTTP2.SentFrames[2].Headers[5])
	assert.Equal(t, "header3: value3", tlsApiResponse.HTTP2.SentFrames[2].Headers[6])
	assert.Equal(t, "header4: value4", tlsApiResponse.HTTP2.SentFrames[2].Headers[7])

	req.Header = http.Header{
		"header-four":  {`value4`},
		"header-two":   {"value2"},
		"header-one":   {"value1"},
		"header-three": {"value3"},
		http.HeaderOrderKey: {
			"header-one",
			"header-two",
			"header-three",
			"header-four",
		},
	}

	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	defer resp.Body.Close()

	readBytes, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	tlsApiResponse = shared.TlsApiResponse{}
	if err := json.Unmarshal(readBytes, &tlsApiResponse); err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "header-one: value1", tlsApiResponse.HTTP2.SentFrames[2].Headers[4])
	assert.Equal(t, "header-two: value2", tlsApiResponse.HTTP2.SentFrames[2].Headers[5])
	assert.Equal(t, "header-three: value3", tlsApiResponse.HTTP2.SentFrames[2].Headers[6])
	assert.Equal(t, "header-four: value4", tlsApiResponse.HTTP2.SentFrames[2].Headers[7])

}
