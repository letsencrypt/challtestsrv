package challtestsrv

import (
	"crypto/tls"
	"net"
	"net/http"
	"testing"
)

func TestHTTP01ECH(t *testing.T) {
	s, err := New(Config{
		TLSALPNOneAddrs: []string{"127.0.0.1:0"},
		ECHPublicName:   "public.example",
	})
	if err != nil {
		t.Fatalf("creating test server: %s", err)
	}

	srv := httpOneServer("", s, true)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %s", err)
	}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })

	s.AddHTTPOneChallenge("example.com", "keyauth")

	for _, tc := range []struct {
		name          string
		echConfigList []byte
		wantECH       bool
	}{
		{
			name:    "No ECH",
			wantECH: false,
		},
		{
			name:          "ECH",
			echConfigList: s.ECHConfigList(),
			wantECH:       true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
				ServerName:                     "example.com",
				InsecureSkipVerify:             true,
				MinVersion:                     tls.VersionTLS13,
				EncryptedClientHelloConfigList: tc.echConfigList,
			}}}
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+ln.Addr().String()+"/", nil)
			if err != nil {
				t.Fatalf("building request: %s", err)
			}
			req.Host = "example.com"
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("request: %s", err)
			}
			defer resp.Body.Close()

			if resp.TLS.ECHAccepted != tc.wantECH {
				t.Errorf("ECHAccepted = %t, but want %t", resp.TLS.ECHAccepted, tc.wantECH)
			}
		})
	}
}
