package challtestsrv

import (
	"crypto/tls"
	"net"
	"testing"
)

func TestTLSALPN01ECH(t *testing.T) {
	s, err := New(Config{
		TLSALPNOneAddrs: []string{"127.0.0.1:0"},
		ECHPublicName:   "public.example",
	})
	if err != nil {
		t.Fatalf("creating test server: %s", err)
	}

	srv := tlsALPNOneServer("", s)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %s", err)
	}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })

	s.AddTLSALPNChallenge("example.com", "keyauth")

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
			conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
				ServerName:                     "example.com",
				NextProtos:                     []string{ACMETLS1Protocol},
				InsecureSkipVerify:             true,
				MinVersion:                     tls.VersionTLS13,
				EncryptedClientHelloConfigList: tc.echConfigList,
			})
			if err != nil {
				t.Fatalf("connection failed: %s", err)
			}
			defer conn.Close()

			if conn.ConnectionState().ECHAccepted != tc.wantECH {
				t.Errorf("ECHAccepted = %t, but want %t", conn.ConnectionState().ECHAccepted, tc.wantECH)
			}
		})
	}
}
