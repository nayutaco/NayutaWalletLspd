package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"

	"github.com/nayutaco/NayutaHub2Lspd/rpc"
	lspdrpc "github.com/nayutaco/NayutaHub2LspdProto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
)

func (lc *LspClient) connectToLsp() error {
	grpcHost := os.Getenv("LISTEN_ADDRESS")
	grpcAddr := fmt.Sprintf("localhost:%s", strings.Split(grpcHost, ":")[1])
	token := os.Getenv("TOKEN")
	cert := os.Getenv("LSP_CERT")

	var option grpc.DialOption
	cp := x509.NewCertPool()
	if !cp.AppendCertsFromPEM([]byte(cert)) {
		return fmt.Errorf("AppendCertsFromPEM")
	}
	creds := credentials.NewTLS(&tls.Config{
		ServerName: "localhost",
		RootCAs:    cp,
	})
	option = grpc.WithTransportCredentials(creds)
	var err error
	lc.Conn, err = grpc.Dial(grpcAddr, option)
	if err != nil {
		return fmt.Errorf("connectToLsp:Dial: %v", err)
	}
	lc.Ctx, lc.Cancel = context.WithCancel(
		metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer "+token),
	)
	lc.Server = lspdrpc.NewLightningServiceClient(lc.Conn)
	lc.Client = rpc.NewInternalClient(lc.Conn)
	return nil
}

func (lc *LspClient) disconnect() {
	lc.Conn.Close()
	lc.Cancel()
}
