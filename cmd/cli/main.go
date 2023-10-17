package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/joho/godotenv"
	"github.com/nayutaco/NayutaHub2Lspd/rpc"
	lspdrpc "github.com/nayutaco/NayutaHub2LspdProto"

	"google.golang.org/grpc"
)

const (
	fileLspdEnv = "lspd.env"
)

type LspClient struct {
	Conn   *grpc.ClientConn
	Client rpc.InternalClient
	Server lspdrpc.LightningServiceClient
	Ctx    context.Context
	Cancel context.CancelFunc
}

var ()

func main() {
	homeDir, _ := os.UserHomeDir()
	envPath := fmt.Sprintf("%s/.lspd", homeDir)
	optEnvDir := flag.String("envdir", envPath, "PATH to load lspd.env")
	flag.Parse()
	if flag.NArg() == 0 && flag.NFlag() == 0 {
		fmt.Printf("HELP:\n")
		flag.PrintDefaults()
		fmt.Printf(`

ping
	send ping

loglevel [ error | warn | info | debug | trace ]
	set loglevel
`,
		)
		return
	}
	*optEnvDir = strings.TrimRight(*optEnvDir, "/")
	envLoad(*optEnvDir)

	args := flag.Args()

	switch args[0] {
	case "ping":
		ping()
	case "loglevel":
		setLogLevel(args[1])
	}
}

func envLoad(envPath string) {
	envFile := fmt.Sprintf("%s/%s", envPath, fileLspdEnv)
	err := godotenv.Load(envFile)
	if err != nil {
		log.Fatalf("Error loading \"%s\"", envFile)
	}
}

func ping() error {
	lc := LspClient{}
	err := lc.connectToLsp()
	if err != nil {
		return fmt.Errorf("err: %v", err)
	}
	pingReq := &lspdrpc.PingRequest{
		Nonce: 12345,
	}
	res, err := lc.Server.Ping(lc.Ctx, pingReq)
	if err != nil {
		return fmt.Errorf("ping: err: %v", err)
	}
	if res.Nonce != 12345 {
		return fmt.Errorf("ping: nonce error")
	}
	fmt.Printf("ping success\n")
	return nil
}

func setLogLevel(loglevel string) error {
	lc := LspClient{}
	err := lc.connectToLsp()
	if err != nil {
		log.Printf("err: %v\n", err)
		return err
	}
	var level rpc.LogLevelRequest_LogLevel
	switch loglevel {
	case "error":
		level = rpc.LogLevelRequest_LOGLEVEL_ERROR
	case "warn":
		level = rpc.LogLevelRequest_LOGLEVEL_WARN
	case "info":
		level = rpc.LogLevelRequest_LOGLEVEL_INFO
	case "debug":
		level = rpc.LogLevelRequest_LOGLEVEL_DEBUG
	case "trace":
		level = rpc.LogLevelRequest_LOGLEVEL_TRACE
	default:
		return fmt.Errorf("setLogLevel: invalid argument: %s", loglevel)
	}

	req := &rpc.LogLevelRequest{
		Level: level,
	}
	_, err = lc.Client.SetLogLevel(lc.Ctx, req)
	if err != nil {
		fmt.Printf("error: %v", err)
		return err
	}
	return nil
}
