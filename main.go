package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/singleflight"

	"github.com/nayutaco/NayutaHub2Lspd/notify"
	"github.com/nayutaco/NayutaHub2Lspd/rpc"
	lspdrpc "github.com/nayutaco/NayutaHub2LspdProto"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/caddyserver/certmagic"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	"github.com/joho/godotenv"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/chainrpc"
	"github.com/lightningnetwork/lnd/lnrpc/routerrpc"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	fileLspdEnv = "lspd.env"
	fileLspdLog = "lspd.log"

	otfInmountAllow = int64(2) // baseFeeMsat*otfInmountAllow

	packageApp = "com.nayuta.core2"

	integrityResultLimitMilli = int64(1000 * 60 * 60 * 1)          // result is valid: nowTime-theTime < limit
	openChannelLimitMilli     = int64(1000 * 60 * 60 * 24 * 7 * 2) // too recently: nowTime-theTime < limit
)

type server struct {
	lspdrpc.UnimplementedLightningServiceServer
}

type internal struct {
	rpc.UnimplementedInternalServer
}

var (
	client                    lnrpc.LightningClient
	routerClient              routerrpc.RouterClient
	chainNotifierClient       chainrpc.ChainNotifierClient
	walletKitClient           walletrpc.WalletKitClient
	openChannelReqGroup       singleflight.Group
	privateKey                *btcec.PrivateKey
	publicKey                 *btcec.PublicKey
	network                   *chaincfg.Params
	baseFeeMsat               int64
	feeRate                   float64
	timeLockDelta             uint32
	channelFeePermyriad       int64
	channelMinimumFeeMsat     int64
	additionalChannelCapacity int64
	maxInactiveDuration       int64
	maxChannelCapacity        int64
	privateChannelCapacity    int64
	openChanFeeMax            uint64
	version                   string
)

func main() {
	var err error

	homeDir, _ := os.UserHomeDir()
	envPath := fmt.Sprintf("%s/.lspd", homeDir)
	optVersion := flag.Bool("version", false, "output version")
	optGenkey := flag.Bool("genkey", false, "generate key")
	optLogStart := flag.Bool("logstart", false, "start with output log to file")
	optStart := flag.Bool("start", false, "start with output log to stdout")
	optEnvDir := flag.String("envdir", envPath, "PATH to load lspd.env")
	optLogDir := flag.String("logdir", envPath, "PATH to save log files")
	optLogLevel := flag.String("loglevel", "debug", "loglevel(error, warn, info, debug, trace)")
	flag.Parse()
	if flag.NArg() == 0 && flag.NFlag() == 0 {
		fmt.Printf("HELP:\n")
		flag.PrintDefaults()
		return
	}
	logLevel, err := convLoglevel(*optLogLevel)
	if err != nil {
		fmt.Printf("loglevel: %v\n", err)
		return
	}

	*optEnvDir = strings.TrimRight(*optEnvDir, "/")
	*optLogDir = strings.TrimRight(*optLogDir, "/")

	switch {
	case *optVersion:
		fmt.Printf("%s\n", version)
		return
	case *optGenkey:
		p, err := btcec.NewPrivateKey()
		if err != nil {
			log.Fatalf("btcec.NewPrivateKey() error: %v", err)
		}
		fmt.Printf("LSPD_PRIVATE_KEY=\"%x\"\n", p.Serialize())
		return
	case *optLogStart:
		os.Mkdir(*optLogDir, 0755)
		dt := fmt.Sprintf("%s/%s", *optLogDir, fileLspdLog)
		logFile, err := os.OpenFile(dt, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatalf("logfile error: %v", err)
		}
		// log.SetFormatter(&log.JSONFormatter{})
		log.SetFormatter(&log.TextFormatter{})
		log.SetOutput(logFile)
	case *optStart:
		break
	default:
		fmt.Printf("invalid option.\n")
		return
	}
	log.SetLevel(logLevel)
	log.Error("log.Error")
	log.Warn("log.Warn")
	log.Info("log.Info")
	log.Debug("log.Debug")
	log.Trace("log.Trace")

	envLoad(*optEnvDir)

	// slack
	notify.SlackInit(os.Getenv("SLACK_BOT_TOKEN"))
	startMsg := fmt.Sprintf("LSP: version=%s, swapScriptVersion=%v", version, swapScriptVersion)
	notify.SlackAlarmMessagePush(startMsg)

	err = pgConnect()
	if err != nil {
		logFatal("pgConnect() error: %v", err)
	}

	privateKeyBytes, err := hex.DecodeString(os.Getenv("LSPD_PRIVATE_KEY"))
	if err != nil {
		logFatal("hex.DecodeString(os.Getenv(\"LSPD_PRIVATE_KEY\")=%v) error: %v", os.Getenv("LSPD_PRIVATE_KEY"), err)
	}
	privateKey, publicKey = btcec.PrivKeyFromBytes(privateKeyBytes)

	certmagicDomain := os.Getenv("CERTMAGIC_DOMAIN")
	address := os.Getenv("LISTEN_ADDRESS")
	var lis net.Listener
	if certmagicDomain == "" {
		var err error
		lis, err = net.Listen("tcp", address)
		if err != nil {
			logFatal("failed to listen: %v", err)
		}
	} else {
		tlsConfig, err := certmagic.TLS([]string{certmagicDomain})
		if err != nil {
			logFatal("failed to run certmagic: %v", err)
		}
		lis, err = tls.Listen("tcp", address, tlsConfig)
		if err != nil {
			logFatal("failed to listen: %v", err)
		}
	}

	// Creds file to connect to LND gRPC
	cp := x509.NewCertPool()
	if !cp.AppendCertsFromPEM([]byte(strings.Replace(os.Getenv("LND_CERT"), "\\n", "\n", -1))) {
		logFatal("credentials: failed to append certificates")
	}
	creds := credentials.NewClientTLSFromCert(cp, "")

	// Address of an LND instance
	conn, err := grpc.Dial(os.Getenv("LND_ADDRESS"), grpc.WithTransportCredentials(creds))
	if err != nil {
		logFatal("LSP: failed to connect to LND gRPC: %v", err)
	}
	defer conn.Close()
	client = lnrpc.NewLightningClient(conn)
	routerClient = routerrpc.NewRouterClient(conn)
	chainNotifierClient = chainrpc.NewChainNotifierClient(conn)
	walletKitClient = walletrpc.NewWalletKitClient(conn)
	stateClient := lnrpc.NewStateClient(conn)

	clientCtx := metadata.AppendToOutgoingContext(context.Background(), "macaroon", os.Getenv("LND_MACAROON_HEX"))
	for {
		stat, err := stateClient.GetState(clientCtx, &lnrpc.GetStateRequest{})
		if err != nil {
			logAlarmNotify("LSP: failed GetState: %v", err)
			time.Sleep(30 * time.Second)
			continue
		}
		if stat.GetState() != lnrpc.WalletState_SERVER_ACTIVE {
			logAlarmNotify("LSP: not SERVER_ACTIVE state")
			time.Sleep(30 * time.Second)
			continue
		}
		break
	}

	info, err := client.GetInfo(clientCtx, &lnrpc.GetInfoRequest{})
	if err != nil {
		logFatal("client.GetInfo() error: %v", err)
	}
	log.Printf("own node_id: %v", info.IdentityPubkey)
	if os.Getenv("NODE_PUBKEY") != info.IdentityPubkey {
		logFatal("mismatch NODE_PUBKEY")
	}
	network = getChainParams(info.Chains[0].Network)

	utxoCnt, err := getUtxos(clientCtx, client)
	if err != nil {
		logFatal("getUtxos error: %v", err)
	}
	log.Infof("utxos: %v", utxoCnt)

	notify.SlackAlarmMessagePush("LSP: started.")
	defer func() {
		log.Infof("stop LSP")
		if p := recover(); p != nil {
			log.Infof("abnormal terminate: %v", string(debug.Stack()))
		}
	}()

	go intercept()
	go forwardingHistorySynchronize()
	go channelsSynchronize(chainNotifierClient)
	go transactionSubscribe(clientCtx)

	var s *grpc.Server
	options := grpc_middleware.WithUnaryServerChain(func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		if md, ok := metadata.FromIncomingContext(ctx); ok {
			for _, auth := range md.Get("authorization") {
				if auth == "Bearer "+os.Getenv("TOKEN") {
					return handler(ctx, req)
				}
			}
		}
		return nil, status.Errorf(codes.PermissionDenied, "Not authorized")
	})
	if os.Getenv("USE_LSP_TLS") == "TRUE" {
		fmt.Printf("TLS\n")
		pemCert := []byte(strings.Replace(os.Getenv("LSP_CERT"), "\\n", "\n", -1))
		pemKey := []byte(strings.Replace(os.Getenv("LSP_KEY"), "\\n", "\n", -1))
		certLspd, err := tls.X509KeyPair(pemCert, pemKey)
		if err != nil {
			logFatal("failed X509KeyPair: %v", err)
		}
		credsLspd := credentials.NewServerTLSFromCert(&certLspd)
		s = grpc.NewServer(options, grpc.Creds(credsLspd))
	} else {
		logAlarmNotify("NO TLS mode")
		s = grpc.NewServer(options)
	}
	lspdrpc.RegisterLightningServiceServer(s, &server{})
	rpc.RegisterInternalServer(s, &internal{})
	if err := s.Serve(lis); err != nil {
		logFatal("failed to serve: %v", err)
	}
}

func convLoglevel(logLevel string) (log.Level, error) {
	switch logLevel {
	case "error":
		return log.ErrorLevel, nil
	case "warn":
		return log.WarnLevel, nil
	case "info":
		return log.InfoLevel, nil
	case "debug":
		return log.DebugLevel, nil
	case "trace":
		return log.TraceLevel, nil
	}
	return log.PanicLevel, fmt.Errorf("unknown loglevel: %s", logLevel)
}

func envLoad(envPath string) {
	envFile := fmt.Sprintf("%s/%s", envPath, fileLspdEnv)
	err := godotenv.Load(envFile)
	if err != nil {
		log.Fatalf("Error loading \"%s\"", envFile)
	}
	log.Debugf("load \"%s\"", envFile)

	var uval64 uint64
	fmt.Printf("read BASE_FEE_MSAT\n")
	baseFeeMsat, err = strconv.ParseInt(os.Getenv("BASE_FEE_MSAT"), 10, 64)
	if err == nil {
		fmt.Printf("read FEE_RATE\n")
		feeRate, err = strconv.ParseFloat(os.Getenv("FEE_RATE"), 64)
	}
	if err == nil {
		fmt.Printf("read TIME_LOCK_DELTA\n")
		uval64, err = strconv.ParseUint(os.Getenv("TIME_LOCK_DELTA"), 10, 32)
	}
	if err == nil {
		fmt.Printf("read CHANNEL_FEE_PERMYRIAD\n")
		timeLockDelta = uint32(uval64)
		channelFeePermyriad, err = strconv.ParseInt(os.Getenv("CHANNEL_FEE_PERMYRIAD"), 10, 64)
	}
	if err == nil {
		fmt.Printf("read CHANNEL_MIN_FEE_MSAT\n")
		channelMinimumFeeMsat, err = strconv.ParseInt(os.Getenv("CHANNEL_MIN_FEE_MSAT"), 10, 64)
	}
	if err == nil {
		fmt.Printf("read ADDITIONAL_CHANNEL_CAPACITY\n")
		additionalChannelCapacity, err = strconv.ParseInt(os.Getenv("ADDITIONAL_CHANNEL_CAPACITY"), 10, 64)
		if additionalChannelCapacity <= propCapacity[len(propCapacity)-1].addCapacity {
			log.Fatal("Error: ADDITIONAL_CHANNEL_CAPACITY <= propCapacity")
		}
	}
	if err == nil {
		fmt.Printf("read MAX_INACTIVATE_DURATION\n")
		maxInactiveDuration, err = strconv.ParseInt(os.Getenv("MAX_INACTIVATE_DURATION"), 10, 64)
	}
	if err == nil {
		fmt.Printf("read MAX_CHANNEL_CAPACITY\n")
		maxChannelCapacity, err = strconv.ParseInt(os.Getenv("MAX_CHANNEL_CAPACITY"), 10, 64)
	}
	if err == nil {
		privateChannelCapacity, err = strconv.ParseInt(os.Getenv("PRIVATE_CHANNEL_CAPACITY"), 10, 64)
	}
	if err == nil {
		openChanFeeMax, err = strconv.ParseUint(os.Getenv("OPEN_CHANNEL_FEE_MAX"), 10, 64)
	}
	if err != nil {
		log.Fatalf("Error parse env: %v", err)
	}

	log.Infof("baseFeeMsat: %v", baseFeeMsat)
	log.Infof("feeRate: %v", feeRate)
	log.Infof("timeLockDelta: %v", timeLockDelta)
	log.Infof("channelFeePermyriad: %v", channelFeePermyriad)
	log.Infof("channelMinimumFeeMsat: %v", channelMinimumFeeMsat)
	log.Infof("additionalChannelCapacity: %v", additionalChannelCapacity)
	log.Infof("maxInactiveDuration: %v", maxInactiveDuration)
	log.Infof("maxChannelCapacity: %v", maxChannelCapacity)
	log.Infof("privateChannelCapacity: %v", privateChannelCapacity)
	log.Infof("openChannelFeeMax: %v", openChanFeeMax)
}

func getChainParams(network string) *chaincfg.Params {
	switch network {
	case "mainnet":
		return &chaincfg.MainNetParams
	case "testnet":
		return &chaincfg.TestNet3Params
	case "signet":
		return &chaincfg.SigNetParams
	case "regtest":
		return &chaincfg.RegressionNetParams
	default:
		log.Errorf("getChainParams: unknown: %v", network)
		return nil
	}
}

func logNotify(format string, params ...interface{}) error {
	msg := fmt.Sprintf(format, params...)
	notify.SlackMessagePush(msg)
	log.Infof(msg)
	return errors.New(msg)
}

func logAlarmNotify(format string, params ...interface{}) error {
	msg := fmt.Sprintf(format, params...)
	notify.SlackAlarmMessagePush(msg)
	log.Errorf(msg)
	return errors.New(msg)
}

func logFatal(format string, params ...interface{}) {
	msg := fmt.Sprintf(format, params...)
	notify.SlackAlarmMessagePush(msg)
	log.Fatalf(msg)
}
