package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	log "github.com/sirupsen/logrus"

	lspdrpc "github.com/nayutaco/NayutaHub2LspdProto"
	"google.golang.org/protobuf/proto"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lntypes"

	"google.golang.org/api/playintegrity/v1"
	"google.golang.org/grpc/metadata"
)

func (s *server) Ping(ctx context.Context, in *lspdrpc.PingRequest) (*lspdrpc.PingReply, error) {
	log.Trace("Ping")
	return &lspdrpc.PingReply{
		Nonce: in.Nonce,
	}, nil
}

func (s *server) ChannelInformation(ctx context.Context, in *lspdrpc.ChannelInformationRequest) (*lspdrpc.ChannelInformationReply, error) {
	log.Trace("ChannelInformation")
	return &lspdrpc.ChannelInformationReply{
		Name:                  os.Getenv("NODE_NAME"),
		Pubkey:                os.Getenv("NODE_PUBKEY"),
		Host:                  os.Getenv("NODE_HOST"),
		BaseFeeMsat:           baseFeeMsat,
		FeeRate:               feeRate,
		TimeLockDelta:         timeLockDelta,
		ChannelFeePermyriad:   channelFeePermyriad,
		ChannelMinimumFeeMsat: channelMinimumFeeMsat,
		LspPubkey:             publicKey.SerializeCompressed(),
		MaxInactiveDuration:   maxInactiveDuration,
		Version:               version,
		SwapScriptVersion:     swapScriptVersion,
	}, nil
}

func (s *server) RegisterPayment(ctx context.Context, in *lspdrpc.RegisterPaymentRequest) (*lspdrpc.RegisterPaymentReply, error) {
	log.Trace("RegisterPayment")
	clientCtx := metadata.AppendToOutgoingContext(context.Background(), "macaroon", os.Getenv("LND_MACAROON_HEX"))
	data, err := Decrypt(privateKey, in.Blob)
	if err != nil {
		return nil, logAlarmNotify("btcec.Decrypt(%x) error: %v", in.Blob, err)
	}
	var pi lspdrpc.PaymentInformation
	err = proto.Unmarshal(data, &pi)
	if err != nil {
		return nil, logAlarmNotify("proto.Unmarshal(%x) error: %v", data, err)
	}
	log.Tracef("RegisterPayment - Destination: %x, pi.PaymentHash: %x, pi.IncomingAmountMsat: %v, pi.OutgoingAmountMsat: %v",
		pi.Destination, pi.PaymentHash, pi.IncomingAmountMsat, pi.OutgoingAmountMsat)
	err = checkPayment(pi.IncomingAmountMsat, pi.OutgoingAmountMsat)
	if err != nil {
		return nil, logAlarmNotify("checkPayment(%v, %v) error: %v", pi.IncomingAmountMsat, pi.OutgoingAmountMsat, err)
	}
	utxoCnt, err := getUtxos(clientCtx, client)
	if err != nil {
		return nil, logAlarmNotify("getUtxos error: %v", err)
	}
	if utxoCnt == 0 {
		return nil, logAlarmNotify("LSP has no UTXOs.")
	}
	err = registerPayment(pi.Destination, pi.PaymentHash, pi.PaymentSecret, pi.IncomingAmountMsat, pi.OutgoingAmountMsat)
	if err != nil {
		return nil, logAlarmNotify("RegisterPayment() error: %v", err)
	}
	log.Debugf("RegisterPayment - Destination: %x, pi.PaymentHash: %x, pi.PaymentSecret: %x, pi.IncomingAmountMsat: %v, pi.OutgoingAmountMsat: %v",
		pi.Destination, pi.PaymentHash, pi.PaymentSecret, pi.IncomingAmountMsat, pi.OutgoingAmountMsat)
	return &lspdrpc.RegisterPaymentReply{}, nil
}

// IntegrityVerify()
func (s *server) OpenChannel(ctx context.Context, in *lspdrpc.OpenChannelRequest) (*lspdrpc.OpenChannelReply, error) {
	log.Trace("OpenChannel")
	r, err, _ := openChannelReqGroup.Do(in.Pubkey, func() (interface{}, error) {
		// already opened
		nodeChannels, err := getNodeChannels(in.Pubkey)
		if err != nil {
			return nil, fmt.Errorf("getNodeChannels: %v(EOPENCHAN=1399)", err)
		}
		// opening
		pendingChannels, err := getPendingNodeChannels(in.Pubkey)
		if err != nil {
			return nil, fmt.Errorf("getPendingNodeChannels: %v(EOPENCHAN=1399)", err)
		}
		if len(nodeChannels) != 0 || len(pendingChannels) != 0 {
			return nil, fmt.Errorf("channel opening or opened(channels=%d, pendings=%d)(EOPENCHAN=1301)", len(nodeChannels), len(pendingChannels))
		}

		// has been opened by this API
		destBytes, err := hex.DecodeString(in.Pubkey)
		if err != nil {
			return nil, fmt.Errorf("invalid pubkey: %v(EOPENCHAN=1399)", err)
		}
		openedChan, err := openedChannel(destBytes, dbOpenChanReasonOpenChan)
		if err != nil {
			return nil, fmt.Errorf("hasChannel: %v(EOPENCHAN=1399)", err)
		}
		if openedChan > 0 {
			_, lastUpdate, err := latestChannel(destBytes)
			if err != nil {
				return nil, fmt.Errorf("latestChannel: %v(EOPENCHAN=1399)", err)
			}
			log.Debugf("  lastUpdate:%s", lastUpdate.String())
			if time.Now().UnixMilli()-lastUpdate.UnixMilli() < openChannelLimitMilli {
				return nil, fmt.Errorf("this channel had been created recently(EOPENCHAN=1302)")
			}
		}

		// integrity result check
		if (network.Name == "mainnet") {
			dbIntegrity, err := dbGetIntegrity(destBytes)
			if err != nil {
				return nil, fmt.Errorf("dbGetIntegrity error: %v(EOPENCHAN=1399)", err)
			}
			if dbIntegrity == nil {
				return nil, fmt.Errorf("integrity result is not registered(EOPENCHAN=1303)")
			}
			if time.Now().UnixMilli()-dbIntegrity.ExecutedAt.UnixMilli() >= integrityResultLimitMilli {
				return nil, fmt.Errorf("integrity result is out of date(EOPENCHAN=1304)")
			}
			if !dbIntegrity.Result {
				return nil, fmt.Errorf("integrity result is false(EOPENCHAN=1305)")
			}
		} else {
			log.Debugf("OpenChannel: skip integrity result check")
		}

		var txidStr string
		var outputIndex uint32
		clientCtx := metadata.AppendToOutgoingContext(ctx, "macaroon", os.Getenv("LND_MACAROON_HEX"))
		channelPoint, err := openChannelSync(clientCtx, client, destBytes, privateChannelCapacity)
		if err != nil {
			return nil, fmt.Errorf("error in openChannelSync: %v(EOPENCHAN=1306)", err)
		}

		txid, _ := chainhash.NewHash(channelPoint.GetFundingTxidBytes())
		if txid == nil {
			return nil, fmt.Errorf("NewHash: txid is null(EOPENCHAN=1399)")
		}
		txidStr = txid.String()
		outputIndex = channelPoint.GetOutputIndex()
		channelPointStr := fmt.Sprintf("%s:%d", txidStr, outputIndex)
		chanID, err := waitChannelCreation(clientCtx, destBytes, channelPointStr)
		if err != nil {
			return nil, fmt.Errorf("waitChannelCreation: %v(EOPENCHAN=1399)", err)
		}

		err = insertChannel(chanID, channelPointStr, destBytes, time.Now(), dbOpenChanReasonOpenChan)
		if err != nil {
			logAlarmNotify("OpenChannel: insertChannel: %v(EOPENCHAN=1399)", err)
			// not stop
		}
		return &lspdrpc.OpenChannelReply{TxHash: txidStr, OutputIndex: outputIndex}, nil
	})

	if err != nil {
		return nil, logAlarmNotify("OpenChannel(%s): err=%v", in.Pubkey, err)
	}
	return r.(*lspdrpc.OpenChannelReply), nil
}

func (s *server) RegisterSubmarine(ctx context.Context, in *lspdrpc.Encrypted) (*lspdrpc.Encrypted, error) {
	log.Trace("RegisterSubmarine")
	clientCtx := metadata.AppendToOutgoingContext(context.Background(), "macaroon", os.Getenv("LND_MACAROON_HEX"))
	data, err := Decrypt(privateKey, in.Data)
	if err != nil {
		return nil, logAlarmNotify("btcec.Decrypt(%x) error: %v", in.Data, err)
	}
	var rs lspdrpc.RegisterSubmarineRequest
	err = proto.Unmarshal(data, &rs)
	if err != nil {
		return nil, logAlarmNotify("proto.Unmarshal(%x) error: %v", data, err)
	}
	utxoCnt, err := getUtxos(clientCtx, client)
	if err != nil {
		return nil, logAlarmNotify("getUtxos error: %v", err)
	}
	if utxoCnt == 0 {
		return nil, logAlarmNotify("LSP has no UTXOs.")
	}

	scriptAddress, htlcPubkey, err := registerSubmarine(&rs)
	if err != nil {
		return nil, logAlarmNotify("submarine() error: %v", err)
	}

	reqly := &lspdrpc.RegisterSubmarineReply{
		ScriptAddress: scriptAddress,
		HtlcPubkey:    htlcPubkey,
	}
	data, _ = proto.Marshal(reqly)

	// encrypt
	lspPubkeyBytes, err := btcec.ParsePubKey(rs.EncryptPubkey)
	if err != nil {
		log.Errorf("btcec.ParsePubKey(%x) error: %v", rs.EncryptPubkey, err)
		return nil, err
	}
	encrypted, err := Encrypt(lspPubkeyBytes, data)
	if err != nil {
		return nil, err
	}
	res := &lspdrpc.Encrypted{
		Data: encrypted,
	}
	return res, err
}

// ReceiveSubmarine はクライアントからのAPI呼び出し。
// transaction の output が登録されて未処理の場合は submarine swap を開始する。
func (s *server) ReceiveSubmarine(ctx context.Context, in *lspdrpc.Encrypted) (*lspdrpc.ReceiveSubmarineReply, error) {
	log.Trace("ReceiveSubmarine")
	clientCtx := metadata.AppendToOutgoingContext(context.Background(), "macaroon", os.Getenv("LND_MACAROON_HEX"))
	data, err := Decrypt(privateKey, in.Data)
	if err != nil {
		return nil, logAlarmNotify("btcec.Decrypt(%x) error: %v", in.Data, err)
	}
	var rs lspdrpc.ReceiveSubmarineRequest
	err = proto.Unmarshal(data, &rs)
	if err != nil {
		return nil, logAlarmNotify("proto.Unmarshal(%x) error: %v", data, err)
	}

	if err != nil {
		return nil, logAlarmNotify("submarine() error: %v", err)
	}
	sub, err := dbGetSubmarine(rs.PaymentHash)
	if err != nil {
		return nil, logAlarmNotify("dbGetSubmarine() error: %v", err)
	}
	if sub.Status != dbSubmarineStatReg || len(sub.Invoice) > 0 {
		// invoice登録済み
		return nil, logAlarmNotify("invoice already registered")
	}
	resDecode, err := client.DecodePayReq(clientCtx, &lnrpc.PayReqString{PayReq: rs.Invoice})
	if err != nil {
		return nil, logAlarmNotify("invalid invoice: %v", err)
	}
	log.Tracef("resDecode=%v", resDecode)
	hash, err := lntypes.MakeHashFromStr(resDecode.PaymentHash)
	if err != nil {
		return nil, logAlarmNotify("invalid invoice: %v", err)
	}
	if !bytes.Equal(hash[:], rs.PaymentHash) {
		return nil, logAlarmNotify("PaymentHash not match")
	}
	if resDecode.CltvExpiry+swapCltvSafety >= int64(csvHeights[swapScriptVersion]) {
		// invoice の min_final_cltv_expiry が swap script の OP_CSV に近すぎる
		return nil, logAlarmNotify("ReceiveSubmarine: CltvExpiry(%v) >= OP_CSV height", resDecode.CltvExpiry)
	}
	err = dbInvoiceSubmarine(rs.PaymentHash, rs.Invoice)
	if err != nil {
		return nil, logAlarmNotify("dbInvoiceSubmarine err: %v", err)
	}
	sub.Invoice = rs.Invoice
	chk, err := dbCheckOpenSubmarine(rs.PaymentHash)
	if err != nil {
		return nil, logAlarmNotify("dbCheckOpenSubmarine err: %v", err)
	}
	if chk {
		// invoiceとTXID検出が揃った
		err = submarineProcess(rs.PaymentHash, sub, resDecode.NumMsat)
	} else {
		log.Debugf("ReceiveSubmarine(%x): transaction yet received.", rs.PaymentHash)
	}

	return &lspdrpc.ReceiveSubmarineReply{}, err
}

func (s *server) QueryRoutes(ctx context.Context, in *lspdrpc.Encrypted) (*lspdrpc.Encrypted, error) {
	log.Trace("QueryRoutes")
	clientCtx := metadata.AppendToOutgoingContext(context.Background(), "macaroon", os.Getenv("LND_MACAROON_HEX"))
	data, err := Decrypt(privateKey, in.Data)
	if err != nil {
		return nil, logNotify("btcec.Decrypt(%x) error: %v", in.Data, err)
	}
	var rs lspdrpc.QueryRoutesRequest
	err = proto.Unmarshal(data, &rs)
	if err != nil {
		return nil, logNotify("proto.Unmarshal(%x) error: %v", data, err)
	}

	resDecode, err := client.DecodePayReq(clientCtx, &lnrpc.PayReqString{PayReq: rs.Invoice})
	if err != nil {
		return nil, logNotify("invalid invoice: %v", err)
	}
	hashedDestination := sha256.Sum256([]byte(resDecode.Destination))
	amount := resDecode.NumSatoshis
	if amount == 0 {
		log.Debugf("QueryRoutes: use specified amount")
		amount = rs.Amount
	}
	log.Debugf("QueryRoutes: decode invoice: destination=`%s`, route_hints_num=%d, cltv_expiry=%d, amount_is_zero=%v",
		hex.EncodeToString(hashedDestination[:]),
		len(resDecode.RouteHints),
		resDecode.CltvExpiry,
		resDecode.NumSatoshis == 0,
	)
	if rs.IgnoredNodes != nil && len(rs.IgnoredNodes) > 0 {
		for i, v := range rs.IgnoredNodes {
			log.Debugf("  ignore nodes[%d]%x", i, v)
		}
	}
	ignoredPairs := []*lnrpc.NodePair{}
	if rs.IgnoredPairs != nil && len(rs.IgnoredPairs) > 0 {
		for i, v := range rs.IgnoredPairs {
			hashedFrom := sha256.Sum256([]byte(v.From))
			hashedTo := sha256.Sum256([]byte(v.To))
			log.Debugf("  ignore pairs[%d] from=%x, to=%x", i, hashedFrom, hashedTo)
			pair := &lnrpc.NodePair{
				From: v.From,
				To:   v.To,
			}
			ignoredPairs = append(ignoredPairs, pair)
		}
	}

	response, err := client.QueryRoutes(clientCtx, &lnrpc.QueryRoutesRequest{
		PubKey:            resDecode.Destination,
		Amt:               amount,
		RouteHints:        resDecode.RouteHints,
		IgnoredNodes:      rs.IgnoredNodes,
		IgnoredPairs:      ignoredPairs,
		FinalCltvDelta:    int32(resDecode.CltvExpiry),
		UseMissionControl: true,
	})
	if err != nil {
		return nil, logNotify("fail QueryRoutes: %v", err)
	}

	data, _ = proto.Marshal(response)

	// encrypt
	lspPubkeyBytes, err := btcec.ParsePubKey(rs.EncryptPubkey)
	if err != nil {
		log.Errorf("btcec.ParsePubKey(%x) error: %v", rs.EncryptPubkey, err)
		return nil, err
	}
	encrypted, err := Encrypt(lspPubkeyBytes, data)
	if err != nil {
		return nil, err
	}
	res := &lspdrpc.Encrypted{
		Data: encrypted,
	}
	return res, nil
}

func (s *server) RegisterUserInfo(ctx context.Context, in *lspdrpc.Encrypted) (*lspdrpc.RegisterUserInfoReply, error) {
	log.Trace("RegisterUserInfo")
	data, err := Decrypt(privateKey, in.Data)
	if err != nil {
		return nil, logNotify("btcec.Decrypt(%x) error: %v", in.Data, err)
	}
	var userInfo lspdrpc.RegisterUserInfoRequest
	err = proto.Unmarshal(data, &userInfo)
	if err != nil {
		return nil, logNotify("proto.Unmarshal(%x) error: %v", data, err)
	}

	if len(userInfo.MailAddress) == 0 {
		return nil, logAlarmNotify("fail RegisterUserInfo: null mail address")
	}
	err = dbRegisterUserInfo(userInfo.MailAddress)
	if err != nil {
		return nil, logAlarmNotify("fail RegisterUserInfo: db: %v", err)
	}

	return &lspdrpc.RegisterUserInfoReply{}, nil
}

func (s *server) ReportMessage(ctx context.Context, in *lspdrpc.Encrypted) (*lspdrpc.ReportReply, error) {
	log.Trace("ReportMessage")
	data, err := Decrypt(privateKey, in.Data)
	if err != nil {
		return nil, logNotify("ReportMessage: btcec.Decrypt(%x) error: %v", in.Data, err)
	}
	var report lspdrpc.ReportRequest
	err = proto.Unmarshal(data, &report)
	if err != nil {
		return nil, logNotify("ReportMessage: proto.Unmarshal(%x) error: %v", data, err)
	}

	msg := fmt.Sprintf("REPORT: category=%s, level=%d, message=%s", report.Category, report.Level, report.Message)
	switch report.Level {
	case lspdrpc.ReportRequest_REPORTLEVEL_NORMAL:
		log.Infof(msg)
	case lspdrpc.ReportRequest_REPORTLEVEL_NOTIFY:
		logNotify(msg)
	case lspdrpc.ReportRequest_REPORTLEVEL_ALERT:
		logAlarmNotify(msg)
	default:
		log.Warnf("ReportMessage: unknown level(%v): category=%s, message=%s", report.Level, report.Category, report.Message)
	}

	return &lspdrpc.ReportReply{}, nil
}

func generateNonce() (string, error) {
	// https://developer.android.com/google/play/integrity/verdict?hl=ja#nonce
	// 16-500 chars
	nonce := make([]byte, 32)
	_, err := rand.Read(nonce)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(nonce), nil
}

func (s *server) IntegrityNonce(ctx context.Context, in *lspdrpc.Encrypted) (*lspdrpc.Encrypted, error) {
	log.Trace("IntegrityNonce")
	data, err := Decrypt(privateKey, in.Data)
	if err != nil {
		return nil, logAlarmNotify("IntegrityNonce: btcec.Decrypt(%x) error: %v", in.Data, err)
	}
	var request lspdrpc.IntegrityNonceRequest
	err = proto.Unmarshal(data, &request)
	if err != nil {
		return nil, logAlarmNotify("IntegrityNonce: proto.Unmarshal(%x) error: %v", data, err)
	}

	log.Debugf("IntegrityNonce: deocde pubkey=%x, id=%s", request.Pubkey, request.Id)

	response := lspdrpc.IntegrityNonceReply{}
	response.Nonce, err = generateNonce()
	if err != nil {
		return nil, logAlarmNotify("IntegrityNonce(node_id=%x) generateNonce: %v", request.Pubkey, err)
	}
	logNotify("IntegrityNonce(node_id=%x): created", request.Pubkey)
	err = dbInsertNonceIntegrity(request.Pubkey, request.Id, response.Nonce, time.Now())
	if err != nil {
		return nil, logAlarmNotify("IntegrityNonce(node_id=%x) DB error: %v", request.Pubkey, err)
	}
	data, _ = proto.Marshal(&response)

	// encrypt
	lspPubkeyBytes, err := btcec.ParsePubKey(request.EncryptPubkey)
	if err != nil {
		log.Errorf("btcec.ParsePubKey(%x) error: %v", request.EncryptPubkey, err)
		return nil, err
	}
	encrypted, err := Encrypt(lspPubkeyBytes, data)
	if err != nil {
		return nil, err
	}
	res := &lspdrpc.Encrypted{
		Data: encrypted,
	}
	return res, nil
}

func integrityCheck(decodedToken *playintegrity.DecodeIntegrityTokenResponse, nonce string) bool {
	if decodedToken == nil ||
		decodedToken.TokenPayloadExternal == nil ||
		decodedToken.TokenPayloadExternal.AccountDetails == nil ||
		decodedToken.TokenPayloadExternal.AppIntegrity == nil ||
		decodedToken.TokenPayloadExternal.DeviceIntegrity == nil ||
		decodedToken.TokenPayloadExternal.RequestDetails == nil {

		log.Debugf("   fail: decodedToken.TokenPayloadExternal.* has nil member")
		return false
	}

	verifyResult := true
	if decodedToken.TokenPayloadExternal.AccountDetails.AppLicensingVerdict != "LICENSED" {
		log.Debugf("   fail: decodedToken.TokenPayloadExternal.AccountDetails.AppLicensingVerdict: %s", decodedToken.TokenPayloadExternal.AccountDetails.AppLicensingVerdict)
		verifyResult = false
	}
	if decodedToken.TokenPayloadExternal.AppIntegrity.AppRecognitionVerdict != "PLAY_RECOGNIZED" {
		log.Debugf("   fail: decodedToken.TokenPayloadExternal.AppIntegrity.AppRecognitionVerdict: %s", decodedToken.TokenPayloadExternal.AppIntegrity.AppRecognitionVerdict)
		verifyResult = false
	}
	if decodedToken.TokenPayloadExternal.AppIntegrity.PackageName != packageApp {
		log.Debugf("   fail: decodedToken.TokenPayloadExternal.AppIntegrity.PackageName: %s", decodedToken.TokenPayloadExternal.AppIntegrity.PackageName)
		verifyResult = false
	}
	deviceRecog := 0
	for _, v := range decodedToken.TokenPayloadExternal.DeviceIntegrity.DeviceRecognitionVerdict {
		if v == "MEETS_BASIC_INTEGRITY" {
			deviceRecog |= 1
		}
		if v == "MEETS_DEVICE_INTEGRITY" {
			deviceRecog |= 2
		}
		if v == "MEETS_VIRTUAL_INTEGRITY" {
			log.Debugf("     fail: MEETS_VIRTUAL_INTEGRITY")
			verifyResult = false
		}
	}
	if deviceRecog != 3 {
		log.Debugf("   fail: decodedToken.TokenPayloadExternal.DeviceIntegrity.DeviceRecognitionVerdict")
		verifyResult = false
	}
	if decodedToken.TokenPayloadExternal.RequestDetails.Nonce != nonce {
		log.Debugf("   fail: decodedToken.TokenPayloadExternal.RequestDetails.Nonce: %s", decodedToken.TokenPayloadExternal.RequestDetails.Nonce)
		verifyResult = false
	}
	if decodedToken.TokenPayloadExternal.RequestDetails.RequestPackageName != packageApp {
		log.Debugf("   fail: decodedToken.TokenPayloadExternal.RequestDetails.RequestPackageName: %s", decodedToken.TokenPayloadExternal.RequestDetails.RequestPackageName)
		verifyResult = false
	}

	return verifyResult
}

// https://github.com/googleapis/google-api-go-client/tree/main/playintegrity/v1
func (s *server) IntegrityVerify(ctx context.Context, in *lspdrpc.Encrypted) (*lspdrpc.IntegrityVerifyReply, error) {
	log.Trace("IntegrityVerify")
	data, err := Decrypt(privateKey, in.Data)
	if err != nil {
		return nil, logAlarmNotify("IntegrityVerify: btcec.Decrypt(%x) error: %v", in.Data, err)
	}
	var request lspdrpc.IntegrityVerifyRequest
	err = proto.Unmarshal(data, &request)
	if err != nil {
		return nil, logAlarmNotify("IntegrityVerify: proto.Unmarshal(%x) error: %v", data, err)
	}

	response := lspdrpc.IntegrityVerifyReply{}
	if (network.Name != "mainnet") {
		log.Debugf("IntegrityVerify: skip integrity verify")
		response.Result = lspdrpc.IntegrityResult_INTEGRITYRESULT_OK
		return &response, nil
	}
	dbIntegrity, err := dbGetIntegrity(request.Pubkey)
	if err != nil {
		return nil, logAlarmNotify("IntegrityVerify(node_id=%x): dbGetIntegrity error: %v", data, err)
	}

	if len(request.Token) == 0 {
		// return previous result
		response.Result = lspdrpc.IntegrityResult_INTEGRITYRESULT_NONE
		if dbIntegrity != nil && time.Now().UnixMilli()-dbIntegrity.ExecutedAt.UnixMilli() < integrityResultLimitMilli {
			// already verified
			if dbIntegrity.Result {
				response.Result = lspdrpc.IntegrityResult_INTEGRITYRESULT_OK
			} else {
				response.Result = lspdrpc.IntegrityResult_INTEGRITYRESULT_NG
			}
		}
		logNotify("IntegrityVerify(node_id=%x): previous result(result=%d)", request.Pubkey, response.Result)
		return &response, nil
	}

	if dbIntegrity == nil {
		return nil, logAlarmNotify("IntegrityVerify(node_id=%x): fail get: %v", request.Pubkey, err)
	}
	log.Tracef("IntegrityVerify(node_id=%x): createdAt=%s, executedAt=%s",
		request.Pubkey, dbIntegrity.CreatedAt.String(), dbIntegrity.ExecutedAt.String())

	var verifyResult bool
	if dbIntegrity.Id == "iOS" {
		// iOSではIntegrity APIが使用できない
		log.Tracef("IntegrityVerify(node_id=%x): skip integrity check", request.Pubkey)
		verifyResult = true
	} else {
		// iOS以外
		integrityCtx := context.Background()
		integritySvc, err := playintegrity.NewService(integrityCtx)
		if err != nil {
			return nil, logAlarmNotify("IntegrityVerify(node_id=%x): playintegrity.NewService error: %v", request.Pubkey, err)
		}
		tokenRequest := &playintegrity.DecodeIntegrityTokenRequest{
			IntegrityToken:  request.Token,
			ForceSendFields: []string{},
			NullFields:      []string{},
		}
		decodeRequest := integritySvc.V1.DecodeIntegrityToken(packageApp, tokenRequest)
		decodedToken, err := decodeRequest.Do()
		if err != nil {
			return nil, logAlarmNotify("IntegrityVerify(node_id=%x): playintegrity.Do error: %v", request.Pubkey, err)
		}
		verifyResult = integrityCheck(decodedToken, dbIntegrity.Nonce)

		js, err := decodedToken.TokenPayloadExternal.MarshalJSON()
		if err == nil {
			log.Debugf("IntegrityVerify(node_id=%x): verifyResult=%v, TokenPayloadExternal=%s", request.Pubkey, verifyResult, string(js))
		} else {
			// ログ出力だけのためreturnしない
			logAlarmNotify("IntegrityVerify(node_id=%x): MarshalJSON error: %v", request.Pubkey, err)
		}
	}

	err = dbUpdateResultIntegrity(request.Pubkey, verifyResult, time.Now())
	if err != nil {
		return nil, logAlarmNotify("IntegrityVerify(node_id=%x): DB update=%v", request.Pubkey, err)
	}
	if verifyResult {
		response.Result = lspdrpc.IntegrityResult_INTEGRITYRESULT_OK
	} else {
		response.Result = lspdrpc.IntegrityResult_INTEGRITYRESULT_NG
	}
	logNotify("IntegrityVerify(node_id=%x): verify result=%d", request.Pubkey, response.Result)

	return &response, nil
}
