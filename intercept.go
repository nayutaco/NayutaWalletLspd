package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"os"
	"time"

	"github.com/nayutaco/NayutaHub2Lspd/notify"
	log "github.com/sirupsen/logrus"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/routerrpc"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/record"
	"github.com/lightningnetwork/lnd/routing/route"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	sphinx "github.com/lightningnetwork/lightning-onion"
)

type InterceptResult int

// propCapacity is list for proportionalCapacity().
var propCapacity = []struct {
	limitSat    int64
	addCapacity int64
}{
	{
		limitSat:    50_000,
		addCapacity: 20_000,
	},
	{
		limitSat:    100_000,
		addCapacity: 50_000,
	},
}

const (
	openTimeout      = 30 * time.Second
	openCheckTimeout = 60 * time.Second
)

const (
	interceptNone InterceptResult = iota
	interceptDone
)

func calcMinFeeMsat(incomingAmountMsat int64) int64 {
	fees := incomingAmountMsat * channelFeePermyriad / 10_000 / 1_000 * 1_000
	if fees < channelMinimumFeeMsat {
		fees = channelMinimumFeeMsat
	}
	return fees
}

func checkPayment(incomingAmountMsat, outgoingAmountMsat int64) error {
	fees := calcMinFeeMsat(incomingAmountMsat)
	if incomingAmountMsat-outgoingAmountMsat < fees {
		return fmt.Errorf("not enough fees: in=%d, out=%d, fee=%d", incomingAmountMsat, outgoingAmountMsat, fees)
	}
	return nil
}

func proportionalCapacity(localFundingAmountMsat int64) int64 {
	capacity := localFundingAmountMsat / 1000
	log.Tracef("proportionalCapacity: localFundingAmountMsat=%d, capacity=%d", localFundingAmountMsat, capacity)
	addCapacity := int64(0)
	for _, prop := range propCapacity {
		if capacity < prop.limitSat {
			addCapacity = prop.addCapacity
			break
		}
	}
	if addCapacity == 0 {
		addCapacity = additionalChannelCapacity
	}

	log.Tracef("proportionalCapacity: capacity=%d, addCapacity=%d", capacity, addCapacity)
	return capacity + addCapacity
}

// openChannel はチャネルをオープンする。
// キャパシティは localFundingAmountMsat/1000 + proportionalCapacity() になるので注意すること。
func openChannel(ctx context.Context, client lnrpc.LightningClient, paymentHash, destination []byte, localFundingAmountMsat int64) ([]byte, uint32, error) {
	capacity := proportionalCapacity(localFundingAmountMsat)
	channelPoint, err := openChannelSync(ctx, client, destination, capacity)
	if err != nil {
		return nil, 0, err
	}
	txid := channelPoint.GetFundingTxidBytes()
	index := channelPoint.OutputIndex
	notify.SendOpenChannelEmailNotification(
		paymentHash,
		localFundingAmountMsat,
		destination,
		capacity,
		txid,
		index,
	)
	err = setFundingTx(paymentHash, txid, int(index))
	return txid, index, err
}

func openChannelSync(ctx context.Context, client lnrpc.LightningClient, destination []byte, capacitySat int64) (*lnrpc.ChannelPoint, error) {
	var channelPoint *lnrpc.ChannelPoint
	var err error

	deadline := time.Now().Add(openTimeout)
	for {
		channelPoint, err = client.OpenChannelSync(ctx, &lnrpc.OpenChannelRequest{
			NodePubkey:         destination,
			LocalFundingAmount: capacitySat,
			Private:            true,
			SatPerVbyte:        openChanFeeMax,
			CommitmentType:     lnrpc.CommitmentType_ANCHORS,
			ZeroConf:           true,
		})
		if err == nil || err.Error() != "Synchronizing blockchain" {
			break
		}
		if time.Now().After(deadline) {
			err = fmt.Errorf("open timeout")
			break
		}
		log.Warnf("client.OpenChannelSync(%x, %v) error: %v", destination, capacitySat, err)
		time.Sleep(1 * time.Second)
	}
	if err != nil {
		logAlarmNotify("client.OpenChannelSync(%x, %v) error: %v", destination, capacitySat, err)
		return nil, err
	}
	txid, _ := chainhash.NewHash(channelPoint.GetFundingTxidBytes())
	if txid != nil {
		logNotify("client.OpenChannelSync(%x): channelPoint=%s:%d, capacity=%d", destination, txid.String(), channelPoint.OutputIndex, capacitySat)
	}
	return channelPoint, err
}

func getChannel(ctx context.Context, client lnrpc.LightningClient, node []byte, channelPoint string) uint64 {
	r, err := client.ListChannels(ctx, &lnrpc.ListChannelsRequest{Peer: node})
	if err != nil {
		logAlarmNotify("client.ListChannels(%x) error: %v", node, err)
		return 0
	}
	for _, c := range r.Channels {
		if c.ChannelPoint == channelPoint && c.Active {
			return c.ChanId
		}
	}
	log.Tracef("No channel found: getChannel(%x)", node)
	return 0
}

func waitChannelCreation(
	ctx context.Context,
	destination []byte,
	channelPoint string,
) (uint64, error) {
	deadline := time.Now().Add(openCheckTimeout)
	var chanID uint64
	fmt.Printf("wait channelPoint=%v\n", channelPoint)
	for {
		chanID = getChannel(ctx, client, destination, channelPoint)
		if chanID != 0 {
			break
		}
		if time.Now().After(deadline) {
			return 0, fmt.Errorf("timeout")
		}
		time.Sleep(1 * time.Second)
	}
	return chanID, nil
}

func getNodeChannels(nodeID string) ([]*lnrpc.Channel, error) {
	clientCtx := metadata.AppendToOutgoingContext(context.Background(), "macaroon", os.Getenv("LND_MACAROON_HEX"))
	listResponse, err := client.ListChannels(clientCtx, &lnrpc.ListChannelsRequest{})
	if err != nil {
		logAlarmNotify("client.ListChannels(%s) error: %v", nodeID, err)
		return nil, err
	}
	var nodeChannels []*lnrpc.Channel
	for _, channel := range listResponse.Channels {
		if channel.RemotePubkey == nodeID {
			nodeChannels = append(nodeChannels, channel)
		}
	}
	return nodeChannels, nil
}

func getPendingNodeChannels(nodeID string) ([]*lnrpc.PendingChannelsResponse_PendingOpenChannel, error) {
	clientCtx := metadata.AppendToOutgoingContext(context.Background(), "macaroon", os.Getenv("LND_MACAROON_HEX"))
	pendingResponse, err := client.PendingChannels(clientCtx, &lnrpc.PendingChannelsRequest{})
	if err != nil {
		return nil, err
	}
	var pendingChannels []*lnrpc.PendingChannelsResponse_PendingOpenChannel
	for _, p := range pendingResponse.PendingOpenChannels {
		if p.Channel.RemoteNodePub == nodeID {
			pendingChannels = append(pendingChannels, p)
		}
	}
	return pendingChannels, nil
}

func queryRoutes(ctx context.Context, client lnrpc.LightningClient, destination string, amountMsat int64) bool {
	response, err := client.QueryRoutes(ctx, &lnrpc.QueryRoutesRequest{
		PubKey: destination,
		Amt:    amountMsat / 1000,
	})
	if err != nil {
		log.Tracef("queryRoutes() err: %v(dest=%s msat=%d)", err, destination, amountMsat)
		return false
	}
	return len(response.Routes) > 0
}

func getRemoteTotalBalance(ctx context.Context, client lnrpc.LightningClient, destination []byte) (int64, int64, error) {
	channels, err := client.ListChannels(ctx, &lnrpc.ListChannelsRequest{
		Peer:       destination,
		ActiveOnly: true,
	})
	if err != nil {
		return 0, 0, logAlarmNotify("ListChannels error: %v", err)
	}
	totalRemote := int64(0)
	totalCapacity := int64(0)
	for _, v := range channels.Channels {
		totalRemote += v.RemoteBalance
		totalCapacity += v.Capacity
	}
	return totalRemote, totalCapacity, nil
}

func getUtxos(ctx context.Context, client lnrpc.LightningClient) (int64, error) {
	utxos, err := client.ListUnspent(ctx, &lnrpc.ListUnspentRequest{
		MinConfs: 1,
		MaxConfs: math.MaxInt32,
	})
	if err != nil {
		return 0, err
	}
	return int64(len(utxos.Utxos)), nil
}

func sendableMax(ctx context.Context, client lnrpc.LightningClient, destination []byte) (int64, error) {
	const marginRate int64 = 50

	channels, err := client.ListChannels(ctx, &lnrpc.ListChannelsRequest{
		Peer:       destination,
		ActiveOnly: true,
	})
	if err != nil {
		return 0, logAlarmNotify("sendableMax: ListChannels error: %v", err)
	}

	var maxSendable int64
	for _, v := range channels.Channels {
		// LocalBalance = Capacity - RemoteBalance - CommitFee - Anchorx2
		// Sendable = LocalBalance - ChanReserveSat - margin
		//
		// The sendable amount should have a margin to allow for possible
		// changes due to BOLT "update_fee" message.
		//
		// NOTE: should use bandwidth?
		margin := int64(v.CommitFee * marginRate / 100)
		sendable := v.LocalBalance - int64(v.LocalConstraints.ChanReserveSat) - margin
		if maxSendable < sendable {
			maxSendable = sendable
		}
	}
	return maxSendable, nil
}

func cancelForwarding(
	ctx context.Context,
	interceptorClient routerrpc.Router_HtlcInterceptorClient,
	incomingCircuitKey *routerrpc.CircuitKey,
	message string,
) {
	interceptorClient.Send(&routerrpc.ForwardHtlcInterceptResponse{
		IncomingCircuitKey: incomingCircuitKey,
		Action:             routerrpc.ResolveHoldForwardAction_FAIL,
	})
	logAlarmNotify(message)
}

func intercept() {
	for {
		cancellableCtx, cancel := context.WithCancel(context.Background())
		clientCtx := metadata.AppendToOutgoingContext(cancellableCtx, "macaroon", os.Getenv("LND_MACAROON_HEX"))
		interceptorClient, err := routerClient.HtlcInterceptor(clientCtx)
		if err != nil {
			logAlarmNotify("routerClient.HtlcInterceptor(): %v", err)
			cancel()
			time.Sleep(1 * time.Second)
			continue
		}

		for {
			request, err := interceptorClient.Recv()
			if err != nil {
				// If it is  just the error result of the context cancellation
				// the we exit silently.
				status, ok := status.FromError(err)
				if ok && status.Code() == codes.Canceled {
					break
				}
				// Otherwise it an unexpected error, we fail the test.
				logAlarmNotify("unexpected error in interceptor.Recv() %v", err)
				cancel()
				break
			}
			// fmt.Printf("htlc: %v\nchanID: %v\nincoming amount: %v\noutgoing amount: %v\nincomin expiry: %v\noutgoing expiry: %v\npaymentHash: %x\nonionBlob: %x\n\n",
			// 	request.IncomingCircuitKey.HtlcId,
			// 	request.IncomingCircuitKey.ChanId,
			// 	request.IncomingAmountMsat,
			// 	request.OutgoingAmountMsat,
			// 	request.IncomingExpiry,
			// 	request.OutgoingExpiry,
			// 	request.PaymentHash,
			// 	request.OnionBlob,
			// )

			result := interceptOnTheFly(clientCtx, interceptorClient, request)
			if result == interceptDone {
				continue
			}

			// normal payment
			log.Trace("normal payment")
			interceptorClient.Send(&routerrpc.ForwardHtlcInterceptResponse{
				IncomingCircuitKey:      request.IncomingCircuitKey,
				Action:                  routerrpc.ResolveHoldForwardAction_RESUME,
				OutgoingAmountMsat:      request.OutgoingAmountMsat,
				OutgoingRequestedChanId: request.OutgoingRequestedChanId,
				OnionBlob:               request.OnionBlob,
			})
		}
	}
}

func interceptOnTheFly(
	ctx context.Context,
	interceptorClient routerrpc.Router_HtlcInterceptorClient,
	request *routerrpc.ForwardHtlcInterceptRequest,
) InterceptResult {
	log.Tracef("interceptOnTheFly: start")
	paymentHash, paymentSecret, destination, incomingAmountMsat, outgoingAmountMsat, fundingTxID, fundingTxOutnum, err := paymentInfo(request.PaymentHash)
	if err != nil {
		log.Debugf("paymentInfo(%x) error: %v", request.PaymentHash, err)
		return interceptNone
	}
	if paymentHash == nil {
		log.Tracef("interceptOnTheFly(%x): No on-the-fly payment hash", request.PaymentHash)
		return interceptNone
	}
	if incomingAmountMsat > int64(request.IncomingAmountMsat) {
		msg := fmt.Sprintf("intercept(%x): incomingAmountMsat(%v) > int64(request.IncomingAmountMsat(%v)", paymentHash, incomingAmountMsat, request.IncomingAmountMsat)
		cancelForwarding(ctx, interceptorClient, request.IncomingCircuitKey, msg)
		return interceptDone
	}

	// 'request.IncomingAmountMsat' contains forwarding fee.
	log.Debugf("intercept(%x): paymentSecret=%x, destination=%x, incomingAmountMsat=%v, outgoingAmountMsat=%v, request.incomingAmountMsat=%v, request.outgoingAmountMsat=%v",
		paymentHash, paymentSecret, destination, incomingAmountMsat, outgoingAmountMsat, request.IncomingAmountMsat, request.OutgoingAmountMsat)
	if fundingTxID == nil {
		if bytes.Equal(paymentHash, request.PaymentHash) {
			totalRemote, totalCapacity, nil := getRemoteTotalBalance(ctx, client, destination)
			if err != nil {
				msg := fmt.Sprintf("interceptOnTheFly(%x): fail getRemoteTotalBalance: %v", paymentHash, err)
				cancelForwarding(ctx, interceptorClient, request.IncomingCircuitKey, msg)
				return interceptDone
			}
			if totalCapacity > maxChannelCapacity {
				// 既にキャパシティ上限を超えていたら処理を中断する
				msg := fmt.Sprintf("interceptOnTheFly: over capacity limit: %v > %v", totalCapacity, maxChannelCapacity)
				cancelForwarding(ctx, interceptorClient, request.IncomingCircuitKey, msg)
				return interceptDone
			}
			fundingAmountMsat := totalRemote*1000 + incomingAmountMsat
			if fundingAmountMsat/1000 > maxChannelCapacity {
				msg := fmt.Sprintf("interceptOnTheFly: funding amount(%v) exceeds MAX_CHANNEL_CAPACITY(%v)", fundingAmountMsat/1000, maxChannelCapacity)
				cancelForwarding(ctx, interceptorClient, request.IncomingCircuitKey, msg)
				return interceptDone
			}
			if queryRoutes(ctx, client, hex.EncodeToString(destination), outgoingAmountMsat) {
				// 送金可能なルートがある場合はチャネルをオープンせずエラーにする
				sendableSat, err := sendableMax(ctx, client, destination)
				if err != nil {
					msg := fmt.Sprintf("interceptOnTheFly(%x): channel balance err: %v", paymentHash, err)
					cancelForwarding(ctx, interceptorClient, request.IncomingCircuitKey, msg)
					return interceptDone
				}
				log.Debugf("sendableMax=%v", sendableSat)
				feeSat := calcMinFeeMsat(incomingAmountMsat) / 1000
				if sendableSat > outgoingAmountMsat/1000+feeSat {
					msg := fmt.Sprintf("interceptOnTheFly(%x): already have payment channel(feeSat=%v, sendableSat=%v, outgoingMsat=%v)", paymentHash, feeSat, sendableSat, outgoingAmountMsat)
					cancelForwarding(ctx, interceptorClient, request.IncomingCircuitKey, msg)
					return interceptDone
				}
				// ルートはあるが NC2 で receiveMax を下回っているので on-the-fly する
			}
			logNotify("interceptOnTheFly(%x): remoteMsat=%v, inAmountMsat=%v", paymentHash, totalRemote*1000, incomingAmountMsat)
			fundingTxID, fundingTxOutnum, err = openChannel(ctx, client, request.PaymentHash, destination, fundingAmountMsat)
			if err != nil {
				msg := fmt.Sprintf("interceptOnTheFly(%x): fail open channel: %v", paymentHash, err)
				cancelForwarding(ctx, interceptorClient, request.IncomingCircuitKey, msg)
				return interceptDone
			}
		} else { //probing
			msg := fmt.Sprintf("interceptOnTheFly(%x): fail payment hash", paymentHash)
			cancelForwarding(ctx, interceptorClient, request.IncomingCircuitKey, msg)
			return interceptDone
		}
	}

	pubKey, err := btcec.ParsePubKey(destination)
	if err != nil {
		msg := fmt.Sprintf("btcec.ParsePubKey(): %v", err)
		cancelForwarding(ctx, interceptorClient, request.IncomingCircuitKey, msg)
		return interceptDone
	}
	sessionKey, err := btcec.NewPrivateKey()
	if err != nil {
		msg := fmt.Sprintf("btcec.NewPrivateKey(): %v", err)
		cancelForwarding(ctx, interceptorClient, request.IncomingCircuitKey, msg)
		return interceptDone
	}

	var bigProd, bigAmt big.Int
	amt := (bigAmt.Div(bigProd.Mul(big.NewInt(outgoingAmountMsat), big.NewInt(int64(request.OutgoingAmountMsat))), big.NewInt(incomingAmountMsat))).Int64()

	var addr [32]byte
	copy(addr[:], paymentSecret)
	hop := route.Hop{
		AmtToForward:     lnwire.MilliSatoshi(amt),
		OutgoingTimeLock: request.OutgoingExpiry,
		MPP:              record.NewMPP(lnwire.MilliSatoshi(outgoingAmountMsat), addr),
		CustomRecords:    make(record.CustomSet),
	}

	var b bytes.Buffer
	err = hop.PackHopPayload(&b, uint64(0))
	if err != nil {
		msg := fmt.Sprintf("hop.PackHopPayload(): %v", err)
		cancelForwarding(ctx, interceptorClient, request.IncomingCircuitKey, msg)
		return interceptDone
	}
	payload, err := sphinx.NewHopPayload(nil, b.Bytes())
	if err != nil {
		msg := fmt.Sprintf("sphinx.NewHopPayload(): %v", err)
		cancelForwarding(ctx, interceptorClient, request.IncomingCircuitKey, msg)
		return interceptDone
	}
	var sphinxPath sphinx.PaymentPath
	sphinxPath[0] = sphinx.OnionHop{
		NodePub:    *pubKey,
		HopPayload: payload,
	}
	sphinxPacket, err := sphinx.NewOnionPacket(
		&sphinxPath, sessionKey, request.PaymentHash,
		sphinx.DeterministicPacketFiller,
	)
	if err != nil {
		msg := fmt.Sprintf("sphinx.NewOnionPacket(): %v", err)
		cancelForwarding(ctx, interceptorClient, request.IncomingCircuitKey, msg)
		return interceptDone
	}
	var onionBlob bytes.Buffer
	err = sphinxPacket.Encode(&onionBlob)
	if err != nil {
		msg := fmt.Sprintf("sphinxPacket.Encode(): %v", err)
		cancelForwarding(ctx, interceptorClient, request.IncomingCircuitKey, msg)
		return interceptDone
	}
	var h chainhash.Hash
	err = h.SetBytes(fundingTxID)
	if err != nil {
		msg := fmt.Sprintf("h.SetBytes(%x) error: %v", fundingTxID, err)
		cancelForwarding(ctx, interceptorClient, request.IncomingCircuitKey, msg)
		return interceptDone
	}
	channelPoint := wire.NewOutPoint(&h, fundingTxOutnum).String()
	go onTheFlyExecute(
		ctx, interceptorClient, request.IncomingCircuitKey, destination,
		channelPoint, uint64(amt), onionBlob.Bytes(), paymentHash,
	)
	log.Tracef("interceptOnTheFly: end")
	return interceptDone
}

func onTheFlyExecute(
	ctx context.Context,
	interceptorClient routerrpc.Router_HtlcInterceptorClient,
	incomingCircuitKey *routerrpc.CircuitKey,
	destination []byte,
	channelPoint string,
	outgoingAmountMsat uint64,
	onionBlob []byte,
	paymentHash []byte,
) {
	log.Tracef("onTheFlyExecute(%x): start", paymentHash)
	chanID, err := waitChannelCreation(ctx, destination, channelPoint)
	if err != nil {
		msg := fmt.Sprintf("onTheFlyExecute(%x): fail On-The-Fly (3)", paymentHash)
		cancelForwarding(ctx, interceptorClient, incomingCircuitKey, msg)
		return
	}

	time.Sleep(1 * time.Second)
	interceptorClient.Send(&routerrpc.ForwardHtlcInterceptResponse{
		IncomingCircuitKey:      incomingCircuitKey,
		Action:                  routerrpc.ResolveHoldForwardAction_RESUME,
		OutgoingAmountMsat:      outgoingAmountMsat,
		OutgoingRequestedChanId: chanID,
		OnionBlob:               onionBlob,
	})
	err = insertChannel(chanID, channelPoint, destination, time.Now(), dbOpenChanReasonOnTheFly)
	if err != nil {
		logAlarmNotify("onTheFlyExecute(%x): insertChannel error: %v", paymentHash, err)
	}
	logNotify("onTheFlyExecute(%x): done(chan_id=`%d`)", paymentHash, chanID)
}
