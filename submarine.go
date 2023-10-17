package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	lspdrpc "github.com/nayutaco/NayutaHub2LspdProto"
	"google.golang.org/grpc/metadata"
)

const (
	// 最新scriptバージョン
	// 更新時の変更箇所
	//	- csvHeights[]
	//  - newSubmarineScriptTypeA()
	//  - submarineOpenAndPay() - case文
	//	- NayutaCore2Lnd - lspclient/
	swapScriptVersion = 2

	// 許容するscript version下限
	swapScriptVersionAllowMin = 2

	// sat per kiro weight
	feeRateSatPerKw = 300

	paymentRetryMax = 3

	// アプリからのinvoiceに含まれるmin_final_cltv_expiryチェック
	// NC2 で使用する min_final_cltv_expiry
	swapCltvSafety = 40
)

// submarine swap可能期間(block)
var csvHeights = []uint32{
	2,   // version 0
	6,   // version 1
	144, // version 2
}

// Script Type-A
//
//	  OP_SHA256 <sha256(preimage)> OP_EQUAL
//	  OP_IF
//			// SWAP
//	     <htlcPubkey>
//	  OP_ELSE
//			// REFUND
//	     <csvHeight> OP_CSV OP_DROP <repayPubkey>
//	  OP_ENDIF
//	  OP_CHKSIG
func newSubmarineScriptTypeA(csvHeight uint32, hash []byte, htlcPubkey []byte, repayPubkey []byte) []byte {
	const (
		OP_IF     = 0x63
		OP_ELSE   = 0x67
		OP_ENDIF  = 0x68
		OP_DROP   = 0x75
		OP_EQUAL  = 0x87
		OP_SHA256 = 0xa8
		OP_CHKSIG = 0xac
		OP_CSV    = 0xb2
	)

	script := append([]byte{OP_SHA256, 0x20}, hash...)
	script = append(script, OP_EQUAL, OP_IF, 0x21)
	script = append(script, htlcPubkey...)
	script = append(script, OP_ELSE)
	if csvHeight <= 1 {
		log.Errorf("invalid csvHeight=%v", csvHeight)
		return nil
	} else if csvHeight <= 16 {
		script = append(script, 0x50+byte(csvHeight))
	} else if csvHeight <= 0x4b {
		script = append(script, byte(csvHeight))
	} else if csvHeight <= 0x7f {
		script = append(script, 0x01, byte(csvHeight))
	} else if csvHeight <= 0x7fff {
		script = append(script, 0x02, byte(csvHeight&0xff), byte(csvHeight>>8))
	} else {
		log.Errorf("invalid csvHeight=%v", csvHeight)
		return nil
	}
	script = append(script, OP_CSV, OP_DROP, 0x21)
	script = append(script, repayPubkey...)
	script = append(script, OP_ENDIF, OP_CHKSIG)
	return script
}

func transactionSubscribe(ctx context.Context) error {
	res, err := client.SubscribeTransactions(ctx, &lnrpc.GetTransactionsRequest{})
	if err != nil {
		logAlarmNotify("transactionSubscribe - err: %v", err)
		return err
	}
	for {
		var txs *lnrpc.Transaction
		txs, err = res.Recv()
		if err == io.EOF {
			// ToDo どうする？
			logAlarmNotify("transactionSubscribe - EOF")
			break
		}
		if ctx.Err() == context.Canceled {
			logAlarmNotify("transactionSubscribe - err2: %v", err)
			err = ErrSubscTxCancel
			break
		}
		if err != nil {
			logAlarmNotify("transactionSubscribe - err3: %v", err)
			break
		}
		if txs == nil {
			logNotify("transactionSubscribe: no transaction")
			continue
		}
		if txs.NumConfirmations == 0 {
			log.Tracef("transactionSubscribe(txid=%s): confirm = 0", txs.TxHash)
			continue
		}
		if txs.Amount < 0 {
			log.Tracef("transactionSubscribe(txid=%s): amount < 0", txs.TxHash)
			continue
		}

		log.Debugf("transactionSubscribe(txid=%s): tx confirmed", txs.TxHash)
		err = submarineOutpointCheck(ctx, txs)
		if err != nil {
			logAlarmNotify("transactionSubscribe(txid=%s): submarineOutpointCheck: %v", txs.TxHash, err)
			break
		}
	}

	return err
}

// submarineOutpointCheck は transactionの通知によって呼び出される。
// transaction の output が登録されて未処理かつクライアントの要求がある場合は submarine swap を開始する。
// クライアントの要求がまだない場合は情報だけ保持しておき ReceiveSubmarine() で継続する。
func submarineOutpointCheck(ctx context.Context, txs *lnrpc.Transaction) error {
	hashes, err := dbGetPaymentHashSubmerine(dbSubmarineStatReg)
	if err != nil {
		return err
	}
	for _, hash := range hashes {
		sub, err := dbGetSubmarine(hash)
		if err != nil {
			continue
		}
		if sub.InTxid != nil {
			continue
		}
		for i, detail := range txs.OutputDetails {
			v := detail.Address
			if v != sub.ScriptAddress {
				continue
			}
			log.Tracef("submarineOutpointCheck:%s", v)
			txid, _ := hex.DecodeString(txs.TxHash)
			if err = dbDetectTxidSubmarine(hash, txid, int32(i), txs.Amount, uint32(txs.BlockHeight)); err != nil {
				logAlarmNotify("submarineOutpointCheck(%x): fail dbDetectTxidSubmarine: %v", hash, err)
				continue
			}
			chk, err := dbCheckOpenSubmarine(hash)
			if err != nil {
				logAlarmNotify("submarineOutpointCheck(%x): fail dbCheckOpenSubmarine err: %v", hash, err)
				continue
			}
			if !chk {
				log.Debugf("submarineOutpointCheck(%x): invoice yet received.", hash)
				break
			}
			// invoiceとTXID検出が揃った
			resDecode, err := client.DecodePayReq(ctx, &lnrpc.PayReqString{PayReq: sub.Invoice})
			if err != nil {
				logAlarmNotify("submarineOutpointCheck(%x): fail DecodePayReq: %v", hash, err)
				break
			}
			sub.InTxid = txid
			sub.InIndex = int32(i)
			sub.InAmount = txs.Amount
			sub.Height = txs.BlockHeight
			err = submarineProcess(hash, sub, resDecode.NumMsat)
			if err != nil {
				log.Errorf("submarineOutpointCheck(%x): fail submarineProcess: %v", hash, err)
			}
			break
		}
	}
	return nil
}

func registerSubmarine(rs *lspdrpc.RegisterSubmarineRequest) (string, []byte, error) {
	log.Debugf("registerSubmarine(%x): rs.destination=%x, rs.scriptVersion=%d, swapScriptVersion=%v, csvHeights=%v", rs.PaymentHash, rs.Destination, rs.SwapScriptVersion, swapScriptVersion, csvHeights)

	if rs.SwapScriptVersion < swapScriptVersionAllowMin {
		return "", nil, logAlarmNotify("registerSubmarine(%x): unsupport script version(%d)", rs.PaymentHash, rs.SwapScriptVersion)
	}
	if swapScriptVersion < rs.SwapScriptVersion {
		return "", nil, logAlarmNotify("registerSubmarine(%x): incomming version is newer than LSP(%d < %d)", rs.PaymentHash, swapScriptVersion, rs.SwapScriptVersion)
	}

	htlcKey, htlcPubkey := newPrivkey()
	script := newSubmarineScriptTypeA(csvHeights[rs.SwapScriptVersion], rs.PaymentHash, htlcPubkey, rs.RepayPubkey)

	// add to wallet
	clientCtx := metadata.AppendToOutgoingContext(context.Background(), "macaroon", os.Getenv("LND_MACAROON_HEX"))
	info, err := client.GetInfo(clientCtx, &lnrpc.GetInfoRequest{})
	if err != nil {
		return "", nil, err
	}
	scriptAddr, err := addWatchScript(clientCtx, script, info.BlockHash, info.BlockHeight)
	if err != nil {
		return "", nil, err
	}

	err = dbRegisterAddrSubmarine(
		rs.PaymentHash,
		htlcKey,
		rs.Destination,
		script,
		scriptAddr,
		int32(info.BlockHeight),
		rs.SwapScriptVersion,
	)
	if err != nil {
		logAlarmNotify("registerSubmarine(%x): dbRegisterAddrSubmarine() error: %v", rs.PaymentHash, err)
		return "", nil, err
	}
	log.Debugf("registerSubmarine(%x): script=%x, addr=%s, htlcPubkey=%x", rs.PaymentHash, script, scriptAddr, htlcPubkey)
	return scriptAddr, htlcPubkey, nil
}

func submarineProcess(paymentHash []byte, sub *dbSubmarineType, outgoingMsat int64) error {
	log.Tracef("submarineProcess(%x): outgoingMsat=%v", paymentHash, outgoingMsat)
	err := checkPayment(sub.InAmount*1000, outgoingMsat)
	if err != nil {
		// submarineできない
		logAlarmNotify("submarineProcess(%x): cancel: %v", paymentHash, err)
		dbCancelSubmarine(paymentHash)
		return err
	}
	log.Infof("submarineProcess(%x): open and pay", paymentHash)
	go submarineOpenAndPay(paymentHash, sub, outgoingMsat)
	return nil
}

func submarineOpenAndPay(paymentHash []byte, sub *dbSubmarineType, outgoingMsat int64) {
	clientCtx := metadata.AppendToOutgoingContext(context.Background(), "macaroon", os.Getenv("LND_MACAROON_HEX"))

	log.Tracef("submarineOpenAndPay(%x): sub=%v, outgoingMsat=%v", paymentHash, sub, outgoingMsat)
	err := dbOpenSubmarine(paymentHash)
	if err != nil {
		logAlarmNotify("submarineOpenAndPay(%x): dbOpenSubmarine err: %v", paymentHash, err)
		return
	}

	resDecode, err := client.DecodePayReq(clientCtx, &lnrpc.PayReqString{PayReq: sub.Invoice})
	if err != nil {
		logAlarmNotify("invalid invoice: %v", err)
		return
	}

	// open channel
	inAmountMsat := sub.InAmount * 1000
	if !queryRoutes(clientCtx, client, hex.EncodeToString(sub.RemoteNode), outgoingMsat) {
		// create channel if there is no route
		err = submarineOpen(clientCtx, client, paymentHash, sub, inAmountMsat, resDecode.CltvExpiry)
	} else {
		log.Infof("submarineOpenAndPay(%x): there is payment route.", paymentHash)
	}
	if err == nil {
		err = submarineBlockLimitCheck(clientCtx, client, sub.ScriptVersion, sub.Height, resDecode.CltvExpiry)
	}
	if err != nil {
		logAlarmNotify("submarineOpenAndPay(%x): open/not open err: %v", paymentHash, err)
		return
	}

	// pay
	log.Tracef("submarineOpenAndPay(%x): pay...", paymentHash)
	err = dbPaySubmarine(paymentHash)
	if err != nil {
		logAlarmNotify("submarineOpenAndPay(%x): dbPaySubmarine err: %v", paymentHash, err)
		return
	}
	var preimage []byte
	retry := 0
	for retry < paymentRetryMax {
		retry++
		time.Sleep(time.Second * time.Duration(retry))
		resPay, err := client.SendPaymentSync(clientCtx, &lnrpc.SendRequest{
			PaymentRequest: sub.Invoice,
		})
		if err != nil {
			log.Errorf("submarineOpenAndPay(%x): pay err(retry=%d): %v", paymentHash, retry, err)
			continue
		}
		log.Debugf("submarineOpenAndPay(%x): SendPaymentSync result(payment_hash=%x, payment_error=%s)", paymentHash, resPay.PaymentHash, resPay.PaymentError)
		if len(resPay.PaymentError) != 0 {
			log.Errorf("submarineOpenAndPay(%x): API error: %s", paymentHash, resPay.PaymentError)
			continue
		}
		if !bytes.Equal(resPay.PaymentHash, paymentHash) {
			log.Errorf("submarineOpenAndPay(%x): pay PaymentHash not match", paymentHash)
			continue
		}
		if len(resPay.PaymentPreimage) != 32 {
			log.Errorf("submarineOpenAndPay(%x): invalid PaymentPreimage", paymentHash)
			continue
		}
		logNotify("Submarine Swap done: %x", paymentHash)
		preimage = resPay.PaymentPreimage
		break
	}
	if len(preimage) == 0 {
		logAlarmNotify("submarineOpenAndPay(%x): fail payment", paymentHash)
		return
	}
	log.Infof("submarineOpenAndPay(%x): payed: preimage=%x", paymentHash, preimage)

	// redeem script
	label := fmt.Sprintf("submarine-%x", paymentHash)
	var txid []byte
	switch sub.ScriptVersion {
	case 2:
		txid, err = submarineRedeemScriptTypeA(clientCtx, preimage, sub, label)
	default:
		logAlarmNotify("submarineOpenAndPay(%x): invalid script version %v", paymentHash, sub.ScriptVersion)
		return
	}
	if err != nil {
		logAlarmNotify("submarineOpenAndPay(%x): submarineRedeemScript err: %v", paymentHash, err)
		return
	}
	txHash, err := chainhash.NewHash(txid)
	if err != nil {
		logAlarmNotify("submarineOpenAndPay(%x): NewHash(%x) err: %v", paymentHash, txid, err)
		return
	}
	log.Debugf("Submarine Redeemed: %s", txHash.String())
	err = dbDoneSubmarine(paymentHash, txid)
	if err != nil {
		logAlarmNotify("submarineOpenAndPay(%x): dbDoneSubmarine err: %v", paymentHash, err)
		return
	}
	logNotify("submarineOpenAndPay(%x): done", paymentHash)
}

// submarineBlockLimitCheck
//
// |                                  |
// |<--------(OP_CSV value)---------->|
// |                                  |
// |           swap         |  none   | repay
// |<---------------------->|<------->|------->
// |                        |         |
// |    +min_final       -expiry_delta|
// |   |--------->|         |<--------|
// |   |          *         |         |
// |   current              |         |
// |                        |         |
// conf=1
func submarineBlockLimitCheck(ctx context.Context, client lnrpc.LightningClient, scriptVersion int32, height int32, cltvExpiry int64) error {
	// check OP_CSV height
	//
	//	conf = info.BlockHeight - uint32(sub.Height) + 1
	//		conf = [1, csvHeight) : SWAP
	//  	conf = [csvHeight,]   : REDEEM
	//
	//		 ↓↓
	//
	//		conf = [1, csvHeight-safety)         : SWAP
	//  	conf = [csvHeight-safety, csvHeight) : none
	//  	conf = [csvHeight,]                  : REDEEM
	var info *lnrpc.GetInfoResponse
	info, err := client.GetInfo(ctx, &lnrpc.GetInfoRequest{})
	if err != nil {
		return err
	}
	safety := uint32(height) + csvHeights[scriptVersion] - (timeLockDelta + uint32(cltvExpiry))
	if info.BlockHeight > safety {
		return fmt.Errorf("over OP_CSV(%d) limit(%d): current=%d, tx=%d", csvHeights[scriptVersion], safety, info.BlockHeight, height)
	}
	return nil
}

// submarineOpen はチャネルをオープンする。
// キャパシティは inAmountMsat/1000 + remote balance合計 + proportionalCapacity() になるので注意すること。
func submarineOpen(ctx context.Context, client lnrpc.LightningClient, paymentHash []byte, sub *dbSubmarineType, inAmountMsat int64, cltvExpiry int64) error {
	var fundingTxID []byte
	var fundingTxOutnum uint32
	var err error

	retry := 0
	for {
		totalRemote, totalCapacity, nil := getRemoteTotalBalance(ctx, client, sub.RemoteNode)
		if err != nil {
			break
		}
		if totalCapacity > maxChannelCapacity {
			// 既にキャパシティ上限を超えていたら処理を中断する
			break
		}

		fundingAmountMsat := totalRemote*1000 + inAmountMsat
		if fundingAmountMsat/1000 > maxChannelCapacity {
			err = logNotify("funding amount(%v) exceeds MAX_CHANNEL_CAPACITY(%v)", fundingAmountMsat/1000, maxChannelCapacity)
			break
		}

		logNotify("submarineOpen(%x): remoteMsat=%v, inAmountMsat=%v", paymentHash, totalRemote*1000, inAmountMsat)

		// check OP_CSV height
		err = submarineBlockLimitCheck(ctx, client, sub.ScriptVersion, sub.Height, cltvExpiry)
		if err != nil {
			break
		}

		fundingTxID, fundingTxOutnum, err = openChannel(ctx, client, paymentHash, sub.RemoteNode, fundingAmountMsat)
		if err != nil {
			retry++
			logNotify("@channel submarineOpen(%x): fail openChannel(retry=%d) err: %v", paymentHash, retry, err)
			time.Sleep(5 * time.Minute)
			continue
		}
		break
	}
	if err != nil {
		return logAlarmNotify("submarineOpen(%x) err: %v", paymentHash, err)
	}

	var h chainhash.Hash
	err = h.SetBytes(fundingTxID)
	if err != nil {
		return logAlarmNotify("submarineOpen(%x): SetBytes err: %v", paymentHash, err)
	}

	log.Tracef("submarineOpen(%x): open wait...", paymentHash)
	channelPoint := wire.NewOutPoint(&h, fundingTxOutnum).String()
	chanID, err := waitChannelCreation(ctx, sub.RemoteNode, channelPoint)
	if err != nil {
		return logAlarmNotify("submarineOpen(%x): Stop retrying getChannel(%x, %v)", paymentHash, sub.RemoteNode, channelPoint)
	}

	err = insertChannel(chanID, channelPoint, sub.RemoteNode, time.Now(), dbOpenChanReasonSubmarine)
	if err != nil {
		logAlarmNotify("submarineOpen(%x): insertChannel error: %v", paymentHash, err)
	}

	log.Tracef("submarineOpen(%x): opened", paymentHash)
	return nil
}

func submarineRedeemScriptTypeA(
	ctx context.Context,
	preimage []byte,
	sub *dbSubmarineType,
	label string,
) ([]byte, error) {
	// <witness>
	//   1 + 73(max signature)
	//   1 + 32(preimage)
	//   1 + (script length)
	const SZ_WITNESS = 1 + 73 + 1 + 32 + 1

	resAddr, _ := client.NewAddress(ctx, &lnrpc.NewAddressRequest{
		Type: lnrpc.AddressType_WITNESS_PUBKEY_HASH,
	})
	inTxidStr := hex.EncodeToString(sub.InTxid)
	payAddr, _ := btcutil.DecodeAddress(resAddr.Address, network)
	payPkScript, _ := txscript.PayToAddrScript(payAddr)
	txHash, err := redeemWitnessScript(
		ctx,
		preimage,
		sub.HtlcKey,
		sub.Script,
		inTxidStr,
		sub.InIndex,
		sub.InAmount,
		sub.ScriptAddress,
		payPkScript,
		uint32(sub.Height),
		int64(feeRateSatPerKw),
		int64(SZ_WITNESS+len(sub.Script)),
		label,
	)
	if err != nil {
		log.Errorf("redeemWitnessScript: err: %v", err)
		return nil, err
	}
	logNotify("submarineRedeemScriptTypeA: publish txid: %s", txHash.String())

	return txHash[:], nil
}

func redeemWitnessScript(
	ctx context.Context,
	preimage []byte,
	htlcKey []byte,
	script []byte,
	prevTxidStr string,
	prevTxIndex int32,
	prevAmount int64,
	prevAddrStr string,
	pkScript []byte,
	lockTime uint32,
	satPerKw int64,
	szWitness int64,
	label string,
) (*chainhash.Hash, error) {

	feeRateKw := chainfee.SatPerKWeight(satPerKw)
	privateKey, _ := btcec.PrivKeyFromBytes(htlcKey)

	// tx
	//	version: 2
	//	input num: 1
	//	output num: 1
	outTx := wire.NewMsgTx(2)

	// lock time
	outTx.LockTime = lockTime

	// output(no amount)
	txOut := wire.NewTxOut(0, pkScript)
	outTx.AddTxOut(txOut)

	// input
	prevTxid, err := chainhash.NewHashFromStr(prevTxidStr)
	if err != nil {
		return nil, err
	}
	prevOutPoint := wire.NewOutPoint(prevTxid, uint32(prevTxIndex))
	var sig []byte
	var witness [][]byte
	txIn := wire.NewTxIn(prevOutPoint, sig, witness)
	outTx.AddTxIn(txIn)

	prevAddr, err := btcutil.DecodeAddress(prevAddrStr, network)
	if err != nil {
		return nil, err
	}
	prevPkScript, err := txscript.PayToAddrScript(prevAddr)
	if err != nil {
		return nil, err
	}
	prevOutputFetcher := txscript.NewCannedPrevOutputFetcher(prevPkScript, prevAmount)

	// fee
	weight := int64(4*outTx.SerializeSizeStripped()) + szWitness
	fee := feeRateKw.FeeForWeight(weight)
	outTx.TxOut[0].Value = int64(prevAmount - int64(fee))

	// witness
	sigHashes := txscript.NewTxSigHashes(outTx, prevOutputFetcher)
	scriptSig, err := txscript.RawTxInWitnessSignature(outTx, sigHashes, 0, prevAmount, script, txscript.SigHashAll, privateKey)
	if err != nil {
		return nil, err
	}
	outTx.TxIn[0].Witness = [][]byte{scriptSig, preimage, script}

	var buf bytes.Buffer
	err = outTx.Serialize(&buf)
	if err != nil {
		return nil, err
	}
	payres, err := walletKitClient.PublishTransaction(ctx, &walletrpc.Transaction{
		TxHex: buf.Bytes(),
		Label: label,
	})
	if err != nil {
		return nil, err
	}
	if len(payres.PublishError) != 0 {
		return nil, errors.New(payres.PublishError)
	}
	txHash := outTx.TxHash()
	return &txHash, nil
}

func newPrivkey() ([]byte, []byte) {
	p, _ := btcec.NewPrivateKey()
	q := p.PubKey()
	return p.Serialize(), q.SerializeCompressed()
}

func addWatchScript(ctx context.Context, script []byte, blockHashStr string, blockHeight uint32) (string, error) {
	res, err := walletKitClient.ImportWitnessScript(ctx, &walletrpc.ImportWitnessScriptRequest{
		Script:       script,
		BlockHashStr: blockHashStr,
		BlockHeight:  int32(blockHeight),
	})
	if err != nil {
		return "", err
	}
	log.Tracef("addWatchScript: %s", res.Address)
	return res.Address, nil
}
