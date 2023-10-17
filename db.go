package main

import (
	"context"
	"fmt"
	"os"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/jackc/pgtype"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
)

type dbSubmarineStat int32

const (
	// dbOpenChanReasonSync: detect channel on periodic checks
	dbOpenChanReasonSync = "sync"
	// dbOpenChanReasonOnTheFly: on-the-fly channel creation
	dbOpenChanReasonOnTheFly = "onthefly"
	// dbOpenChanReasonSubmarine: submarine swap
	dbOpenChanReasonSubmarine = "submarine"
	// dbOpenChanReasonOpenChan: gRPC OpenChannel API
	dbOpenChanReasonOpenChan = "openchan"
)

const (
	dbSubmarineStatNone dbSubmarineStat = iota
	dbSubmarineStatReg
	dbSubmarineStatOpen
	dbSubmarineStatPay
	dbSubmarineStatDone
	dbSubmarineStatCancel
)

type dbSubmarineType struct {
	HtlcKey       []byte
	RemoteNode    []byte
	Script        []byte
	ScriptAddress string
	Invoice       string
	InTxid        []byte
	InIndex       int32
	InAmount      int64
	OutTxid       []byte
	Status        dbSubmarineStat
	Height        int32
	ScriptVersion int32
}

type dbIntegrityType struct {
	NodeID     []byte
	Id         string
	CreatedAt  time.Time
	Nonce      string
	ExecutedAt time.Time
	Result     bool
}

var (
	pgxPool *pgxpool.Pool
)

func pgConnect() error {
	var err error
	pgxPool, err = pgxpool.Connect(context.Background(), os.Getenv("DATABASE_URL"))
	if err != nil {
		return fmt.Errorf("pgxpool.Connect(%v): %w", os.Getenv("DATABASE_URL"), err)
	}
	return nil
}

func paymentInfo(htlcPaymentHash []byte) (
	paymentHash []byte,
	paymentSecret []byte,
	destination []byte,
	incomingAmountMsat int64,
	outgoingAmountMsat int64,
	fundingTxID []byte,
	fundingTxOutnum uint32,
	err error) {

	var txOutnum pgtype.Int4

	err = pgxPool.QueryRow(context.Background(),
		`SELECT payment_hash, payment_secret, destination, incoming_amount_msat, outgoing_amount_msat, funding_tx_id, funding_tx_outnum
			FROM payments
			WHERE payment_hash=$1 OR sha256('probing-01:' || payment_hash)=$1`,
		htlcPaymentHash).Scan(&paymentHash, &paymentSecret, &destination, &incomingAmountMsat, &outgoingAmountMsat, &fundingTxID, &txOutnum)
	if err != nil {
		if err == pgx.ErrNoRows {
			err = nil
		}
		return nil, nil, nil, 0, 0, nil, 0, err
	}
	fundingTxOutnum = uint32(txOutnum.Int)
	return
}

func setFundingTx(paymentHash, fundingTxID []byte, fundingTxOutnum int) error {
	commandTag, err := pgxPool.Exec(context.Background(),
		`UPDATE payments
			SET funding_tx_id = $2, funding_tx_outnum = $3
			WHERE payment_hash=$1`,
		paymentHash, fundingTxID, fundingTxOutnum)
	log.Tracef("setFundingTx(%x): fundingTxID(rev)=%x: %s err: %v", paymentHash, fundingTxID, commandTag, err)
	return err
}

func registerPayment(destination, paymentHash, paymentSecret []byte, incomingAmountMsat, outgoingAmountMsat int64) error {
	commandTag, err := pgxPool.Exec(context.Background(),
		`INSERT INTO
		payments (destination, payment_hash, payment_secret, incoming_amount_msat, outgoing_amount_msat)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT DO NOTHING`,
		destination, paymentHash, paymentSecret, incomingAmountMsat, outgoingAmountMsat)
	log.Tracef("registerPayment(%x, %x, %x, %v, %v) rows: %v err: %v",
		destination, paymentHash, paymentSecret, incomingAmountMsat, outgoingAmountMsat, commandTag.RowsAffected(), err)
	if err != nil {
		return fmt.Errorf("registerPayment(%x, %x, %x, %v, %v) error: %w",
			destination, paymentHash, paymentSecret, incomingAmountMsat, outgoingAmountMsat, err)
	}
	return nil
}

func insertChannel(chanID uint64, channelPoint string, nodeID []byte, lastUpdate time.Time, reason string) error {
	_, err := pgxPool.Exec(context.Background(),
		`INSERT INTO
	channels (chanid, channel_point, nodeid, last_update, reason)
	VALUES ($1, $2, $3, $4, $5)
	ON CONFLICT DO NOTHING`,
		chanID, channelPoint, nodeID, lastUpdate, reason)
	if err != nil {
		return fmt.Errorf("insertChannel(%v, %s, %x) error: %w",
			chanID, channelPoint, nodeID, err)
	}
	return nil
}

func openedChannel(nodeID []byte, reason string) (int64, error) {
	var count int64
	err := pgxPool.QueryRow(context.Background(),
		`SELECT count(*) FROM channels WHERE nodeid=$1 AND reason=$2`, nodeID, reason).Scan(&count)
	if err != nil {
		return 0, err
	}
	log.Debugf("openedChannel: count=%v", count)
	return count, nil
}

func latestChannel(nodeID []byte) (uint64, *time.Time, error) {
	var chanID uint64
	var lastUpdate time.Time
	err := pgxPool.QueryRow(context.Background(),
		`SELECT chanid, last_update FROM channels ORDER BY last_update DESC LIMIT 1`).Scan(&chanID, &lastUpdate)
	if err != nil {
		return 0, nil, err
	}
	return chanID, &lastUpdate, nil
}

func lastForwardingEvent() (int64, error) {
	var last int64
	err := pgxPool.QueryRow(context.Background(),
		`SELECT coalesce(MAX("timestamp"), 0) AS last FROM forwarding_history`).Scan(&last)
	if err != nil {
		return 0, err
	}
	return last, nil
}

func insertForwardingEvents(rowSrc pgx.CopyFromSource) error {

	tx, err := pgxPool.Begin(context.Background())
	if err != nil {
		return fmt.Errorf("pgxPool.Begin() error: %w", err)
	}
	defer tx.Rollback(context.Background())

	_, err = tx.Exec(context.Background(), `
	CREATE TEMP TABLE tmp_table ON COMMIT DROP AS
		SELECT *
		FROM forwarding_history
		WITH NO DATA;
	`)
	if err != nil {
		return fmt.Errorf("CREATE TEMP TABLE error: %w", err)
	}

	_, err = tx.CopyFrom(context.Background(),
		pgx.Identifier{"tmp_table"},
		[]string{"timestamp", "chanid_in", "chanid_out", "amt_msat_in", "amt_msat_out"}, rowSrc)
	if err != nil {
		return fmt.Errorf("CopyFrom() error: %w", err)
	}
	// log.Tracef("count1: %v", count)

	_, err = tx.Exec(context.Background(), `
	INSERT INTO forwarding_history
		SELECT *
		FROM tmp_table
	ON CONFLICT DO NOTHING
	`)
	if err != nil {
		return fmt.Errorf("INSERT INTO forwarding_history error: %w", err)
	}
	// log.Tracef("count2: %v", cmdTag.RowsAffected())
	return tx.Commit(context.Background())
}

func dbGetSubmarine(paymentHash []byte) (*dbSubmarineType, error) {
	var st = &dbSubmarineType{}
	err := pgxPool.QueryRow(context.Background(),
		`SELECT htlc_key, remote_node, script, script_address, invoice, in_txid, in_index, in_amount, out_txid, status, height, script_version
			FROM submarines
			WHERE payment_hash=$1`,
		paymentHash).Scan(&st.HtlcKey, &st.RemoteNode, &st.Script, &st.ScriptAddress, &st.Invoice, &st.InTxid, &st.InIndex, &st.InAmount, &st.OutTxid, &st.Status, &st.Height, &st.ScriptVersion)
	return st, err
}

func dbGetPaymentHashSubmerine(status dbSubmarineStat) ([][]byte, error) {
	var sql string
	if status != dbSubmarineStatNone {
		sql = fmt.Sprintf("SELECT payment_hash FROM submarines WHERE status=%d", status)
	} else {
		sql = "SELECT payment_hash FROM submarines"
	}
	rows, err := pgxPool.Query(context.Background(), sql)
	if err != nil {
		if err == pgx.ErrNoRows {
			err = nil
		}
		return nil, err
	}
	defer rows.Close()

	var result [][]byte
	for rows.Next() {
		var paymentHash []byte
		err = rows.Scan(&paymentHash)
		if err != nil {
			break
		}
		// log.Tracef("dbGetPaymentHashSubmerine: %x", paymentHash)
		result = append(result, paymentHash)
	}
	return result, nil
}

// status: null => REG
func dbRegisterAddrSubmarine(paymentHash, htlcKey, remoteNode, script []byte, scriptAddress string, height int32, scriptVersion int32) error {
	commandTag, err := pgxPool.Exec(context.Background(),
		`INSERT INTO
		submarines (payment_hash, htlc_key, remote_node, script, script_address, height, script_version, status)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT DO NOTHING`,
		paymentHash, htlcKey, remoteNode, script, scriptAddress, height, scriptVersion, dbSubmarineStatReg)
	log.Tracef("registerAddrSubmarine(%x): remoteNode=%x, scriptAddress=%s: rows: %v err: %v",
		paymentHash, remoteNode, scriptAddress, commandTag.RowsAffected(), err)
	if err != nil {
		return fmt.Errorf("registerAddrSubmarine(%x, %x, %x, %v) error: %w",
			paymentHash, remoteNode, script, scriptAddress, err)
	}
	return nil
}

// status: CANCEL以外
func dbDetectTxidSubmarine(paymentHash []byte, inTxid []byte, inIndex int32, inAmount int64, height uint32) error {
	commandTag, err := pgxPool.Exec(context.Background(),
		`UPDATE submarines
			SET in_txid = $2, in_index = $3, in_amount = $4, height = $5
			WHERE payment_hash=$1 AND in_txid IS NULL AND status!=$6`,
		paymentHash, inTxid, inIndex, inAmount, height, dbSubmarineStatCancel)
	log.Tracef("detectTxidSubmarine(%x) inTxid=%x: %s err: %v", paymentHash, inTxid, commandTag, err)
	return err
}

// status: CANCEL以外
func dbInvoiceSubmarine(paymentHash []byte, invoice string) error {
	commandTag, err := pgxPool.Exec(context.Background(),
		`UPDATE submarines
			SET invoice = $2
			WHERE payment_hash=$1 AND length(invoice)=0 AND status!=$3`,
		paymentHash, invoice, dbSubmarineStatCancel)
	log.Tracef("dbInvoiceSubmarine(%x): invoice=%s: %s err: %v", paymentHash, invoice, commandTag, err)
	return err
}

func dbCheckOpenSubmarine(paymentHash []byte) (bool, error) {
	var (
		invoice string
		in_txid []byte
		status  dbSubmarineStat
	)
	err := pgxPool.QueryRow(context.Background(),
		`SELECT invoice, in_txid, status
			FROM submarines
			WHERE payment_hash=$1`,
		paymentHash).Scan(&invoice, &in_txid, &status)
	if err != nil {
		return false, err
	}
	return len(invoice) > 0 && len(in_txid) > 0 && (status == dbSubmarineStatReg), nil
}

// status: null => REG => OPEN
func dbOpenSubmarine(paymentHash []byte) error {
	commandTag, err := pgxPool.Exec(context.Background(),
		`UPDATE submarines
			SET status = $2
			WHERE payment_hash=$1 AND status=$3`,
		paymentHash, dbSubmarineStatOpen, dbSubmarineStatReg)
	log.Tracef("dbOpenSubmarine(%x): %s err: %v", paymentHash, commandTag, err)
	return err
}

// status: null => REG => OPEN => PAY
func dbPaySubmarine(paymentHash []byte) error {
	commandTag, err := pgxPool.Exec(context.Background(),
		`UPDATE submarines
			SET status = $2
			WHERE payment_hash=$1 AND status=$3`,
		paymentHash, dbSubmarineStatPay, dbSubmarineStatOpen)
	log.Tracef("dbPaySubmarine(%x): %s err: %v", paymentHash, commandTag, err)
	return err
}

// status: null => REG => OPEN => PAY => DONE
func dbDoneSubmarine(paymentHash []byte, txid []byte) error {
	commandTag, err := pgxPool.Exec(context.Background(),
		`UPDATE submarines
			SET out_txid = $2, status = $3
			WHERE payment_hash=$1 AND status=$4`,
		paymentHash, txid, dbSubmarineStatDone, dbSubmarineStatPay)
	log.Tracef("dbDoneSubmarine(%x): txid(rev)=%x: %s err: %v", paymentHash, txid, commandTag, err)
	return err
}

// status: => CANCEL
func dbCancelSubmarine(paymentHash []byte) error {
	commandTag, err := pgxPool.Exec(context.Background(),
		`UPDATE submarines
			SET status = $2
			WHERE payment_hash=$1`,
		paymentHash, dbSubmarineStatCancel)
	log.Tracef("dbCancelSubmarine(%x): %s err: %v", paymentHash, commandTag, err)
	return err
}

func dbRegisterUserInfo(mailAddress string) error {
	commandTag, err := pgxPool.Exec(context.Background(),
		`INSERT INTO
		userinfo (mail_address, count)
		VALUES ($1, 1)
		ON CONFLICT (mail_address) DO UPDATE SET count = userinfo.count + 1 WHERE userinfo.mail_address=$1`,
		mailAddress)
	log.Tracef("dbRegisterUserInfo: %s rows: %v err: %v",
		mailAddress, commandTag.RowsAffected(), err)
	if err != nil {
		return fmt.Errorf("dbRegisterUserInfo(%s) error: %w", mailAddress, err)
	}
	return nil
}

func dbInsertNonceIntegrity(nodeID []byte, id string, nonce string, createdAt time.Time) error {
	commandTag, err := pgxPool.Exec(context.Background(),
		`INSERT INTO
		integrity (nodeid, id, nonce_created_at, nonce, integrity_executed_at, integrity_result)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (nodeid) DO UPDATE SET id = $2, nonce_created_at = $3, nonce = $4, integrity_executed_at = $5, integrity_result = $6 WHERE integrity.nodeid=$1`,
		nodeID, id, createdAt, nonce, time.UnixMilli(0), false)
	log.Tracef("dbInsertNonceIntegrity: %x rows: %v err: %v",
		nodeID, commandTag.RowsAffected(), err)
	if err != nil {
		return fmt.Errorf("dbInsertNonceIntegrity(%x) error: %w", nodeID, err)
	}
	return nil
}

func dbUpdateResultIntegrity(nodeID []byte, result bool, executedAt time.Time) error {
	commandTag, err := pgxPool.Exec(context.Background(),
		`UPDATE integrity
			SET integrity_executed_at = $2, integrity_result = $3
			WHERE nodeid=$1`,
		nodeID, executedAt, result)
	log.Tracef("dbUpdateResultIntegrity: %x rows: %v err: %v",
		nodeID, commandTag.RowsAffected(), err)
	if err != nil {
		return fmt.Errorf("dbUpdateResultIntegrity(%x) error: %w", nodeID, err)
	}
	return nil
}

func dbGetIntegrity(nodeID []byte) (*dbIntegrityType, error) {
	var result dbIntegrityType
	err := pgxPool.QueryRow(context.Background(),
		`SELECT id, nonce_created_at, nonce, integrity_executed_at, integrity_result
			FROM integrity
			WHERE nodeid=$1`,
		nodeID).Scan(&result.Id, &result.CreatedAt, &result.Nonce, &result.ExecutedAt, &result.Result)
	if err != nil {
		if err == pgx.ErrNoRows {
			err = nil
		}
		return nil, err
	}
	return &result, nil
}

// // Comment out for future use
// func dbGetIntegrityFromID(id string) (*dbIntegrityType, error) {
// 	var result dbIntegrityType
// 	err := pgxPool.QueryRow(context.Background(),
// 		`SELECT nodeid, nonce_created_at, nonce, integrity_executed_at, integrity_result
// 			FROM integrity
// 			WHERE id=$1`,
// 		id).Scan(&result.NodeID, &result.CreatedAt, &result.Nonce, &result.ExecutedAt, &result.Result)
// 	if err != nil {
// 		if err == pgx.ErrNoRows {
// 			err = nil
// 		}
// 		return nil, err
// 	}
// 	return &result, nil
// }
