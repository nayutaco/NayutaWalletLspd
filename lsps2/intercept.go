package lsps2

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"math"
	"time"

	"github.com/breez/lspd/basetypes"
	"github.com/breez/lspd/chain"
	"github.com/breez/lspd/lightning"
)

type InterceptAction int

const (
	INTERCEPT_RESUME              InterceptAction = 0
	INTERCEPT_RESUME_WITH_ONION   InterceptAction = 1
	INTERCEPT_FAIL_HTLC_WITH_CODE InterceptAction = 2
	INTERCEPT_IGNORE              InterceptAction = 3

	// INTERCEPT_CANNOT_HANDLE means the htlc is not registered in a lsps2.buy
	// request. So this interceptor cannot handle it. This state exists to
	// assist bacckward compatibility with the previous htlc interceptor. If the
	// previous htlc interceptor is removed, this can be replaced with
	// INTERCEPT_RESUME.
	INTERCEPT_CANNOT_HANDLE InterceptAction = 4
)

type InterceptFailureCode uint16

var (
	FAILURE_TEMPORARY_CHANNEL_FAILURE InterceptFailureCode = 0x1007
	FAILURE_AMOUNT_BELOW_MINIMUM      InterceptFailureCode = 0x100B
	FAILURE_INCORRECT_CLTV_EXPIRY     InterceptFailureCode = 0x100D
	FAILURE_UNKNOWN_NEXT_PEER         InterceptFailureCode = 0x400A
)

type InterceptorConfig struct {
	AdditionalChannelCapacitySat uint64
	MinConfs                     *uint32
	TargetConf                   uint32
	FeeStrategy                  chain.FeeStrategy
	MinPaymentSizeMsat           uint64
	MaxPaymentSizeMsat           uint64
	TimeLockDelta                uint32
	HtlcMinimumMsat              uint64
	MppTimeout                   time.Duration
}

type Interceptor struct {
	store                    Lsps2Store
	client                   lightning.Client
	feeEstimator             chain.FeeEstimator
	config                   *InterceptorConfig
	newPart                  chan *partState
	partAwaitingRegistration chan *awaitingRegistrationEvent
	registrationReady        chan *registrationReadyEvent
	notRegistered            chan string
	paymentReady             chan string
	paymentTimeout           chan string
	feeParamsTimeout         chan string
	paymentFailure           chan *paymentFailureEvent
	paymentChanOpened        chan *paymentChanOpenedEvent
	inflightPayments         map[string]*paymentState
}

func NewInterceptor(
	store Lsps2Store,
	client lightning.Client,
	feeEstimator chain.FeeEstimator,
	config *InterceptorConfig,
) *Interceptor {
	if config.MppTimeout.Nanoseconds() == 0 {
		config.MppTimeout = time.Duration(90 * time.Second)
	}

	return &Interceptor{
		store:        store,
		client:       client,
		feeEstimator: feeEstimator,
		config:       config,
		// TODO: make sure the chan sizes do not lead to deadlocks.
		newPart:                  make(chan *partState, 1000),
		partAwaitingRegistration: make(chan *awaitingRegistrationEvent, 1000),
		registrationReady:        make(chan *registrationReadyEvent, 1000),
		notRegistered:            make(chan string, 1000),
		paymentReady:             make(chan string, 1000),
		paymentTimeout:           make(chan string, 1000),
		feeParamsTimeout:         make(chan string, 1000),
		paymentFailure:           make(chan *paymentFailureEvent, 1000),
		paymentChanOpened:        make(chan *paymentChanOpenedEvent, 1000),
		inflightPayments:         make(map[string]*paymentState),
	}
}

type InterceptRequest struct {
	// Identifier that uniquely identifies this htlc.
	// For cln, that's hash of the next onion or the shared secret.
	Identifier         string
	Scid               basetypes.ShortChannelID
	PaymentHash        []byte
	IncomingAmountMsat uint64
	OutgoingAmountMsat uint64
	IncomingExpiry     uint32
	OutgoingExpiry     uint32
}

func (r *InterceptRequest) paymentId() string {
	return fmt.Sprintf("%s|%x", r.Scid.ToString(), r.PaymentHash)
}

func (r *InterceptRequest) htlcId() string {
	return r.Identifier
}

type InterceptResult struct {
	Action      InterceptAction
	FailureCode InterceptFailureCode
	AmountMsat  uint64
	FeeMsat     *uint64
	Scid        basetypes.ShortChannelID
}

type paymentState struct {
	id                       string
	fakeScid                 basetypes.ShortChannelID
	incomingSumMsat          uint64
	outgoingSumMsat          uint64
	paymentSizeMsat          uint64
	feeMsat                  uint64
	registration             *BuyRegistration
	parts                    map[string]*partState
	isFinal                  bool
	timoutChanClosed         bool
	timeoutChan              chan struct{}
	isRunningTimeoutListener bool
}

func (p *paymentState) closeTimeoutChan() {
	if p.timoutChanClosed {
		return
	}

	close(p.timeoutChan)
	p.timoutChanClosed = true
}

type partState struct {
	isProcessed bool
	isFinalized bool
	req         *InterceptRequest
	resolution  chan *InterceptResult
}

type registrationReadyEvent struct {
	paymentId    string
	registration *BuyRegistration
}

type paymentChanOpenedEvent struct {
	paymentId       string
	scid            basetypes.ShortChannelID
	htlcMinimumMsat uint64
}

type paymentFailureEvent struct {
	paymentId string
	code      InterceptFailureCode
}

type awaitingRegistrationEvent struct {
	paymentId string
	partId    string
}

func (i *Interceptor) Start(ctx context.Context) {
	// Main event loop for stages of htlcs to be handled. Note that the event
	// loop has to execute quickly, so any code running in the 'handle' methods
	// must execute quickly. If there is i/o involved, or any waiting, run that
	// code in a goroutine, and place an event onto the event loop to continue
	// processing after the slow operation is done.
	// The nice thing about an event loop is that it runs on a single thread.
	// So there's no locking needed, as long as everything that needs
	// synchronization goes through the event loop.
	for {
		select {
		case part := <-i.newPart:
			i.handleNewPart(part)
		case ev := <-i.registrationReady:
			i.handleRegistrationReady(ev)
		case paymentId := <-i.notRegistered:
			i.handleNotRegistered(paymentId)
		case ev := <-i.partAwaitingRegistration:
			i.handlePartAwaitingRegistration(ev)
		case paymentId := <-i.paymentReady:
			i.handlePaymentReady(paymentId)
		case paymentId := <-i.paymentTimeout:
			i.handlePaymentTimeout(paymentId)
		case paymentId := <-i.feeParamsTimeout:
			i.handleFeeParamsTimeout(paymentId)
		case ev := <-i.paymentFailure:
			i.handlePaymentFailure(ev.paymentId, ev.code)
		case ev := <-i.paymentChanOpened:
			i.handlePaymentChanOpened(ev)
		}
	}
}

func (i *Interceptor) handleNewPart(part *partState) {
	payment, paymentExisted := i.inflightPayments[part.req.paymentId()]
	if !paymentExisted {
		payment = &paymentState{
			id:          part.req.paymentId(),
			fakeScid:    part.req.Scid,
			parts:       make(map[string]*partState),
			timeoutChan: make(chan struct{}),
		}
		i.inflightPayments[part.req.paymentId()] = payment

		go func() {
			select {
			case <-time.After(i.config.MppTimeout):
				// Handle timeout inside the event loop, to make sure there are
				// no race conditions, since this timeout watcher is running in
				// a goroutine.
				i.paymentTimeout <- part.req.paymentId()
			case <-payment.timeoutChan:
				// Stop listening for timeouts when the payment is ready.
			}
		}()

		// Fetch the buy registration in a goroutine, to avoid blocking the
		// event loop.
		go i.fetchRegistration(part.req.paymentId(), part.req.Scid)
	}

	// Check whether we already have this part, because it may have been
	// replayed.
	existingPart, partExisted := payment.parts[part.req.htlcId()]
	// Adds the part to the in-progress parts. Or replaces it, if it already
	// exists, to make sure we always reply to the correct identifier. If a htlc
	// was replayed, assume the latest event is the truth to respond to.
	payment.parts[part.req.htlcId()] = part

	if partExisted {
		// If the part already existed, that means it has been replayed. In this
		// case the first occurence can be safely ignored, because we won't be
		// able to reply to that htlc anyway. Keep the last replayed version for
		// further processing. This result below tells the caller to ignore the
		// htlc.
		if !existingPart.isFinalized {
			existingPart.isFinalized = true
			existingPart.resolution <- &InterceptResult{
				Action: INTERCEPT_IGNORE,
			}
		}

		// Update the new part to processed, if the replaced part was processed
		// already.
		part.isProcessed = existingPart.isProcessed
		return
	}

	i.partAwaitingRegistration <- &awaitingRegistrationEvent{
		paymentId: part.req.paymentId(),
		partId:    part.req.htlcId(),
	}
}

func (i *Interceptor) fetchRegistration(
	paymentId string,
	scid basetypes.ShortChannelID,
) {
	registration, err := i.store.GetBuyRegistration(
		context.TODO(),
		scid,
	)

	if err == ErrNotFound {
		i.notRegistered <- paymentId
		return
	}

	if err != nil {
		log.Printf(
			"Failed to get buy registration for %v: %v",
			uint64(scid),
			err,
		)
		i.notRegistered <- paymentId
		return
	}

	i.registrationReady <- &registrationReadyEvent{
		paymentId:    paymentId,
		registration: registration,
	}
}

func (i *Interceptor) handlePartAwaitingRegistration(ev *awaitingRegistrationEvent) {
	payment, ok := i.inflightPayments[ev.paymentId]
	if !ok {
		// This part is already handled.
		return
	}

	part, ok := payment.parts[ev.partId]
	if !ok {
		// This part is already handled.
		return
	}

	if part.isFinalized {
		return
	}

	if payment.registration == nil {
		// The registration is not yet ready, queue the part again.
		i.partAwaitingRegistration <- ev
		return
	}

	if payment.registration.IsComplete {
		i.failPart(payment, part, FAILURE_UNKNOWN_NEXT_PEER)
		return
	}

	var err error
	if payment.registration.Mode == OpeningMode_NoMppVarInvoice {
		// Mode == no-MPP+var-invoice
		if payment.paymentSizeMsat != 0 {
			// Another part is already processed for this payment, and with
			// no-MPP+var-invoice there can be only a single part, so this
			// part will be failed back.
			i.failPart(payment, part, FAILURE_UNKNOWN_NEXT_PEER)
			return
		}

		// If the mode is no-MPP+var-invoice, the payment size comes from
		// the actual forwarded amount.
		payment.paymentSizeMsat = part.req.OutgoingAmountMsat

		// Make sure the minimum and maximum are not exceeded.
		if payment.paymentSizeMsat > i.config.MaxPaymentSizeMsat ||
			payment.paymentSizeMsat < i.config.MinPaymentSizeMsat {
			i.failPart(payment, part, FAILURE_UNKNOWN_NEXT_PEER)
			return
		}

		// Make sure there is enough fee to deduct.
		payment.feeMsat, err = computeOpeningFee(
			payment.paymentSizeMsat,
			payment.registration.OpeningFeeParams.Proportional,
			payment.registration.OpeningFeeParams.MinFeeMsat,
		)
		if err != nil {
			i.failPart(payment, part, FAILURE_UNKNOWN_NEXT_PEER)
			return
		}

		// Make sure the part fits the htlc and fee constraints.
		if payment.feeMsat+i.config.HtlcMinimumMsat >
			payment.paymentSizeMsat {
			i.failPart(payment, part, FAILURE_UNKNOWN_NEXT_PEER)
			return
		}
	} else {
		// Mode == MPP+fixed-invoice
		payment.paymentSizeMsat = *payment.registration.PaymentSizeMsat
		payment.feeMsat, err = computeOpeningFee(
			payment.paymentSizeMsat,
			payment.registration.OpeningFeeParams.Proportional,
			payment.registration.OpeningFeeParams.MinFeeMsat,
		)
		if err != nil {
			log.Printf(
				"Opening fee calculation error while trying to open channel "+
					"for scid %s: %v",
				payment.registration.Scid.ToString(),
				err,
			)
			i.failPart(payment, part, FAILURE_UNKNOWN_NEXT_PEER)
			return
		}
	}

	validUntil, err := time.Parse(
		basetypes.TIME_FORMAT,
		payment.registration.OpeningFeeParams.ValidUntil,
	)
	if err != nil {
		log.Printf(
			"Failed parse validUntil '%s' for %s: %v. Failing part.",
			payment.registration.OpeningFeeParams.ValidUntil,
			part.req.Scid.ToString(),
			err,
		)
		i.failPart(payment, part, FAILURE_UNKNOWN_NEXT_PEER)
		return
	}

	// Expired opening_fee_params are failed back immediately.
	if time.Now().After(validUntil) {
		i.failPart(payment, part, FAILURE_UNKNOWN_NEXT_PEER)
		return
	}

	if !payment.isRunningTimeoutListener {
		payment.isRunningTimeoutListener = true
		go func() {
			select {
			case <-time.After(time.Until(validUntil)):
				// Handle timeout of the opening_fee_params.
				i.feeParamsTimeout <- part.req.paymentId()
			case <-payment.timeoutChan:
				// Stop listening for timeouts when the payment is ready.
			}
		}()
	}

	// Make sure the cltv delta is enough.
	if int64(part.req.IncomingExpiry)-int64(part.req.OutgoingExpiry) <
		int64(i.config.TimeLockDelta)+2 {
		i.failPart(payment, part, FAILURE_INCORRECT_CLTV_EXPIRY)
		return
	}

	// Make sure htlc minimum is enough
	if part.req.OutgoingAmountMsat < i.config.HtlcMinimumMsat {
		i.failPart(payment, part, FAILURE_AMOUNT_BELOW_MINIMUM)
		return
	}

	// Make sure we're not getting tricked
	if part.req.IncomingAmountMsat < part.req.OutgoingAmountMsat {
		i.failPart(payment, part, FAILURE_AMOUNT_BELOW_MINIMUM)
		return
	}

	// Fail parts that come in after the payment is already final. To avoid
	// inconsistencies in the payment state.
	if payment.isFinal {
		i.failPart(payment, part, FAILURE_UNKNOWN_NEXT_PEER)
		return
	}

	// This is a new part. Update the sum of htlcs currently
	// in-flight.
	payment.incomingSumMsat += part.req.IncomingAmountMsat
	payment.outgoingSumMsat += part.req.OutgoingAmountMsat

	part.isProcessed = true
	// If payment_size_msat is reached, the payment is ready to forward. (this
	// is always true in no-MPP+var-invoice mode)
	if payment.outgoingSumMsat >= payment.paymentSizeMsat {
		payment.isFinal = true
		i.paymentReady <- part.req.paymentId()
	}
}

func (i *Interceptor) handleRegistrationReady(ev *registrationReadyEvent) {
	payment, ok := i.inflightPayments[ev.paymentId]
	if !ok {
		// Apparently the payment is already finished.
		return
	}

	payment.registration = ev.registration
}

func (i *Interceptor) handleNotRegistered(paymentId string) {
	i.finalizeAllParts(paymentId, &InterceptResult{
		Action: INTERCEPT_CANNOT_HANDLE,
	})
}

func (i *Interceptor) handlePaymentReady(paymentId string) {
	payment, ok := i.inflightPayments[paymentId]
	if !ok {
		// Apparently this payment is already finalized.
		return
	}

	// TODO: Handle notifications.
	// Stops the timeout listeners
	payment.closeTimeoutChan()
	go i.openChannel(payment)
}

// Opens a channel to the destination and waits for the channel to become
// active. When the channel is active, sends an openChanEvent. Should be run in
// a goroutine.
func (i *Interceptor) openChannel(payment *paymentState) {
	destination, _ := hex.DecodeString(payment.registration.PeerId)

	if payment.registration.ChannelPoint == nil {

		var targetConf *uint32
		confStr := "<nil>"
		var feeEstimation *float64
		feeStr := "<nil>"
		if i.feeEstimator != nil {
			fee, err := i.feeEstimator.EstimateFeeRate(
				context.Background(),
				i.config.FeeStrategy,
			)
			if err == nil {
				feeEstimation = &fee.SatPerVByte
				feeStr = fmt.Sprintf("%.5f", *feeEstimation)
			} else {
				log.Printf("Error estimating chain fee, fallback to target "+
					"conf: %v", err)
				targetConf = &i.config.TargetConf
				confStr = fmt.Sprintf("%v", *targetConf)
			}
		}

		capacity := ((payment.paymentSizeMsat - payment.feeMsat +
			999) / 1000) + i.config.AdditionalChannelCapacitySat

		log.Printf(
			"LSPS2: Opening zero conf channel. Destination: %x, capacity: %v, "+
				"fee: %s, targetConf: %s",
			destination,
			capacity,
			feeStr,
			confStr,
		)

		channelPoint, err := i.client.OpenChannel(&lightning.OpenChannelRequest{
			Destination:    destination,
			CapacitySat:    uint64(capacity),
			MinConfs:       i.config.MinConfs,
			IsPrivate:      true,
			IsZeroConf:     true,
			FeeSatPerVByte: feeEstimation,
			TargetConf:     targetConf,
		})
		if err != nil {
			log.Printf(
				"LSPS2 openChannel: client.OpenChannel(%x, %v) error: %v",
				destination,
				capacity,
				err,
			)
			// TODO: Verify that a client disconnect before receiving
			// funding_signed doesn't cause the OpenChannel call to error.
			// unknown_next_peer should only be returned if the client rejects
			// the channel, or the channel cannot be opened at all. If the
			// client disconnects before receiving funding_signed,
			// temporary_channel_failure should be returned.
			i.paymentFailure <- &paymentFailureEvent{
				paymentId: payment.id,
				code:      FAILURE_UNKNOWN_NEXT_PEER,
			}
			return
		}

		err = i.store.SetChannelOpened(
			context.TODO(),
			&ChannelOpened{
				RegistrationId:  payment.registration.Id,
				Outpoint:        channelPoint,
				FeeMsat:         payment.feeMsat,
				PaymentSizeMsat: payment.paymentSizeMsat,
			},
		)
		if err != nil {
			log.Printf(
				"LSPS2 openChannel: store.SetOpenedChannel(%d, %s) error: %v",
				payment.registration.Id,
				channelPoint.String(),
				err,
			)
			i.paymentFailure <- &paymentFailureEvent{
				paymentId: payment.id,
				code:      FAILURE_TEMPORARY_CHANNEL_FAILURE,
			}
			return
		}

		payment.registration.ChannelPoint = channelPoint
		// TODO: Send open channel email notification.
	}
	deadline := time.Now().Add(time.Minute)
	// Wait for the channel to open.
	for {
		chanResult, _ := i.client.GetChannel(
			destination,
			*payment.registration.ChannelPoint,
		)
		if chanResult == nil {
			select {
			case <-time.After(time.Second):
				continue
			case <-time.After(time.Until(deadline)):
				i.paymentFailure <- &paymentFailureEvent{
					paymentId: payment.id,
					code:      FAILURE_TEMPORARY_CHANNEL_FAILURE,
				}
				return
			}
		}
		log.Printf(
			"Got new channel for forward successfully. scid alias: %v, "+
				"confirmed scid: %v",
			chanResult.InitialChannelID.ToString(),
			chanResult.ConfirmedChannelID.ToString(),
		)

		scid := chanResult.ConfirmedChannelID
		if uint64(scid) == 0 {
			scid = chanResult.InitialChannelID
		}

		i.paymentChanOpened <- &paymentChanOpenedEvent{
			paymentId:       payment.id,
			scid:            scid,
			htlcMinimumMsat: chanResult.HtlcMinimumMsat,
		}
		break
	}
}

func (i *Interceptor) handlePaymentChanOpened(event *paymentChanOpenedEvent) {
	payment, ok := i.inflightPayments[event.paymentId]
	if !ok {
		// Apparently this payment is already finalized.
		return
	}
	feeRemainingMsat := payment.feeMsat

	// Deduct the lsp fee from the parts to forward.
	resolutions := []*struct {
		part       *partState
		resolution *InterceptResult
	}{}
	for _, part := range payment.parts {
		if part.isFinalized {
			continue
		}

		if !part.isProcessed {
			continue
		}

		deductMsat := uint64(math.Min(
			float64(feeRemainingMsat),
			float64(part.req.OutgoingAmountMsat-event.htlcMinimumMsat),
		))
		feeRemainingMsat -= deductMsat
		amountMsat := part.req.OutgoingAmountMsat - deductMsat
		var feeMsat *uint64
		if deductMsat > 0 {
			feeMsat = &deductMsat
		}
		resolutions = append(resolutions, &struct {
			part       *partState
			resolution *InterceptResult
		}{
			part: part,
			resolution: &InterceptResult{
				Action:     INTERCEPT_RESUME_WITH_ONION,
				AmountMsat: amountMsat,
				FeeMsat:    feeMsat,
				Scid:       event.scid,
			},
		})
	}

	if feeRemainingMsat > 0 {
		// It is possible this case happens if the htlc_minimum_msat is larger
		// than 1. We might not be able to deduct the opening fees from the
		// payment entirely. This is an edge case, and we'll fail the payment.
		log.Printf(
			"After deducting fees from payment parts, there was still fee "+
				"remaining. payment id: %s, fee remaining msat: %d. Failing "+
				"payment.",
			event.paymentId,
			feeRemainingMsat,
		)
		// TODO: Verify temporary_channel_failure is the way to go here, maybe
		// unknown_next_peer is more appropriate.
		i.paymentFailure <- &paymentFailureEvent{
			paymentId: event.paymentId,
			code:      FAILURE_TEMPORARY_CHANNEL_FAILURE,
		}
		return
	}

	for _, resolution := range resolutions {
		resolution.part.isFinalized = true
		resolution.part.resolution <- resolution.resolution
	}

	payment.registration.IsComplete = true
	go i.store.SetCompleted(context.TODO(), payment.registration.Id)
	delete(i.inflightPayments, event.paymentId)
}

func (i *Interceptor) handlePaymentTimeout(paymentId string) {
	i.handlePaymentFailure(paymentId, FAILURE_TEMPORARY_CHANNEL_FAILURE)
}

func (i *Interceptor) handleFeeParamsTimeout(paymentId string) {
	i.handlePaymentFailure(paymentId, FAILURE_UNKNOWN_NEXT_PEER)
}

func (i *Interceptor) handlePaymentFailure(
	paymentId string,
	code InterceptFailureCode,
) {
	i.finalizeAllParts(paymentId, &InterceptResult{
		Action:      INTERCEPT_FAIL_HTLC_WITH_CODE,
		FailureCode: code,
	})
}

func (i *Interceptor) finalizeAllParts(
	paymentId string,
	result *InterceptResult,
) {
	payment, ok := i.inflightPayments[paymentId]
	if !ok {
		// Apparently this payment is already finalized.
		return
	}

	// Stops the timeout listeners
	payment.closeTimeoutChan()

	for _, part := range payment.parts {
		if part.isFinalized {
			continue
		}

		part.isFinalized = true
		part.resolution <- result
	}
	delete(i.inflightPayments, paymentId)
}

func (i *Interceptor) Intercept(req *InterceptRequest) *InterceptResult {
	resolution := make(chan *InterceptResult, 1)
	i.newPart <- &partState{
		req:        req,
		resolution: resolution,
	}
	return <-resolution
}

func (i *Interceptor) failPart(
	payment *paymentState,
	part *partState,
	code InterceptFailureCode,
) {
	part.isFinalized = true
	part.resolution <- &InterceptResult{
		Action:      INTERCEPT_FAIL_HTLC_WITH_CODE,
		FailureCode: code,
	}
	delete(payment.parts, part.req.htlcId())
	if len(payment.parts) == 0 {
		payment.closeTimeoutChan()
		delete(i.inflightPayments, part.req.paymentId())
	}
}