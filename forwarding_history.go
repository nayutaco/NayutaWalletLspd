package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/chainrpc"
	"google.golang.org/grpc/metadata"
)

type copyFromEvents struct {
	events []*lnrpc.ForwardingEvent
	idx    int
	err    error
}

func (cfe *copyFromEvents) Next() bool {
	cfe.idx++
	return cfe.idx < len(cfe.events)
}

func (cfe *copyFromEvents) Values() ([]interface{}, error) {
	event := cfe.events[cfe.idx]
	values := []interface{}{
		event.TimestampNs,
		event.ChanIdIn, event.ChanIdOut,
		event.AmtInMsat, event.AmtOutMsat}
	return values, nil
}

func (cfe *copyFromEvents) Err() error {
	return cfe.err
}

func channelsSynchronize(client chainrpc.ChainNotifierClient) {
	lastSync := time.Now().Add(-6 * time.Minute)
	for {
		cancellableCtx, cancel := context.WithCancel(context.Background())
		clientCtx := metadata.AppendToOutgoingContext(cancellableCtx, "macaroon", os.Getenv("LND_MACAROON_HEX"))
		stream, err := client.RegisterBlockEpochNtfn(clientCtx, &chainrpc.BlockEpoch{})
		if err != nil {
			logAlarmNotify("chainNotifierClient.RegisterBlockEpochNtfn(): %v", err)
			cancel()
			time.Sleep(1 * time.Second)
			continue
		}

		for {
			_, err := stream.Recv()
			if err != nil {
				logFatal("stream.Recv: %v", err)
				break
			}
			if lastSync.Add(5 * time.Minute).Before(time.Now()) {
				time.Sleep(30 * time.Second)
				err = channelsSynchronizeOnce()
				lastSync = time.Now()
				if err != nil {
					logAlarmNotify("channelsSynchronizeOnce() err: %v", err)
				}
			}
		}
		cancel()
	}
}

func channelsSynchronizeOnce() error {
	log.Trace("channelsSynchronizeOnce")
	clientCtx := metadata.AppendToOutgoingContext(context.Background(), "macaroon", os.Getenv("LND_MACAROON_HEX"))
	channels, err := client.ListChannels(clientCtx, &lnrpc.ListChannelsRequest{PrivateOnly: true})
	if err != nil {
		return logAlarmNotify("ListChannels error: %v", err)
	}
	// log.Trace("channelsSynchronizeOnce - received channels")
	lastUpdate := time.Now()
	for _, c := range channels.Channels {
		nodeID, err := hex.DecodeString(c.RemotePubkey)
		if err != nil {
			logAlarmNotify("hex.DecodeString in channelsSynchronizeOnce error: %v", err)
			continue
		}
		err = insertChannel(c.ChanId, c.ChannelPoint, nodeID, lastUpdate, dbOpenChanReasonSync)
		if err != nil {
			logAlarmNotify("insertChannel(%v, %v, %x) in channelsSynchronizeOnce error: %v", c.ChanId, c.ChannelPoint, nodeID, err)
			continue
		}
	}
	log.Trace("channelsSynchronizeOnce - done")

	return nil
}

func forwardingHistorySynchronize() {
	for {
		err := forwardingHistorySynchronizeOnce()
		if err != nil {
			logAlarmNotify("forwardingHistorySynchronizeOnce() err: %v", err)
		}
		time.Sleep(1 * time.Minute)
	}
}

func forwardingHistorySynchronizeOnce() error {
	last, err := lastForwardingEvent()
	if err != nil {
		return fmt.Errorf("lastForwardingEvent() error: %v", err)
	}
	// log.Tracef("last1: %v", last)
	last = last/1_000_000_000 - 1*3600
	if last <= 0 {
		last = 1
	}
	// log.Tracef("last2: %v", last)
	now := time.Now()
	endTime := uint64(now.Add(time.Hour * 24).Unix())
	clientCtx := metadata.AppendToOutgoingContext(context.Background(), "macaroon", os.Getenv("LND_MACAROON_HEX"))
	indexOffset := uint32(0)
	for {
		forwardHistory, err := client.ForwardingHistory(clientCtx, &lnrpc.ForwardingHistoryRequest{
			StartTime:    uint64(last),
			EndTime:      endTime,
			NumMaxEvents: 10000,
			IndexOffset:  indexOffset,
		})
		if err != nil {
			return fmt.Errorf("client.ForwardingHistory() error: %v", err)
		}
		if len(forwardHistory.ForwardingEvents) == 0 {
			break
		}
		indexOffset = forwardHistory.LastOffsetIndex
		cfe := copyFromEvents{events: forwardHistory.ForwardingEvents, idx: -1}
		err = insertForwardingEvents(&cfe)
		if err != nil {
			return fmt.Errorf("insertForwardingEvents() error: %v", err)
		}
	}
	return nil
}
