package main

import "testing"

func TestPropotionalCapacity(t *testing.T) {
	additionalChannelCapacity = 100_000
	maxChannelCapacity = 400_000
	results := []struct {
		amountMsat int64
		result     int64
	}{
		{
			amountMsat: 0,
			result:     20_000,
		},
		{
			amountMsat: 2_001_000,
			result:     22_001,
		},
		{
			amountMsat: 49_999_999,
			result:     69_999,
		},
		{
			amountMsat: 50_000_000,
			result:     100_000,
		},
		{
			amountMsat: 99_999_999,
			result:     149_999,
		},
		{
			amountMsat: 200_000_000,
			result:     300_000,
		},
	}
	for _, ret := range results {
		localFundingAmountMsat := int64(ret.amountMsat)
		capacity := proportionalCapacity(localFundingAmountMsat)
		if capacity != int64(ret.result) {
			t.Errorf("bad capacity: %d => %d", ret.result, capacity)
		}
	}
}
