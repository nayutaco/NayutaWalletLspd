package main

import (
	"fmt"
	"os"
	"testing"

	"google.golang.org/api/playintegrity/v1"
)

func floatEquals(a, b float64) bool {
	EPSILON := float64(0.00000001)
	return (a-b) < EPSILON && (b-a) < EPSILON
}

func generateEnvFile(t *testing.T, fname string, content string) {
	f, err := os.Create(fname)
	if err != nil {
		t.Errorf("generateEnvFile: create: %v", err)
	}
	_, err = f.Write([]byte(content))
	if err != nil {
		t.Errorf("generateEnvFile: write: %v", err)
	}
}

func removeEnvFile(t *testing.T, fname string) {
	os.Remove(fname)
}

func TestEnvLoad(t *testing.T) {
	lspdEnv := `
NODE_HOST="1.2.3.4:9735"
LISTEN_ADDRESS="5.6.7.8:4000"
LND_ADDRESS="localhost:10009"
NODE_NAME="abcd"

DATABASE_URL="postgres"

LND_MACAROON_HEX="001122"
LND_CERT="-----LND_CERT-----"
NODE_PUBKEY="0381cb801ca3ed432b067b2f4db840ba6c1462782f043b86ecf60a3b1666ad13c5"

BASE_FEE_MSAT=1234
FEE_RATE=0.001234
TIME_LOCK_DELTA=12
CHANNEL_FEE_PERMYRIAD=34
CHANNEL_MIN_FEE_MSAT=4600000
ADDITIONAL_CHANNEL_CAPACITY=780000
MAX_INACTIVATE_DURATION=3888000
MAX_CHANNEL_CAPACITY=4000
PRIVATE_CHANNEL_CAPACITY=5000
OPEN_CHANNEL_FEE_MAX=6000

TOKEN="token"
LSPD_PRIVATE_KEY="lspd_private_key"

# Slack notification
SLACK_BOT_TOKEN="slack_bot_token"
SLACK_SIGNING_SECRET="slack_signing_secret"
SLACK_CHANNEL="slack_channel"
SLACK_CHANNEL_ALARM="slack_channel_alarm"

USE_LSP_TLS=TRUE
LSP_KEY="-----LSP_KEY-----"
LSP_CERT="-----LSP_CERT-----"
`
	fname := fmt.Sprintf("%s/lspd.env", os.TempDir())
	generateEnvFile(t, fname, lspdEnv)
	envLoad(os.TempDir())
	removeEnvFile(t, fname)

	if baseFeeMsat != 1234 {
		t.Errorf("envLoad: baseFeeMsat: %v", baseFeeMsat)
	}
	if !floatEquals(feeRate, 0.001234) {
		t.Errorf("envLoad: feeRate: %v", feeRate)
	}
	if timeLockDelta != 12 {
		t.Errorf("envLoad: timeLockDelta: %v", timeLockDelta)
	}
	if channelFeePermyriad != 34 {
		t.Errorf("envLoad: channelFeePermyriad: %v", channelFeePermyriad)
	}
	if channelMinimumFeeMsat != 4600000 {
		t.Errorf("envLoad: channelMinimumFeeMsat: %v", channelMinimumFeeMsat)
	}
	if additionalChannelCapacity != 780000 {
		t.Errorf("envLoad: additionalChannelCapacity: %v", additionalChannelCapacity)
	}
	if maxInactiveDuration != 3888000 {
		t.Errorf("envLoad: maxInactiveDuration: %v", maxInactiveDuration)
	}
	if maxChannelCapacity != 4000 {
		t.Errorf("envLoad: maxChannelCapacity: %v", maxChannelCapacity)
	}
	if privateChannelCapacity != 5000 {
		t.Errorf("envLoad: privateChannelCapacity: %v", privateChannelCapacity)
	}
	if openChanFeeMax != 6000 {
		t.Errorf("envLoad: openChanFeeMax: %v", openChanFeeMax)
	}
}

func TestIntegrityCheckOK(t *testing.T) {
	nonce := "abcdefg"
	response := playintegrity.DecodeIntegrityTokenResponse{
		TokenPayloadExternal: &playintegrity.TokenPayloadExternal{
			AccountDetails: &playintegrity.AccountDetails{
				AppLicensingVerdict: "LICENSED",
			},
			AppIntegrity: &playintegrity.AppIntegrity{
				AppRecognitionVerdict: "PLAY_RECOGNIZED",
				PackageName:           "com.nayuta.core2",
			},
			DeviceIntegrity: &playintegrity.DeviceIntegrity{
				DeviceRecognitionVerdict: []string{
					"MEETS_STRONG_INTEGRITY",
					"MEETS_DEVICE_INTEGRITY",
					"MEETS_BASIC_INTEGRITY",
				},
			},
			RequestDetails: &playintegrity.RequestDetails{
				Nonce:              nonce,
				RequestPackageName: "com.nayuta.core2",
			},
		},
	}
	if !integrityCheck(&response, nonce) {
		t.Error("need true")
	}
}

func TestIntegrityCheckAccountDetails(t *testing.T) {
	nonce := "abcdefg"
	response := playintegrity.DecodeIntegrityTokenResponse{
		TokenPayloadExternal: &playintegrity.TokenPayloadExternal{
			AccountDetails: &playintegrity.AccountDetails{
				AppLicensingVerdict: "UNLICENSED", // NG
			},
			AppIntegrity: &playintegrity.AppIntegrity{
				AppRecognitionVerdict: "PLAY_RECOGNIZED",
				PackageName:           "com.nayuta.core2",
			},
			DeviceIntegrity: &playintegrity.DeviceIntegrity{
				DeviceRecognitionVerdict: []string{
					"MEETS_STRONG_INTEGRITY",
					"MEETS_DEVICE_INTEGRITY",
					"MEETS_BASIC_INTEGRITY",
				},
			},
			RequestDetails: &playintegrity.RequestDetails{
				Nonce:              nonce,
				RequestPackageName: "com.nayuta.core2",
			},
		},
	}
	if integrityCheck(&response, nonce) {
		t.Error("need false")
	}
}

func TestIntegrityCheckAppIntegrityAppRecognitionVerdict(t *testing.T) {
	nonce := "abcdefg"
	response := playintegrity.DecodeIntegrityTokenResponse{
		TokenPayloadExternal: &playintegrity.TokenPayloadExternal{
			AccountDetails: &playintegrity.AccountDetails{
				AppLicensingVerdict: "LICENSED",
			},
			AppIntegrity: &playintegrity.AppIntegrity{
				AppRecognitionVerdict: "UNRECOGNIZED_VERSION", // NG
				PackageName:           "com.nayuta.core2",
			},
			DeviceIntegrity: &playintegrity.DeviceIntegrity{
				DeviceRecognitionVerdict: []string{
					"MEETS_STRONG_INTEGRITY",
					"MEETS_DEVICE_INTEGRITY",
					"MEETS_BASIC_INTEGRITY",
				},
			},
			RequestDetails: &playintegrity.RequestDetails{
				Nonce:              nonce,
				RequestPackageName: "com.nayuta.core2",
			},
		},
	}
	if integrityCheck(&response, nonce) {
		t.Error("need false")
	}
}

func TestIntegrityCheckAppIntegrityPackageName(t *testing.T) {
	nonce := "abcdefg"
	response := playintegrity.DecodeIntegrityTokenResponse{
		TokenPayloadExternal: &playintegrity.TokenPayloadExternal{
			AccountDetails: &playintegrity.AccountDetails{
				AppLicensingVerdict: "LICENSED",
			},
			AppIntegrity: &playintegrity.AppIntegrity{
				AppRecognitionVerdict: "PLAY_RECOGNIZED",
				PackageName:           "com.nayuta.core", // NG
			},
			DeviceIntegrity: &playintegrity.DeviceIntegrity{
				DeviceRecognitionVerdict: []string{
					"MEETS_STRONG_INTEGRITY",
					"MEETS_DEVICE_INTEGRITY",
					"MEETS_BASIC_INTEGRITY",
				},
			},
			RequestDetails: &playintegrity.RequestDetails{
				Nonce:              nonce,
				RequestPackageName: "com.nayuta.core2",
			},
		},
	}
	if integrityCheck(&response, nonce) {
		t.Error("need false")
	}
}

func TestIntegrityCheckDeviceIntegrity1(t *testing.T) {
	nonce := "abcdefg"
	response := playintegrity.DecodeIntegrityTokenResponse{
		TokenPayloadExternal: &playintegrity.TokenPayloadExternal{
			AccountDetails: &playintegrity.AccountDetails{
				AppLicensingVerdict: "LICENSED",
			},
			AppIntegrity: &playintegrity.AppIntegrity{
				AppRecognitionVerdict: "PLAY_RECOGNIZED",
				PackageName:           "com.nayuta.core2",
			},
			DeviceIntegrity: &playintegrity.DeviceIntegrity{
				DeviceRecognitionVerdict: []string{
					// "MEETS_STRONG_INTEGRITY",
					"MEETS_DEVICE_INTEGRITY",
					"MEETS_BASIC_INTEGRITY",
				},
			},
			RequestDetails: &playintegrity.RequestDetails{
				Nonce:              nonce,
				RequestPackageName: "com.nayuta.core2",
			},
		},
	}
	if !integrityCheck(&response, nonce) {
		t.Error("need true")
	}
}

func TestIntegrityCheckDeviceIntegrity2(t *testing.T) {
	nonce := "abcdefg"
	response := playintegrity.DecodeIntegrityTokenResponse{
		TokenPayloadExternal: &playintegrity.TokenPayloadExternal{
			AccountDetails: &playintegrity.AccountDetails{
				AppLicensingVerdict: "LICENSED",
			},
			AppIntegrity: &playintegrity.AppIntegrity{
				AppRecognitionVerdict: "PLAY_RECOGNIZED",
				PackageName:           "com.nayuta.core2",
			},
			DeviceIntegrity: &playintegrity.DeviceIntegrity{
				DeviceRecognitionVerdict: []string{
					"MEETS_STRONG_INTEGRITY",
					// "MEETS_DEVICE_INTEGRITY",
					"MEETS_BASIC_INTEGRITY",
				},
			},
			RequestDetails: &playintegrity.RequestDetails{
				Nonce:              nonce,
				RequestPackageName: "com.nayuta.core2",
			},
		},
	}
	if integrityCheck(&response, nonce) {
		t.Error("need false")
	}
}

func TestIntegrityCheckDeviceIntegrity3(t *testing.T) {
	nonce := "abcdefg"
	response := playintegrity.DecodeIntegrityTokenResponse{
		TokenPayloadExternal: &playintegrity.TokenPayloadExternal{
			AccountDetails: &playintegrity.AccountDetails{
				AppLicensingVerdict: "LICENSED",
			},
			AppIntegrity: &playintegrity.AppIntegrity{
				AppRecognitionVerdict: "PLAY_RECOGNIZED",
				PackageName:           "com.nayuta.core2",
			},
			DeviceIntegrity: &playintegrity.DeviceIntegrity{
				DeviceRecognitionVerdict: []string{
					"MEETS_STRONG_INTEGRITY",
					"MEETS_DEVICE_INTEGRITY",
					// "MEETS_BASIC_INTEGRITY",
				},
			},
			RequestDetails: &playintegrity.RequestDetails{
				Nonce:              nonce,
				RequestPackageName: "com.nayuta.core2",
			},
		},
	}
	if integrityCheck(&response, nonce) {
		t.Error("need false")
	}
}

func TestIntegrityCheckDeviceIntegrityVirtual(t *testing.T) {
	nonce := "abcdefg"
	response := playintegrity.DecodeIntegrityTokenResponse{
		TokenPayloadExternal: &playintegrity.TokenPayloadExternal{
			AccountDetails: &playintegrity.AccountDetails{
				AppLicensingVerdict: "LICENSED",
			},
			AppIntegrity: &playintegrity.AppIntegrity{
				AppRecognitionVerdict: "PLAY_RECOGNIZED",
				PackageName:           "com.nayuta.core2",
			},
			DeviceIntegrity: &playintegrity.DeviceIntegrity{
				DeviceRecognitionVerdict: []string{
					"MEETS_STRONG_INTEGRITY",
					"MEETS_DEVICE_INTEGRITY",
					"MEETS_BASIC_INTEGRITY",
					"MEETS_VIRTUAL_INTEGRITY", // NG
				},
			},
			RequestDetails: &playintegrity.RequestDetails{
				Nonce:              nonce,
				RequestPackageName: "com.nayuta.core2",
			},
		},
	}
	if integrityCheck(&response, nonce) {
		t.Error("need false")
	}
}

func TestIntegrityCheckRequestDetailsNonce1(t *testing.T) {
	nonce := "abcdefg"
	response := playintegrity.DecodeIntegrityTokenResponse{
		TokenPayloadExternal: &playintegrity.TokenPayloadExternal{
			AccountDetails: &playintegrity.AccountDetails{
				AppLicensingVerdict: "LICENSED",
			},
			AppIntegrity: &playintegrity.AppIntegrity{
				AppRecognitionVerdict: "PLAY_RECOGNIZED",
				PackageName:           "com.nayuta.core2",
			},
			DeviceIntegrity: &playintegrity.DeviceIntegrity{
				DeviceRecognitionVerdict: []string{
					"MEETS_STRONG_INTEGRITY",
					"MEETS_DEVICE_INTEGRITY",
					"MEETS_BASIC_INTEGRITY",
				},
			},
			RequestDetails: &playintegrity.RequestDetails{
				Nonce:              "abcdef", // NG less
				RequestPackageName: "com.nayuta.core2",
			},
		},
	}
	if integrityCheck(&response, nonce) {
		t.Error("need false")
	}
}

func TestIntegrityCheckDetailsNonce2(t *testing.T) {
	nonce := "abcdefg"
	response := playintegrity.DecodeIntegrityTokenResponse{
		TokenPayloadExternal: &playintegrity.TokenPayloadExternal{
			AccountDetails: &playintegrity.AccountDetails{
				AppLicensingVerdict: "LICENSED",
			},
			AppIntegrity: &playintegrity.AppIntegrity{
				AppRecognitionVerdict: "PLAY_RECOGNIZED",
				PackageName:           "com.nayuta.core2",
			},
			DeviceIntegrity: &playintegrity.DeviceIntegrity{
				DeviceRecognitionVerdict: []string{
					"MEETS_STRONG_INTEGRITY",
					"MEETS_DEVICE_INTEGRITY",
					"MEETS_BASIC_INTEGRITY",
				},
			},
			RequestDetails: &playintegrity.RequestDetails{
				Nonce:              "abcdefgh", // NG large
				RequestPackageName: "com.nayuta.core2",
			},
		},
	}
	if integrityCheck(&response, nonce) {
		t.Error("need false")
	}
}

func TestIntegrityCheckRequestDetailsRequestPackageName(t *testing.T) {
	nonce := "abcdefg"
	response := playintegrity.DecodeIntegrityTokenResponse{
		TokenPayloadExternal: &playintegrity.TokenPayloadExternal{
			AccountDetails: &playintegrity.AccountDetails{
				AppLicensingVerdict: "LICENSED",
			},
			AppIntegrity: &playintegrity.AppIntegrity{
				AppRecognitionVerdict: "PLAY_RECOGNIZED",
				PackageName:           "com.nayuta.core2",
			},
			DeviceIntegrity: &playintegrity.DeviceIntegrity{
				DeviceRecognitionVerdict: []string{
					"MEETS_STRONG_INTEGRITY",
					"MEETS_DEVICE_INTEGRITY",
					"MEETS_BASIC_INTEGRITY",
				},
			},
			RequestDetails: &playintegrity.RequestDetails{
				Nonce:              nonce,
				RequestPackageName: "com.nayuta.core3", // NG
			},
		},
	}
	if integrityCheck(&response, nonce) {
		t.Error("need false")
	}
}

func TestIntegrityCheckNil1(t *testing.T) {
	nonce := "abcdefg"
	if integrityCheck(nil, nonce) {
		t.Error("need false")
	}
}

func TestIntegrityCheckNil2(t *testing.T) {
	nonce := "abcdefg"
	response := playintegrity.DecodeIntegrityTokenResponse{
		TokenPayloadExternal: nil,
	}
	if integrityCheck(&response, nonce) {
		t.Error("need false")
	}
}

func TestIntegrityCheckNilAccountDetails(t *testing.T) {
	nonce := "abcdefg"
	response := playintegrity.DecodeIntegrityTokenResponse{
		TokenPayloadExternal: &playintegrity.TokenPayloadExternal{
			AccountDetails: nil,
			AppIntegrity: &playintegrity.AppIntegrity{
				AppRecognitionVerdict: "PLAY_RECOGNIZED",
				PackageName:           "com.nayuta.core2",
			},
			DeviceIntegrity: &playintegrity.DeviceIntegrity{
				DeviceRecognitionVerdict: []string{
					"MEETS_STRONG_INTEGRITY",
					"MEETS_DEVICE_INTEGRITY",
					"MEETS_BASIC_INTEGRITY",
				},
			},
			RequestDetails: &playintegrity.RequestDetails{
				Nonce:              nonce,
				RequestPackageName: "com.nayuta.core3", // NG
			},
		},
	}
	if integrityCheck(&response, nonce) {
		t.Error("need false")
	}
}

func TestIntegrityCheckNilAppIntegrity(t *testing.T) {
	nonce := "abcdefg"
	response := playintegrity.DecodeIntegrityTokenResponse{
		TokenPayloadExternal: &playintegrity.TokenPayloadExternal{
			AccountDetails: &playintegrity.AccountDetails{
				AppLicensingVerdict: "LICENSED",
			},
			AppIntegrity: nil,
			DeviceIntegrity: &playintegrity.DeviceIntegrity{
				DeviceRecognitionVerdict: []string{
					"MEETS_STRONG_INTEGRITY",
					"MEETS_DEVICE_INTEGRITY",
					"MEETS_BASIC_INTEGRITY",
				},
			},
			RequestDetails: &playintegrity.RequestDetails{
				Nonce:              nonce,
				RequestPackageName: "com.nayuta.core3", // NG
			},
		},
	}
	if integrityCheck(&response, nonce) {
		t.Error("need false")
	}
}

func TestIntegrityCheckNilDeviceIntegrity(t *testing.T) {
	nonce := "abcdefg"
	response := playintegrity.DecodeIntegrityTokenResponse{
		TokenPayloadExternal: &playintegrity.TokenPayloadExternal{
			AccountDetails: &playintegrity.AccountDetails{
				AppLicensingVerdict: "LICENSED",
			},
			AppIntegrity: &playintegrity.AppIntegrity{
				AppRecognitionVerdict: "PLAY_RECOGNIZED",
				PackageName:           "com.nayuta.core2",
			},
			DeviceIntegrity: nil,
			RequestDetails: &playintegrity.RequestDetails{
				Nonce:              nonce,
				RequestPackageName: "com.nayuta.core3", // NG
			},
		},
	}
	if integrityCheck(&response, nonce) {
		t.Error("need false")
	}
}

func TestIntegrityCheckNilRequestDetails(t *testing.T) {
	nonce := "abcdefg"
	response := playintegrity.DecodeIntegrityTokenResponse{
		TokenPayloadExternal: &playintegrity.TokenPayloadExternal{
			AccountDetails: &playintegrity.AccountDetails{
				AppLicensingVerdict: "LICENSED",
			},
			AppIntegrity: &playintegrity.AppIntegrity{
				AppRecognitionVerdict: "PLAY_RECOGNIZED",
				PackageName:           "com.nayuta.core2",
			},
			DeviceIntegrity: &playintegrity.DeviceIntegrity{
				DeviceRecognitionVerdict: []string{
					"MEETS_STRONG_INTEGRITY",
					"MEETS_DEVICE_INTEGRITY",
					"MEETS_BASIC_INTEGRITY",
				},
			},
			RequestDetails: nil,
		},
	}
	if integrityCheck(&response, nonce) {
		t.Error("need false")
	}
}
