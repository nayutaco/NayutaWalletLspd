#!/bin/bash

if [ ! -f ./config.sh ]; then
	echo "File not found: config.sh" >&2
	exit 1
fi

source ./config.sh

LSPD_BIN="NayutaHub2Lspd"
LSPD_ENV=${HOME}/.lspd/lspd.env
LND_CONF=${LND_DIR}/lnd.conf
LND_MACAROON=${LND_DIR}/data/chain/bitcoin/${NETWORK}/admin.macaroon

# use stderr

if [ ! -f ${LND_CONF} ]; then
	echo "File not found: ${LND_CONF}" >&2
	exit 1
fi

GETINFO=`${LNCLI} --lnddir ${LND_DIR} -n ${NETWORK} --rpcserver=localhost:${GRPCPORT} getinfo`
NODE_PUBKEY=`echo ${GETINFO} | jq .identity_pubkey`
if [ -z ${NODE_PUBKEY} ]; then
	echo "FAIL get NODE_PUBKEY. Maybe lnd not started." >&2
	exit 1
fi
net=`echo ${GETINFO} | jq -r .chains[0].network`
if [ ${NETWORK} != "${net}" ]; then
	echo "FAIL NETWORK not match: ${NETWORK} != ${net}" >&2
	exit 1
fi
LND_CERT=`cat $LND_DIR/tls.cert | perl -pe 's/\n/\\\\n/g'`

if [ -f ${LSPD_ENV} ]; then
	PREV_TOKEN=`grep -w -e TOKEN ${LSPD_ENV}`
	PREV_LSPD_PRIVATE_KEY=`grep -w -e LSPD_PRIVATE_KEY ${LSPD_ENV}`
	echo "---------------------------" >&2
	echo "- current lspd.env --------" >&2
	echo "${PREV_TOKEN}" >&2
	echo "${PREV_LSPD_PRIVATE_KEY}" >&2
	echo "---------------------------" >&2
	echo >&2
fi
if [ -z "${TOKEN}" ]; then
	TOKEN="TOKEN=\"`openssl rand -base64 48`\""
else
	echo "TOKEN: use config.sh" >&2
	TOKEN="TOKEN=\"${TOKEN}\""
fi
if [ -z "${LSPD_PRIVATE_KEY}" ]; then
	LSPD_PRIVATE_KEY=`${LSPD_BIN} -genkey`
else
	echo "LSPD_PRIVATE_KEY: use config.sh" >&2
	LSPD_PRIVATE_KEY="LSPD_PRIVATE_KEY=\"${LSPD_PRIVATE_KEY}\""
fi

SLACK_BOT_TOKEN="SLACK_BOT_TOKEN=\"${SLACK_BOT_TOKEN}\""
SLACK_SIGNING_SECRET="SLACK_SIGNING_SECRET=\"${SLACK_SIGNING_SECRET}\""
SLACK_CHANNEL="SLACK_CHANNEL=\"${SLACK_CHANNEL}\""
SLACK_CHANNEL_ALARM="SLACK_CHANNEL_ALARM=\"${SLACK_CHANNEL_ALARM}\""

echo "Please check \"NODE_HOST\"(${LNIPADDR})." >&2

POSTGRES_USER=`whoami`
POSTGRES_PASS=`whoami`
if [ -d postgresql ]; then
	echo "CREATE ROLE ${POSTGRES_USER} CREATEDB LOGIN;" > postgresql/init.sql
	echo "ALTER ROLE ${POSTGRES_USER} with PASSWORD '${POSTGRES_PASS}';" >> postgresql/init.sql
fi

# default value
if [ -z "${CHANNEL_MIN_FEE_MSAT}" ]; then
	CHANNEL_MIN_FEE_MSAT=2000000
fi
if [ -z "${MAX_INACTIVATE_DURATION}" ]; then
	MAX_INACTIVATE_DURATION=3888000
fi

# use stdout

echo "NODE_HOST=\"${LNIPADDR}\""
echo "LISTEN_ADDRESS=\"0.0.0.0:${LSPDPORT}\""
echo "LND_ADDRESS=\"localhost:${GRPCPORT}\""
echo "NODE_NAME=\"${NODE_NAME}\""
echo
echo "DATABASE_URL=\"postgres://${POSTGRES_USER}:${POSTGRES_PASS}@localhost:5432/lspdb\""
echo
echo "LND_MACAROON_HEX=\"`xxd -ps -u -c 1000 ${LND_MACAROON}`\""
echo "LND_CERT=\"${LND_CERT}\""
echo "NODE_PUBKEY=${NODE_PUBKEY}"
echo
echo "BASE_FEE_MSAT=${BASE_FEE_MSAT}"
echo "FEE_RATE=${FEE_RATE}"
echo "TIME_LOCK_DELTA=${TIME_LOCK_DELTA}"
echo "CHANNEL_FEE_PERMYRIAD=${CHANNEL_FEE_PERMYRIAD}"
echo "CHANNEL_MIN_FEE_MSAT=${CHANNEL_MIN_FEE_MSAT}"
echo "ADDITIONAL_CHANNEL_CAPACITY=${ADDITIONAL_CHANNEL_CAPACITY}"
echo "MAX_INACTIVATE_DURATION=${MAX_INACTIVATE_DURATION}"
echo "MAX_CHANNEL_CAPACITY=${MAX_CHANNEL_CAPACITY}"
echo "PRIVATE_CHANNEL_CAPACITY=${PRIVATE_CHANNEL_CAPACITY}"
echo "OPEN_CHANNEL_FEE_MAX=${OPEN_CHANNEL_FEE_MAX}"
echo
echo "${TOKEN}"
echo "${LSPD_PRIVATE_KEY}"
echo
echo '# Slack notification'
echo "${SLACK_BOT_TOKEN}"
echo "${SLACK_SIGNING_SECRET}"
echo "${SLACK_CHANNEL}"
echo "${SLACK_CHANNEL_ALARM}"
echo
if [ -n "${LSP_KEY}" ] && [ -n "${LSP_CERT}" ]; then
	echo "USE_LSP_TLS=TRUE"
	echo "LSP_KEY=\"${LSP_KEY}\""
	echo "LSP_CERT=\"${LSP_CERT}\""
else
	echo "USE_LSP_TLS=FALSE"
fi
