#!/bin/bash -e

SERVER_DAYS=365

CA_KEY_PEM="tls_ca.key"
CA_CERT_PEM="tls_ca.cert"
SERVER_REQ_PEM="tls_lspd.req"
SERVER_CERT_PEM="tls_lspd.cert"
SERVER_EXT_CNF="tls.conf"

if [ $# -ne 1 ]; then
    echo "usage: $0 DIRNAME"
    exit 1
fi

DIRNAME=$1
if [ ! -d ${DIRNAME} ]; then
    echo "not exist directory: $DIRNAME"
    exit 1
fi
if [ ! -f "${DIRNAME}/${SERVER_CERT_PEM}" ]; then
    echo "not exist CERT file: ${DIRNAME}/${SERVER_CERT_PEM}"
    exit 1
fi

function generateServer() {
    mv ${DIRNAME}/${SERVER_CERT_PEM} ${DIRNAME}/${SERVER_CERT_PEM}.bak.`date +"%Y%m%d%H%M%S"`

    # Use CA's private key to sign web server's CSR and get back the signed certificate
    openssl x509 -req -in "${DIRNAME}/${SERVER_REQ_PEM}" -sha256 -days ${SERVER_DAYS} -CA ${CA_CERT_PEM} -CAkey ${CA_KEY_PEM} -CAcreateserial -out "${DIRNAME}/${SERVER_CERT_PEM}" -extfile ${SERVER_EXT_CNF} 2> /dev/null

    # Output new expiry date
    openssl x509 -noout -dates -in ${DIRNAME}/${SERVER_CERT_PEM}
}

generateServer

echo '--------------------------------'
echo "LSP_CERT=\"`cat "${DIRNAME}/${SERVER_CERT_PEM}" | perl -pe 's/\n/\\\\n/g'`\""
echo '--------------------------------'
echo 'Please update LSP_CERT in lspd.env file.'
