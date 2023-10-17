#!/bin/bash

SVR_KEY="tls_lspd.key"
SVR_CERT="tls_lspd.cert"
CA_CERT="tls_ca.cert"

if [ $# -ne 1 ]; then
    echo "usage: $0 DIRNAME"
    exit 0
fi

DIRNAME=$1

echo for server
echo
echo USE_LSP_TLS=TRUE
echo "LSP_KEY=\"`cat "${DIRNAME}/${SVR_KEY}" | perl -pe 's/\n/\\\\n/g'`\""
echo "LSP_CERT=\"`cat "${DIRNAME}/${SVR_CERT}" | perl -pe 's/\n/\\\\n/g'`\""
echo
echo
echo for client
echo
echo \'`cat ${CA_CERT} | perl -pe 's/\n/\\\\n/g'`\'
echo
echo