#!/bin/bash -e

CA_DAYS=3650
SERVER_DAYS=365
SUBJECT="/C=JP/ST=Fukuoka/L=Fukuoka/O=Nayuta/OU=Nayuta/CN=localhost"

CA_KEY_PEM="tls_ca.key"
CA_CERT_PEM="tls_ca.cert"
SERVER_KEY_PEM="tls_lspd.key"
SERVER_REQ_PEM="tls_lspd.req"
SERVER_CERT_PEM="tls_lspd.cert"
SERVER_EXT_CNF="tls.conf"

if [ $# -ne 1 ]; then
    echo "usage: $0 DIRNAME"
    exit 0
fi

DIRNAME=$1
if [ ! -d ${DIRNAME} ]; then
    mkdir ${DIRNAME}
fi

function generateCA() {
    echo "-------------------------------"
    echo " generateCA"
    echo "-------------------------------"
    rm -f ${CA_KEY_PEM} ${CA_CERT_PEM}

    # 1. Generate CA's private key and self-signed certificate
    openssl req -x509 -newkey rsa:4096 -sha256 -days ${CA_DAYS} -nodes -keyout ${CA_KEY_PEM} -out ${CA_CERT_PEM} -subj ${SUBJECT} 2> /dev/null

    #echo "CA's self-signed certificate"
    #openssl x509 -in ${CA_CERT_PEM} -noout -text
}

function generateServerKey() {
    echo "-------------------------------"
    echo " generateServerKey"
    echo "-------------------------------"
    rm -f "${DIRNAME}/${SERVER_KEY_PEM}" "${DIRNAME}/${SERVER_REQ_PEM}" "${DIRNAME}/${SERVER_CERT_PEM}"

    # 2. Generate web server's private key and certificate signing request (CSR)
    openssl req -newkey rsa:4096 -sha256 -nodes -keyout "${DIRNAME}/${SERVER_KEY_PEM}" -out "${DIRNAME}/${SERVER_REQ_PEM}" -subj ${SUBJECT} 2> /dev/null
}

function generateServer() {
    echo "-------------------------------"
    echo " generateServer"
    echo "-------------------------------"
    rm -f "${DIRNAME}/${SERVER_CERT_PEM}"

    # 3. Use CA's private key to sign web server's CSR and get back the signed certificate
    openssl x509 -req -in "${DIRNAME}/${SERVER_REQ_PEM}" -sha256 -days ${SERVER_DAYS} -CA ${CA_CERT_PEM} -CAkey ${CA_KEY_PEM} -CAcreateserial -out "${DIRNAME}/${SERVER_CERT_PEM}" -extfile ${SERVER_EXT_CNF} 2> /dev/null

    #echo "Server's signed certificate"
    #openssl x509 -in ${SERVER_CERT_PEM} -noout -text
}

if [ ! -f ${CA_KEY_PEM} ]; then
	generateCA
else
    echo "CA: use existing CERT"
fi

if [ ! -f "${DIRNAME}/${SERVER_KEY_PEM}" ]; then
	generateServerKey
else
    echo "Server: use existing Server Key"
fi

if [ ! -f "${DIRNAME}/${SERVER_CERT_PEM}" ]; then
    generateServer
else
    echo "Server: use existing Server CERT"
fi

echo '--------------------------------'
./read_tls.sh ${DIRNAME}
echo '--------------------------------'
echo 'DONE'
