#!/bin/bash -eu

if [ $# -ne 1 ]; then
	echo usage: $0 PAYMENT_HASH
	exit
fi

SQL="SELECT invoice FROM submarines WHERE payment_hash='\x$1';"

echo $SQL | psql -d lspdb -t

