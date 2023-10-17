#!/bin/bash

SQL="SELECT payment_hash,status FROM submarines;"

echo $SQL | psql -d lspdb -f -

