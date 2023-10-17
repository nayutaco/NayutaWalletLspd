#!/bin/bash -eu

SQL="DELETE FROM channels WHERE nodeid='\x$1';"

echo "$SQL" | psql -d lspdb

