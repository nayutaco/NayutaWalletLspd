#!/bin/bash -eu

SQL="DELETE FROM integrity WHERE nodeid='\x$1';"

echo "$SQL" | psql -d lspdb

