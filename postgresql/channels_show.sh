#!/bin/bash

SQL="SELECT * FROM channels;"

echo "$SQL" | psql -d lspdb

