#!/bin/bash

SQL="SELECT * FROM integrity;"

echo "$SQL" | psql -d lspdb

