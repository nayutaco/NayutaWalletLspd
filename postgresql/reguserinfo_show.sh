#!/bin/bash

SQL="SELECT * FROM userinfo;"

echo "$SQL" | psql -d lspdb

