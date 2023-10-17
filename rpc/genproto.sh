#!/bin/bash
#protoc -I . lspd.proto --go_out=plugins=grpc:.

# https://grpc.io/docs/languages/go/quickstart/#regenerate-grpc-code
protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative internal.proto
