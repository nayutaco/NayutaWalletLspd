MAJOR=0
MINOR=6
BUILD=0
COMMIT=$(shell git log -n1 --abbrev-commit --abbrev=12 --format=format:%h)

all: build cli

build:
	go build -ldflags "-X main.version=v$(MAJOR).$(MINOR).$(BUILD)-$(COMMIT)" .
	./NayutaHub2Lspd -version

cli: cmd/cli/main.go cmd/cli/client.go
	go build ./cmd/cli

install:
	go install -ldflags "-X main.version=v$(MAJOR).$(MINOR).$(BUILD)-$(COMMIT)" .

clean:
	go clean .

test:
	go test -v
