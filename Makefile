.PHONY: all build test clean

# Default: build all sandbox helper binaries into bin/.
all: build

build: bin/ccode-netproxy bin/ccode-gcp-metadata

bin/ccode-netproxy: netproxy/go.mod netproxy/*.go
	@mkdir -p bin
	cd netproxy && go build -trimpath -o ../bin/ccode-netproxy .

bin/ccode-gcp-metadata: gcp-metadata/go.mod gcp-metadata/*.go
	@mkdir -p bin
	cd gcp-metadata && go build -trimpath -o ../bin/ccode-gcp-metadata .

test:
	cd netproxy && go test ./...
	cd gcp-metadata && go test ./...
	./test/test-macos.sh

clean:
	rm -rf bin
