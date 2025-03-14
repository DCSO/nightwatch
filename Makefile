GO_FILES = $(shell find . -type f -name '*.go')

all: nightwatch

release: test vet nightwatch

nightwatch: $(GO_FILES)
	go build -v ./...
	go build -v -o build/nightwatch ./cmd/...

test:
	go test -race -cover -v ./...

vet:
	go vet ./...

clean:
	find . -name '*.yac' -delete
	rm -rf build
