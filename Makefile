.POSIX:
.SUFFIXES:
.SILENT: vet

SOURCES = $(shell find . -type f -name '*.go' -not -path "./vendor/*")

BINARY=sftp2tcp
FULL=github.com/stephane-martin/sftp2tcp
COMMIT=$(shell git rev-parse HEAD)
VERSION=0.1.0
LDFLAGS=-ldflags '-X main.Version=${VERSION} -X main.GitCommit=${COMMIT}'
LDFLAGS_RELEASE=-ldflags '-w -s -X main.Version=${VERSION} -X main.GitCommit=${COMMIT}"'

$(BINARY): ${SOURCES} 
	test -n "${GOPATH}"  # test $$GOPATH
	go build -o ${BINARY} ${LDFLAGS} ${FULL}

release: ${SOURCES} 
	test -n "${GOPATH}"  # test $$GOPATH
	go build -o ${BINARY}_release -a -x ${LDFLAGS_RELEASE} ${FULL}

