.POSIX:
.SUFFIXES:
.SILENT: vet

SOURCES = $(shell find . -type f -name '*.go' -not -path "./vendor/*")

BINARY=sftp2tcp
FULL=github.com/stephane-martin/sftp2tcp
COMMIT=$(shell git rev-parse HEAD)
VERSION=0.2.3
LDFLAGS=-ldflags '-X main.Version=${VERSION} -X main.GitCommit=${COMMIT}'
LDFLAGS_RELEASE=-ldflags '-w -s -X main.Version=${VERSION} -X main.GitCommit=${COMMIT}'

$(BINARY): ${SOURCES} 
	go build -x -tags netgo -o ${BINARY}_debug ${LDFLAGS} ${FULL}

release: ${SOURCES} 
	go build -a -installsuffix nocgo -tags netgo -o ${BINARY} ${LDFLAGS_RELEASE} ${FULL}

