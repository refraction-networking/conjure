FROM golang:latest

RUN apt-get update
RUN apt-get install -y -f libzmq3-dev

WORKDIR /go/src/github/refracction-networking/conjure
COPY cmd/cli /cli

RUN go mod download
RUN go mod tidy
RUN go install ./cmd/cli
