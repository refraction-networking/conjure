FROM golang:1.20

RUN apt-get update
RUN apt-get install -y -f libzmq3-dev

WORKDIR /go/src/github/refracction-networking/gotapdance
COPY . .

# RUN go get -d -v ./...
RUN go mod download
RUN go mod tidy
RUN go install ./cli 

# no run / entrypoint specified. this containter is meant to be run w/
# gns3 and connected to using terminal or telnet.
