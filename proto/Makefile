# Makefile for generating the language-specific protobuf modules

PROTOC		= /usr/bin/protoc

SRC		= signalling.proto

GO_OUT		= signalling.pb.go
RUST_OUT	= signalling.rs
RUST_OUT_PATH	= ../src/$(RUST_OUT)

default: $(RUST_OUT_PATH)

$(GO_OUT):	$(SRC)
	$(PROTOC) $(SRC) --go_out .

$(RUST_OUT_PATH): $(SRC)
	PATH=$(PATH):$(HOME)/.cargo/bin:/root/.cargo/bin $(PROTOC) $(SRC) --rust_out . && cp $(RUST_OUT) $(RUST_OUT_PATH)

$(PYTHON_OUT_PATH): $(SRC)
	$(PROTOC) --python_out=. $(SRC) && cp $(PYTHON_OUT) $(PYTHON_OUT_PATH)

clean:
	rm -f $(GO_OUT) $(RUST_OUT) $(RUST_OUT_PATH) $(PYTHON_OUT) $(PYTHON_OUT_PATH)
