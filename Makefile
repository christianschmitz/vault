build_prefix?=$(abspath ./build)

bin=$(build_prefix)/vault

all: $(bin)

$(bin): $(shell find . -name \*.go) | $(build_prefix)
	go build -ldflags="-s -w" -o $(abspath $@)

$(build_prefix):
	mkdir -p $@

install: $(bin)
	sudo cp $(bin) /usr/local/bin
