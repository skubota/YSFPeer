GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
INSTALL=install
NAME := YSFPeer
TARGET := /usr/local/$(NAME)
CURRENT := $(shell pwd)
VERSION := 0.1
MINVER  :=$(shell date -u +.%Y%m%d)

all: deps build

.PHONY: deps
deps:
	$(GOGET) gopkg.in/yaml.v2

.PHONY: build
build:
	$(GOBUILD) -ldflags "-X main.Version=$(VERSION)$(MINVER)" -o $(NAME)

.PHONY: clean
clean:
	$(GOCLEAN)
	rm -rf $(NAME)

.PHONY: install
install:
	mkdir -p $(TARGET)
	#$(INSTALL) -m 755 $(NAME) $(TARGET)
	#$(INSTALL) -m 644 $(NAME).yml $(TARGET)

.PHONY: fmt
fmt:
	gofmt -w $(NAME).go
