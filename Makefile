# Copyright (c) Abstract Machines
# SPDX-License-Identifier: Apache-2.0

BUILD_DIR ?= build
SERVICES = agent
DOCKERS = $(addprefix docker_,$(SERVICES))
DOCKERS_DEV = $(addprefix docker_dev_,$(SERVICES))
CGO_ENABLED ?= 0
GOARCH ?= amd64
VERSION ?= $(shell git describe --abbrev=0 --tags)
COMMIT ?= $(shell git rev-parse HEAD)
TIME ?= $(shell date +%F_%T)
MOCKERY = $(GOBIN)/mockery
MOCKERY_VERSION = 3.7.0

ifneq ($(MG_BROKER_TYPE),)
    MG_BROKER_TYPE := $(MG_BROKER_TYPE)
else
    MG_BROKER_TYPE=msg_fluxmq
endif

define compile_service
	CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) GOARCH=$(GOARCH) GOARM=$(GOARM) \
	go build -tags $(MG_BROKER_TYPE) -ldflags "-s -w \
	-X 'github.com/absmach/agent.BuildTime=$(TIME)' \
	-X 'github.com/absmach/agent.Version=$(VERSION)' \
	-X 'github.com/absmach/agent.Commit=$(COMMIT)'" \
	-o ${BUILD_DIR}/magistrala-$(1) cmd/main.go
endef

define make_docker
	$(eval svc=$(subst docker_,,$(1)))

	docker build \
		--no-cache \
		--build-arg SVC=$(svc) \
		--build-arg GOARCH=$(GOARCH) \
		--build-arg GOARM=$(GOARM) \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg TIME=$(TIME) \
		--tag=magistrala/$(svc) \
		-f docker/Dockerfile .
endef

define make_docker_dev
	$(eval svc=$(subst docker_dev_,,$(1)))

	docker build \
		--no-cache \
		--build-arg SVC=$(svc) \
		--tag=magistrala/$(svc) \
		-f docker/Dockerfile.dev ./build
endef

all: $(SERVICES) 

arm: GOARCH=arm64
arm: all

.PHONY: all arm $(SERVICES) dockers dockers_dev ui ui_prod ui_run latest release mocks

clean:
	rm -rf ${BUILD_DIR}
	rm -f ui/main.js


ui:
	elm make ui/src/Main.elm --output=ui/main.js

ui_prod:
	elm make --optimize ui/src/Main.elm --output=ui/main.js

ui_run:
	cd ui && elm reactor

ui_clean:
	rm -f ui/main.js
	rm -rf ui/elm-stuff

install:
	cp ${BUILD_DIR}/* $(GOBIN)

test:
	go test -v -race -count 1 -tags test $(shell go list ./... | grep -v 'vendor\|cmd')

$(MOCKERY):
	@mkdir -p $(GOBIN)
	@mkdir -p mockery-tmp
	@echo ">> downloading mockery $(MOCKERY_VERSION)..."
	@curl -sL https://github.com/vektra/mockery/releases/download/v$(MOCKERY_VERSION)/mockery_$(MOCKERY_VERSION)_Linux_x86_64.tar.gz | tar -xz -C mockery-tmp
	@mv mockery-tmp/mockery $(GOBIN)
	@rm -r mockery-tmp

mocks: $(MOCKERY)
	@$(MOCKERY) --config ./tools/config/.mockery.yaml


$(SERVICES):
	$(call compile_service,$(@))

$(DOCKERS):
	$(call make_docker,$(@),$(GOARCH))

$(DOCKERS_DEV):
	$(call make_docker_dev,$(@))

dockers: $(DOCKERS)

dockers_dev: $(DOCKERS_DEV)
ifeq ($(GOARCH), arm)
	docker build --tag=magistrala/ui-arm -f ui/docker/Dockerfile.arm ui
else
	docker build --tag=magistrala/ui -f ui/docker/Dockerfile ui
endif


define docker_push
	for svc in $(SERVICES); do \
		docker push magistrala/$$svc:$(1); \
	done
endef

changelog:
	git log $(shell git describe --tags --abbrev=0)..HEAD --pretty=format:"- %s"

latest: dockers
	$(call docker_push,latest)

release:
	$(eval version = $(shell git describe --abbrev=0 --tags))
	git checkout $(version)
	$(MAKE) dockers
	for svc in $(SERVICES); do \
		docker tag magistrala/$$svc magistrala/$$svc:$(version); \
	done
	$(call docker_push,$(version))

run_provision:
	@bash scripts/provision.sh

provision:
	@bash scripts/provision.sh

run:
	docker compose -f docker/docker-compose.yml --env-file docker/.env up -d

stop:
	docker compose -f docker/docker-compose.yml --env-file docker/.env down

clean_volumes:
	docker compose -f docker/docker-compose.yml --env-file docker/.env down -v
