project_name=crappasswd
BASE_DIR:=$(realpath $(shell dirname $(firstword $(MAKEFILE_LIST))))
IMAGES:=$(shell docker images $(project_name)-builder -a -q)

CURRENT_UID := $(shell id -u)
CURRENT_GID := $(shell id -g)

export CURRENT_UID
export CURRENT_GID

.PHONY: clean-builder clean-code clean all builder-down builder-rebuild run
.DEFAULT_GOAL := build/crappasswd

# DOCKER_CMD := docker run --env-file .env -h $(HOSTNAME) --rm -it --workdir /workspaces/crappasswd -v $(PWD):/workspaces/crappasswd --user $(CURRENT_UID):$(CURRENT_GID) $(project_name)-builder:latest
DOCKER_CMD := docker compose up -d && docker compose exec crappasswd-builder

### Docker targets:

builder-down: builder.Dockerfile compose.yml
	docker compose down

builder-run: builder.Dockerfile compose.yml
	$(DOCKER_CMD) /bin/bash

### Build target for crappasswd:

build/crappasswd: src/main.c
	$(DOCKER_CMD) /bin/bash -c "cmake -B build && cmake --build build"

run: build/crappasswd
	$(DOCKER_CMD) /bin/bash -c "./build/crappasswd"

clean-builder:
	docker compose down
ifeq ($(IMAGES),)
	@echo "No images to remove"
else
	-docker rmi $(IMAGES)
endif

clean-code:
	rm -rf build/

clean: clean-code clean-builder
