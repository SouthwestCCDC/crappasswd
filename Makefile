project_name=crappasswd
IMAGES := $(shell docker images $(project_name)-builder -a -q)
CURRENT_UID := $(shell id -u)
CURRENT_GID := $(shell id -g)

export CURRENT_UID
export CURRENT_GID

.PHONY: clean-builder clean-code clean builder-down run copy
.DEFAULT_GOAL := build/crappasswd

DOCKER_COMPOSE := docker compose -f .devcontainer/compose.yml
DOCKER_CMD := $(DOCKER_COMPOSE) up -d && $(DOCKER_COMPOSE) exec crappasswd-builder

### Docker targets:

builder-down: .devcontainer/builder.Dockerfile .devcontainer/compose.yml
	@$(DOCKER_COMPOSE) down

builder-run: .devcontainer/builder.Dockerfile .devcontainer/compose.yml
	@$(DOCKER_CMD) /bin/bash

### Build target for crappasswd:

build/crappasswd: src/main.c CMakeLists.txt .devcontainer/builder.Dockerfile .devcontainer/compose.yml
	@$(DOCKER_CMD) /bin/bash -c "cmake -B build && cmake --build build"

run: build/crappasswd
	@$(DOCKER_CMD) /bin/bash -c "./build/crappasswd"

copy: build/crappasswd
	@cp build/crappasswd $(HOME)/swccdc/deployment/ansible/roles/2025/regionals/crappasswd/files/crappasswd

clean-builder:
	@$(DOCKER_COMPOSE) down
ifeq ($(IMAGES),)
	@echo "No images to remove"
else
	-docker rmi $(IMAGES)
endif

clean-code:
	@rm -rf build/

clean: clean-code clean-builder
