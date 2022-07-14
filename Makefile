#
# Copyright (C) 2021 The Falco Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
# the License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
SHELL := /bin/bash
GO    ?= $(shell which go)
CURL  ?= $(shell which curl)

FALCOSECURITY_LIBS_REVISION ?= 5b9c3ca9ae55800e774e1681a0c5e7d54ca89263
FALCOSECURITY_LIBS_REPO ?= falcosecurity/libs
PLUGINLIB_URL=https://raw.githubusercontent.com/${FALCOSECURITY_LIBS_REPO}/${FALCOSECURITY_LIBS_REVISION}/userspace/plugin

examples_dir = $(shell ls -d examples/*/ | cut -f2 -d'/' | xargs)
examples_build = $(addprefix example-,$(examples_dir))
examples_clean = $(addprefix clean-example-,$(examples_dir))

.PHONY: all
all: pluginlib examples

.PHONY: clean
clean: clean-pluginlib $(examples_clean)

.PHONY: pluginlib
pluginlib:
	@$(CURL) -Lso pkg/sdk/plugin_types.h $(PLUGINLIB_URL)/plugin_types.h
	@$(CURL) -Lso pkg/sdk/plugin_api.h $(PLUGINLIB_URL)/plugin_api.h

clean-pluginlib:
	@rm -f \
		pkg/sdk/plugin_types.h \
		pkg/sdk/plugin_api.h \

.PHONY: test
test:
	@$(GO) test ./... -cover

.PHONY: examples
examples: $(examples_build)

example-%:
	@cd examples/$* && make

clean-example-%:
	@cd examples/$* && make clean
