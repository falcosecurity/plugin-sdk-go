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
GO ?= $(shell which go)
CURL = curl

FALCOSECURITY_LIBS_REVISION ?= 75ac8c97459919b696c23481b860927fb638da07
FALCOSECURITY_LIBS_REPO ?= falcosecurity/libs

PLUGIN_INFO_DIR=pkg/sdk
PLUGIN_INFO_URL=https://raw.githubusercontent.com/${FALCOSECURITY_LIBS_REPO}/${FALCOSECURITY_LIBS_REVISION}/userspace/libscap/plugin_info.h

examples_dir = $(shell ls -d examples/*/ | cut -f2 -d'/' | xargs)
examples_build = $(addprefix example-,$(examples_dir))
examples_clean = $(addprefix clean-example-,$(examples_dir))

.PHONY: all
all: plugin_info examples

.PHONY: clean
clean: $(examples_clean)
	@rm -f $(PLUGIN_INFO_DIR)/plugin_info.h

.PHONY: plugin_info
plugin_info:
	@$(CURL) -Lso $(PLUGIN_INFO_DIR)/plugin_info.h $(PLUGIN_INFO_URL)

.PHONY: test
test:
	@$(GO) test ./... -cover

.PHONY: examples
examples: $(examples_build)

example-%:
	@cd examples/$* && make

clean-example-%:
	@cd examples/$* && make clean
