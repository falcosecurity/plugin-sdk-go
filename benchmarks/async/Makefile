#
# Copyright (C) 2022 The Falco Authors.
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

SHELL       =/bin/bash -o pipefail
GO          ?= go
NAME        := bench
OUTPUTDIR   := build
OUTPUT      := $(OUTPUTDIR)/bench
OUTPUTGO    := $(OUTPUTDIR)/libgo$(NAME).a

all: $(OUTPUT)

clean:
	@rm -f $(OUTPUTDIR)

$(OUTPUT): bench.c bench.go
	mkdir -p $(OUTPUTDIR)
	GODEBUG=cgocheck=2 $(GO) build -buildmode=c-archive -o $(OUTPUTGO) bench.go
	$(CC) bench.c $(OUTPUTGO) -pthread -o $(OUTPUT)
