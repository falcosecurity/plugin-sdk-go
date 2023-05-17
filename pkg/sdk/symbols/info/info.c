/*
Copyright (C) 2022 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "info.h"
#include "../../plugin_types.h"
#include "../../plugin_api.h"

const char* get_default_required_api_version()
{
	return PLUGIN_API_VERSION_STR;
}

// todo(jasondellaluce,therealbobo): support this for real when we decide to
// deal with non-plugin events in the SDK Go
uint16_t* plugin_get_extract_event_types(uint32_t* num_types)
{
    static uint16_t types[] = { 322 }; // PPME_PLUGINEVENT_E
    *num_types = sizeof(types) / sizeof(uint16_t);
    return &types[0];
}
