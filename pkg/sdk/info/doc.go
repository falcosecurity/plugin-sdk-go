/*
Copyright (C) 2021 The Falco Authors.

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

// This package exports a set of C functions that provide general
// information about the plugin. The exported functions are:
//      uint32_t get_type();
//      uint32_t get_id();
//      char* get_name();
//      char* get_description();
//      char* get_contact();
//      char* get_version();
//      char* get_required_api_version();
//      char* get_event_source();
//      char* get_extract_event_sources();
//
// In almost all cases, your plugin should import this module, unless
// your plugin exports those symbols directly.
package info
