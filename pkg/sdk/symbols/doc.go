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

// Package symbols provides prebuilt implementations for all the C symbols
// required to develop plugins as for the definitions of plugin_info.h.
//
// This package defines low-level constructs for plugin development meant
// for advanced users that wish to use only a portion of the SDK internals.
// The sdk/plugins package should normally be used instead for the most general
// use cases, as it provides more high-level constructs. The symbols package
// is also used internally, and may be subject to more frequent breaking
// changes.
//
// The C symbol set is divided in different sub-packages to allow plugin
// developers to import only the ones they need. Importing one of the
// sub-packages automatically includes its prebuilt symbols in the plugin.
// If one of the prebuilt symbols is imported it would not be possible
// to re-define it in the plugin, as this would lead to a linking failure
// due to multiple definitions of the same symbol.
//
// Each sub-package has been designed to only implement one or few symbols.
// Plugin developers can either decide to implement all the symbols of the
// sub-packages, or to import only a subset of them and decide to implement
// some of the symbols manually.
//
// The mapping between the prebuilt C exported symbols and their sub-package
// has been designed by grouping them depending on their use cases.
// The mapping is designed as follows:
//  - info:         get_type, get_id, get_description, get_contact,
//                  get_version, get_required_api_version,
//                  get_event_source, get_extract_event_sources
//  - fields:       plugin_get_fields
//  - lasterr:      plugin_get_last_error
//  - initialize:   plugin_init, plugin_destroy
//  - open:         plugin_open, plugin_close
//  - nextbatch:    plugin_next_batch
//  - extract:      plugin_extract_fields
//  - evtstr:       plugin_event_to_string
//  - progress:     plugin_get_progress
//
// There are no horizontal dependencies between the sub-packages, which means
// that they are independent from one another. Each sub-package only depends
// on the definitions of the base-level sdk package, and occasionally uses
// constructs from the ptr and cgo packages. This makes each sub-package
// composable, and developers can easily mix manually implemented C symbols
// with the prebuilt ones, as long as the interface requirements are respected.
//
package symbols
