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

#pragma once

#include "plugin_types.h"

#ifdef __cplusplus
extern "C" {
#endif


//
// API versions of this plugin framework
//
#define PLUGIN_API_VERSION_MAJOR 2
#define PLUGIN_API_VERSION_MINOR 0
#define PLUGIN_API_VERSION_PATCH 0

//
// Just some not so smart defines to retrieve plugin api version as string
//
#define QUOTE(str)                  #str
#define EXPAND_AND_QUOTE(str)       QUOTE(str)
#define PLUGIN_API_VERSION          PLUGIN_API_VERSION_MAJOR.PLUGIN_API_VERSION_MINOR.PLUGIN_API_VERSION_PATCH
#define PLUGIN_API_VERSION_STR      EXPAND_AND_QUOTE(PLUGIN_API_VERSION)


// --- STATE STUFF todo(jasondellaluce): clear up docs for this part

// Vtable for controlling fields of entries of a state table
typedef struct
{
    ss_plugin_table_fieldinfo* (*list_fields)(const ss_plugin_table_t* t, uint32_t* nfields);
    ss_plugin_table_field_t* (*get_field)(const ss_plugin_table_t* t, const char* name, ss_plugin_table_type data_type);
    ss_plugin_table_field_t* (*add_field)(const ss_plugin_table_t* t, const char* name, ss_plugin_table_type data_type);
}
plugin_table_field_api;

// Vtable for controlling a state table in read mode
typedef struct
{
    const char*	(*get_name)(const ss_plugin_table_t* t);
    uint32_t *(*get_size)(const ss_plugin_table_t* t); // todo(jasondellaluce): uint64?
    ss_plugin_table_entry_t* (*get_entry)(const ss_plugin_table_t* t, const ss_plugin_table_data* key);
    bool (*foreach_entry)(const ss_plugin_table_t*, bool (*iterator)(const ss_plugin_table_entry_t*));
    void (*read_entry_field)(const ss_plugin_table_t* e, const ss_plugin_table_field_t* f, ss_plugin_table_entry_t* out);
}
plugin_table_read_api;

// todo(jasondellaluce): plugin_table_write_api_t

typedef struct
{
    ss_plugin_table_info* (*list_tables)(ss_plugin_owner_t* o, uint32_t* ntables);
    ss_plugin_table_t* (*get_table)(ss_plugin_owner_t* o, const char* name, ss_plugin_table_type key_type);
    plugin_table_field_api* (*get_table_field_initializer)(ss_plugin_owner_t* o, ss_plugin_table_t* t);
    // todo(jasondellaluce): add_table
}
plugin_table_init_api;

// --- END OF STATE STUFF todo(jasondellaluce): clear up docs for this part


//
// The struct below define the functions and arguments for plugins capabilities:
// * event sourcing
// * field extraction
// The structs are used by the plugin framework to load and interface with plugins.
//
// From the perspective of the plugin, each function below should be
// exported from the dynamic library as a C calling convention
// function, adding a prefix "plugin_" to the function name
// (e.g. plugin_get_required_api_version, plugin_init, etc.)
//
// Plugins are totally responsible of both allocating and deallocating memory.
// Plugins have the guarantee that they can safely deallocate memory in
// these cases:
// - During close(), for all the memory allocated in the context of a plugin
//   instance after open().
// - During destroy(), for all the memory allocated by the plugin, as it stops
//   being executed.
// - During subsequent calls to the same function, for all the exported
//   functions returning memory pointers.
//
// Plugins must not free memory passed in by the framework (i.e. function input
// parameters) if not corresponding to plugin-allocated memory in the
// cases above. Plugins can safely use the passed memory during the execution
// of the exported functions.

//
// Plugins API vtable
//
typedef struct
{
	//
	// Return the version of the plugin API used by this plugin.
	// Required: yes
	// Return value: the API version string, in the following format:
	//       "<major>.<minor>.<patch>", e.g. "1.2.3".
	// NOTE: to ensure correct interoperability between the framework and the plugins,
	//       we use a semver approach. Plugins are required to specify the version
	//       of the API they run against, and the framework will take care of checking
	//       and enforcing compatibility.
	//
	const char *(*get_required_api_version)();

	//
	// Return a string representation of a schema describing the data expected
	// to be passed as a configuration during the plugin initialization.
	// Required: no
	// Arguments:
	// - schema_type: The schema format type of the returned value among the
	//   list of the supported ones according to the ss_plugin_config_schema
	//   enumeration.
	// Return value: a string representation of the schema for the config
	//   to be passed to init().
	//
	// Plugins can optionally export this symbol to specify the expected
	// format for the configuration string passed to init(). If specified,
	// the init() function can assume the config string to always be
	// well-formed. The framework will take care of automatically parsing it
	// against the provided schema and generating ad-hoc errors accordingly.
	// This also serves as a piece of documentation for users about how the
	// plugin needs to be configured.
	//
	const char *(*get_init_schema)(ss_plugin_schema_type *schema_type);

	//
	// Initialize the plugin and allocate its state.
	// Required: yes
	// Arguments:
	// - config: a string with the plugin configuration. The format of the
	//   string is chosen by the plugin itself.
	// - rc: pointer to a ss_plugin_rc that will contain the initialization result
	// Return value: pointer to the plugin state that will be treated as opaque
	//   by the framework and passed to the other plugin functions.
	//   If rc is SS_PLUGIN_FAILURE, this function may return NULL or a state to
	//   later retrieve the error string.
	// 
	// If a non-NULL ss_plugin_t* state is returned, then subsequent invocations
	// of init() must not return the same ss_plugin_t* value again, if not after
	// it has been disposed with destroy() first.
	ss_plugin_t *(*init)(const char *config, ss_plugin_rc *rc, ss_plugin_owner_t* owner, plugin_table_init_api* table_init);

	//
	// Destroy the plugin and, if plugin state was allocated, free it.
	// Required: yes
	//
	void (*destroy)(ss_plugin_t *s);

	//
	// Return a string with the error that was last generated by
	// the plugin.
	// Required: yes
	//
	// In cases where any other api function returns an error, the
	// plugin should be prepared to return a human-readable error
	// string with more context for the error. The framework
	// calls get_last_error() to access that string.
	//
	const char *(*get_last_error)(ss_plugin_t *s);

	//
	// Return the name of the plugin, which will be printed when displaying
	// information about the plugin.
	// Required: yes
	//
	const char *(*get_name)();

	//
	// Return the descriptions of the plugin, which will be printed when displaying
	// information about the plugin.
	// Required: yes
	//
	const char *(*get_description)();

	//
	// Return a string containing contact info (url, email, etc) for
	// the plugin authors.
	// Required: yes
	//
	const char *(*get_contact)();

	//
	// Return the version of this plugin itself
	// Required: yes
	// Return value: a string with a version identifier, in the following format:
	//        "<major>.<minor>.<patch>", e.g. "1.2.3".
	// This differs from the api version in that this versions the
	// plugin itself. Note, increasing the major version signals breaking
	// changes in the plugin implementation but must not change the
	// serialization format of the event data. For example, events written
	// in pre-existing capture files must always be readable by newer versions
	// of the plugin.
	//
	const char *(*get_version)();

	// Event sourcing capability API
	struct
	{
		//
		// Return the unique ID of the plugin.
		// Required: yes
		// EVERY PLUGIN WITH EVENT SOURCING CAPABILITIES MUST OBTAIN AN OFFICIAL ID FROM THE
		// FALCOSECURITY ORGANIZATION, OTHERWISE IT WON'T PROPERLY COEXIST WITH OTHER PLUGINS.
		//
		uint32_t (*get_id)();

		//
		// Return a string representing the name of the event source generated
		// by this plugin.
		// Required: yes
		// Example event sources would be strings like "aws_cloudtrail",
		// "k8s_audit", etc. The source can be used by plugins with event
		// sourcing capabilities to filter the events they receive.
		//
		const char* (*get_event_source)();

		//
		// Open the event source and start a capture (e.g. stream of events)
		// Required: yes
		// Arguments:
		// - s: the plugin state returned by init()
		// - params: the open parameters, as an opaque string.
		//           The string format is defined by the plugin itself
		// - rc: pointer to a ss_plugin_rc that will contain the open result
		// Return value: a pointer to the opened plugin instance that will be
		//               passed to next_batch(), close(), event_to_string()
		//               and extract_fields().
		//
		// If a non-NULL ss_instance_t* instance is returned, then subsequent
		// invocations of open() must not return the same ss_instance_t* value
		// again, if not after it has been disposed with close() first.
		ss_instance_t* (*open)(ss_plugin_t* s, const char* params, ss_plugin_rc* rc);

		//
		// Close a capture.
		// Required: yes
		// Arguments:
		// - s: the plugin state, returned by init(). Can be NULL.
		// - h: the plugin instance, returned by open(). Can be NULL.
		//
		void (*close)(ss_plugin_t* s, ss_instance_t* h);

		//
		// Return a list of suggested open parameters supported by this plugin.
		// Any of the values in the returned list are valid parameters for open().
		// Required: no
		// Return value: a string with the list of open params encoded as
		//   a json array. Each field entry is a json object with the following
		//   properties:
		//     - "value": a string usable as an open() parameter.
		//     - "desc": (optional) a string with a description of the parameter.
		//     - "separator": (optional) a separator string, for when "value"
		//                    represents multiple contatenated open parameters
		//   Example return value:
		//   [
		//      {"value": "resource1", "desc": "An example of openable resource"},
		//      {"value": "resource2", "desc": "Another example of openable resource"},
		//      {
		//          "value": "res1;res2;res3",
		//          "desc": "Some names",
		//          "separator": ";"
		//      }
		//   ]
		const char* (*list_open_params)(ss_plugin_t* s, ss_plugin_rc* rc);

		//
		// Return the read progress.
		// Required: no
		// Arguments:
		// - progress_pct: the read progress, as a number between 0 (no data has been read)
		//   and 10000 (100% of the data has been read). This encoding allows the framework to
		//   print progress decimals without requiring to deal with floating point numbers
		//   (which could cause incompatibility problems with some languages).
		// Return value: a string representation of the read
		//   progress. This might include the progress percentage
		//   combined with additional context added by the plugin. If
		//   NULL, progress_pct should be used.
		//   The returned memory pointer must be allocated by the plugin
		//   and must not be deallocated or modified until the next call to
		//   get_progress().
		// NOTE: reporting progress is optional and in some case could be impossible. However,
		//       when possible, it's recommended as it provides valuable information to the
		//       user.
		//
		// This function can be invoked concurrently by multiple threads,
		// each with distinct and unique parameter values.
		// If the returned pointer is non-NULL, then it must be uniquely
		// attached to the ss_instance_t* parameter value. The pointer must not
		// be shared across multiple distinct ss_instance_t* values.
		const char* (*get_progress)(ss_plugin_t* s, ss_instance_t* h, uint32_t* progress_pct);

		//
		// Return a text representation of an event generated by this plugin with event sourcing capabilities.
		// Required: no
		// Arguments:
		// - evt: an event struct produced by a call to next_batch().
		//   This is allocated by the framework, and it is not guaranteed
		//   that the event struct pointer is the same returned by the last
		//   next_batch() call.
		// Return value: the text representation of the event. This is used, for example,
		//   to print a line for the given event.
		//   The returned memory pointer must be allocated by the plugin
		//   and must not be deallocated or modified until the next call to
		//   event_to_string().
		//
		// This function can be invoked concurrently by multiple threads,
		// each with distinct and unique parameter values.
		// If the returned pointer is non-NULL, then it must be uniquely
		// attached to the ss_plugin_t* parameter value. The pointer must not
		// be shared across multiple distinct ss_plugin_t* values.
		const char* (*event_to_string)(ss_plugin_t *s, const ss_plugin_event *evt);

		//
		// Return the next batch of events.
		// On success:
		//   - nevts will be filled in with the number of events.
		//   - evts: pointer to an ss_plugin_event pointer. The plugin must
		//     allocate an array of contiguous ss_plugin_event structs
		//     and each data buffer within each ss_plugin_event struct.
		//     Memory pointers set as output must be allocated by the plugin
		//     and must not be deallocated or modified until the next call to
		//     next_batch() or close().
		// Required: yes
		//
		// This function can be invoked concurrently by multiple threads,
		// each with distinct and unique parameter values.
		// The value of the ss_plugin_event** output parameter must be uniquely
		// attached to the ss_instance_t* parameter value. The pointer must not
		// be shared across multiple distinct ss_instance_t* values.
		ss_plugin_rc (*next_batch)(ss_plugin_t* s, ss_instance_t* h, uint32_t *nevts, ss_plugin_event **evts);
	};

	// Field extraction capability API
	struct
	{
		//
		// Return a string describing the event sources that this
		// plugin can consume.
		// Required: no
		// Return value: a json array of strings containing event
		//   sources returned by a plugin with event sourcing capabilities get_event_source()
		//   function.
		// This function is optional--if NULL or an empty array, then if plugin has sourcing capability
		// it will only receive events matching its event source,
		// otherwise it will receive every event for extraction.
		//
		const char* (*get_extract_event_sources)();

		//
		// Return the list of extractor fields exported by this plugin. Extractor
		// fields can be used in Falco rule conditions.
		// Required: yes
		// Return value: a string with the list of fields encoded as a json
		//   array.
		//   Each field entry is a json object with the following properties:
		//     "name": a string with a name for the field
		//     "type": one of "string", "uint64"
		//     "isList: (optional) If present and set to true, notes
		//              that the field extracts a list of values.
		//     "arg": (optional) if present, notes that the field can accept
		//             an argument e.g. field[arg]. More precisely, the following
		//             flags could be specified:
		//             "isRequired": if true, the argument is required.
		//             "isIndex": if true, the field is numeric.
		//             "isKey": if true, the field is a string.
		//             If "isRequired" is true, one between "isIndex" and
		//             "isKey" must be true, to specify the argument type.
		//             If "isRequired" is false, but one between "isIndex"
		//             and "isKey" is true, the argument is allowed but
		//             not required.
		//     "display": (optional) If present, a string that will be used to
		//                display the field instead of the name. Used in tools
		//                like wireshark.
		//     "desc": a string with a description of the field
		// Example return value:
		// [
		//    {"type": "uint64", "name": "field1", "desc": "Describing field 1"},
		//    {"type": "string", "name": "field2", "arg": {"isRequired": true, "isIndex": true}, "desc": "Describing field 2"},
		// ]
		const char* (*get_fields)();

		//
		// Extract one or more a filter field values from an event.
		// Required: yes
		// Arguments:
		// - evt: an event struct produced by a call to next_batch().
		//   This is allocated by the framework, and it is not guaranteed
		//   that the event struct pointer is the same returned by the last
		//   next_batch() call.
		// - num_fields: the length of the fields array.
		// - fields: an array of ss_plugin_extract_field structs. Each entry
		//   contains a single field + optional argument as input, and the corresponding
		//   extracted value as output. Memory pointers set as output must be allocated
		//   by the plugin and must not be deallocated or modified until the next
		//   extract_fields() call.
		//
		// Return value: A ss_plugin_rc with values SS_PLUGIN_SUCCESS or SS_PLUGIN_FAILURE.
		//
		// This function can be invoked concurrently by multiple threads,
		// each with distinct and unique parameter values.
		// The value of the ss_plugin_extract_field* output parameter must be
		// uniquely attached to the ss_plugin_t* parameter value. The pointer
		// must not be shared across multiple distinct ss_plugin_t* values.
		ss_plugin_rc (*extract_fields)(ss_plugin_t *s, const ss_plugin_event *evt, uint32_t num_fields, ss_plugin_extract_field *fields);
	};
} plugin_api;

#ifdef __cplusplus
}
#endif