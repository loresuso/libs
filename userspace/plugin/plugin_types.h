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

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <inttypes.h>

// The noncontinguous numbers are to maintain equality with underlying
// falcosecurity libs types.
typedef enum ss_plugin_field_type
{
	FTYPE_UINT64 = 8,
	FTYPE_STRING = 9
} ss_plugin_field_type;

// Values to return from init() / open() / next_batch() /
// extract_fields().
typedef enum ss_plugin_rc
{
	SS_PLUGIN_SUCCESS = 0,
	SS_PLUGIN_FAILURE = 1,
	SS_PLUGIN_TIMEOUT = -1,
	SS_PLUGIN_EOF = 2,
	SS_PLUGIN_NOT_SUPPORTED = 3,
} ss_plugin_rc;

// The supported schema formats for the init configuration.
typedef enum ss_plugin_schema_type
{
	// The schema is undefined and the init configuration
	// is an opaque string.
	SS_PLUGIN_SCHEMA_NONE = 0,
	//
	// The schema follows the JSON Schema specific, and the
	// init configuration must be represented as a json.
	// see: https://json-schema.org/
	SS_PLUGIN_SCHEMA_JSON = 1,
} ss_plugin_schema_type;

// todo(jasondellaluce): add docs
typedef struct ss_plugin_plugin_event
{
	const uint8_t *data;
	uint32_t datalen;
	uint64_t ts;
} ss_plugin_plugin_event;

// todo(jasondellaluce): add docs
// todo(jasondellaluce): this should be kept in sync with the never-changin
// one of libscap, so we either need to document this or share it in a common
// header
#if defined _MSC_VER
#pragma pack(push)
#pragma pack(1)
#elif defined __sun
#pragma pack(1)
#else
#pragma pack(push, 1)
#endif
typedef struct ss_plugin_syscall_event {
#ifdef PPM_ENABLE_SENTINEL
	uint32_t sentinel_begin;
#endif
	uint64_t ts; /* timestamp, in nanoseconds from epoch */
	uint64_t tid; /* the tid of the thread that generated this event */
	uint32_t len; /* the event len, including the header */
	uint16_t type; /* the event type */
	uint32_t nparams; /* the number of parameters of the event */
} ss_plugin_syscall_event;
#if defined __sun
#pragma pack()
#else
#pragma pack(pop)
#endif

// This struct represents an event returned by the plugin, and is used
// below in next_batch().
// - evtnum: incremented for each event returned. Might not be contiguous.
// - data: pointer to a memory buffer pointer. The plugin will set it
//   to point to the memory containing the next event.
// - datalen: pointer to a 32bit integer. The plugin will set it the size of the
//   buffer pointed by data.
// - ts: the event timestamp, in nanoseconds since the epoch.
//   Can be (uint64_t)-1, in which case the engine will automatically
//   fill the event time with the current time.
//
// Note: event numbers are assigned by the plugin
// framework. Therefore, there isn't any need to fill in evtnum when
// returning an event via plugin_next_batch. It will be ignored.
typedef struct ss_plugin_event
{
	uint64_t evtnum;
	union
	{
		ss_plugin_plugin_event plugin;
		// todo(jasondellaluce): figure out if we can make this a non-pointer.
		// the answer is probably no due to the fields being appended to the
		// scap header and thus the struct size not being predictable at compile
		// time
		ss_plugin_syscall_event* syscall;
	};
	// todo(jasondellaluce): consider adding the event source (index and string)
	// here instead of in ss_plugin_extract_field, so that it's available for
	// state parsing as well
} ss_plugin_event;


// todo(jasondellaluce): add docs here
typedef struct ss_plugin_state_event
{
	uint32_t code;
	const char* name;
	uint32_t datalen;
	const uint8_t *data;
} ss_plugin_state_event;

// Used in extract_fields functions below to receive a field/arg
// pair and return an extracted value.
// field_id: id of the field, as of its index in the list of
//           fields specified by the plugin.
// field: the field name.
// arg_key: the field argument, if a 'key' argument has been specified
//          for the field (isKey=true), otherwise it's NULL.
//          For example:
//          * if the field specified by the user is foo.bar[pippo], arg_key 
//            will be the string "pippo"
//         	* if the field specified by the user is foo.bar, arg will be NULL
// arg_index: the field argument, if a 'index' argument has been specified
//            for the field (isIndex=true), otherwise it's 0.
//            For example:
//            * if the field specified by the user is foo.bar[1], arg_index 
//            will be the uint64_t '1'. 
//            Please note the ambiguity with a 0
//            argument which could be a real argument of just the default 
//            value to point out the absence. The `arg_present` field resolves
//            this ambiguity.
// arg_present: helps to understand if the arg is there since arg_index is
//              0-based.
// ftype: the type of the field. Could be derived from the field name alone,
//   but including here can prevent a second lookup of field names.
// flist: whether the field can extract lists of values or not.
//   Could be derived from the field name alone, but including it
//   here can prevent a second lookup of field names.
// The following should be filled in by the extraction function:
// - res: this union should be filled with a pointer to an array of values.
//   The array represent the list of extracted values for this field from a given event.
//   Each array element should be filled with a char* string if the corresponding
//   field was type==string, and with a uint64 value if the corresponding field was
//   type==uint64.
// - res_len: the length of the array of pointed by res.
//   If the field is not a list type, then res_len must be either 0 or 1.
//   If the field is a list type, then res_len can must be any value from 0 to N, depending
//   on how many values can be extracted from a given event.
//   Setting res_len to 0 means that no value of this field can be extracted from a given event.
typedef struct ss_plugin_extract_field
{
	// NOTE: For a given architecture, this has always the same size which
	// is sizeof(uintptr_t). Adding new value types will not create breaking
	// changes in the plugin API. However, we must make sure that each added
	// type is always a pointer.
	union
    {
		const char** str;
		uint64_t* u64;
	} res;
	uint64_t res_len;

	// NOTE: When/if adding new input fields, make sure of appending them
	// at the end of the struct to avoid introducing breaking changes in the
	// plugin API.
	uint32_t field_id;
	const char* field;
	const char* arg_key;
	uint64_t arg_index;
	bool arg_present;
	uint32_t ftype;
	bool flist;
	const char* source;
} ss_plugin_extract_field;

//
// This is the opaque pointer to the state of a plugin.
// It points to any data that might be needed plugin-wise. It is
// allocated by init() and must be destroyed by destroy().
// It is defined as void because the engine doesn't care what it is
// and it treats is as opaque.
//
typedef void ss_plugin_t;

//
// This is the opaque pointer to the state of an open instance of the source
// plugin.
// It points to any data that is needed while a capture is running. It is
// allocated by open() and must be destroyed by close().
// It is defined as void because the engine doesn't care what it is
// and it treats is as opaque.
//
typedef void ss_instance_t;

// --- STATE STUFF todo(jasondellaluce): clear up docs for this part

// Opaque a pointer to the owner of a plugin. It can be used to invert the
// control and invoke functions of the owner from within the plugin.
typedef void ss_plugin_owner_t;

// Opaque a pointer to a state table
typedef void ss_plugin_table_t;

// Opaque a pointer to an entry of a state table
typedef void ss_plugin_table_entry_t;

// Opaque a accessor to a field of a state table, which can be used
// on any entry of that table
typedef void ss_plugin_table_field_t;

// Types supported by entry fields of state tables
// todo(jasondellaluce): support all types defined in libsinsp
typedef enum ss_plugin_table_type
{
	INT64,
    UINT64,
    STRING,
	STRUCT,
} ss_plugin_table_type;

// Data representation of entry fields of state tables
typedef union ss_plugin_table_data
{
	int64_t s64;
    uint64_t u64;
    const char* str;
} ss_plugin_table_data;

// Info about a state table
typedef struct ss_plugin_table_info
{
    const char* name;
    ss_plugin_table_type key_type;
} ss_plugin_table_info;

// Info about a field of entries of a state table
typedef struct ss_plugin_table_fieldinfo
{
    const char* name;
    ss_plugin_table_type field_type;
	// todo(jasondellaluce): bool read_only;
} ss_plugin_table_fieldinfo;

#ifdef __cplusplus
}
#endif