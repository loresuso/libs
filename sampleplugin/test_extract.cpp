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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <functional>
#include <chrono>
#include "../userspace/plugin/plugin_api.h"

static const char *pl_required_api_version = PLUGIN_API_VERSION_STR;
static const char *pl_name_base            = "test_extract";
static char pl_name[1024];
static const char *pl_desc                 = "Test Plugin For Regression Tests";
static const char *pl_contact              = "github.com/falcosecurity/falco";
static const char *pl_version              = "0.1.0";
static const char *pl_extract_sources      = "[\"test_source\"]";
static const char *pl_fields               = "[{\"type\": \"uint64\", \"name\": \"test.field\", \"desc\": \"Describing test field\"}]";

// This struct represents the state of a plugin. Just has a placeholder string value.
typedef struct plugin_state
{
} plugin_state;

extern "C"
const char* plugin_get_required_api_version()
{
	return pl_required_api_version;
}

extern "C"
const char* plugin_get_name()
{
	// Add a random-ish suffix to the end, as some tests load
	// multiple copies of this plugin
	snprintf(pl_name, sizeof(pl_name)-1, "%s%ld", pl_name_base, random());
	return pl_name;
}

extern "C"
const char* plugin_get_description()
{
	return pl_desc;
}

extern "C"
const char* plugin_get_contact()
{
	return pl_contact;
}

extern "C"
const char* plugin_get_version()
{
	return pl_version;
}

extern "C"
const char* plugin_get_extract_event_sources()
{
	return pl_extract_sources;
}

extern "C"
const char* plugin_get_fields()
{
	return pl_fields;
}

extern "C"
const char* plugin_get_last_error(ss_plugin_t* s)
{
	return NULL;
}

static const char* table_type_names[] = {
	"int64",
	"uint64",
	"string",
};

extern "C"
ss_plugin_t* plugin_init(const char* config, int32_t* rc, ss_plugin_owner_t* o, plugin_table_init_api* table_init)
{
	uint32_t ntables = 0;
	auto tableinfos = table_init->list_tables(o, &ntables);

	printf("PLUGIN INIT\n");
	printf("PRINTING ALL TABLES IN REGISTRY\n");
	printf("%d tables:\n", ntables);
	for (uint32_t i = 0; i < ntables; i++)
	{
		auto t = table_init->get_table(o, tableinfos[i].name, tableinfos[i].key_type);
		auto size = table_init->read_api.get_size(t);
		printf("  %s (key: %s, size: %d)\n", tableinfos[i].name, table_type_names[tableinfos[i].key_type], size);

		// adding a custom field dynamically
		table_init->field_api.add_field(t, "proc_hash", ss_plugin_table_type::STRING);

		uint32_t nfields;
		auto fieldinfos = table_init->field_api.list_fields(t, &nfields);
		for (uint32_t j = 0; j < nfields; j++)
		{
			printf("    %s: %s\n", fieldinfos[j].name, table_type_names[fieldinfos[j].field_type]);
		}
	}

	// create new thread with tid 101
	ss_plugin_table_data data;		
	auto thread_t = table_init->get_table(o, "simple_table", ss_plugin_table_type::UINT64);

	auto new_thread = table_init->write_api.create_entry(thread_t);
	data.u64 = 101;
	new_thread = table_init->write_api.add_entry(thread_t, &data, new_thread);

	// fields
	// auto pid_field = table_init->field_api.get_field(thread_t, "pid", ss_plugin_table_type::INT64);
	// auto exe_field = table_init->field_api.get_field(thread_t, "exe", ss_plugin_table_type::STRING);
	auto hash_field = table_init->field_api.get_field(thread_t, "proc_hash", ss_plugin_table_type::STRING);

	// write some data in the new thread
	// data.u64 = 1000;
	// table_init->write_api.write_entry_field(thread_t, new_thread, pid_field, &data);
	// data.str = "python3";
	// table_init->write_api.write_entry_field(thread_t, new_thread, exe_field, &data);
	data.str = "deadbeef";
	table_init->write_api.write_entry_field(thread_t, new_thread, hash_field, &data);

	// uint64_t iterations = 10000000;
	// auto start = std::chrono::steady_clock::now();
	// for (uint64_t i = 0; i < iterations; i++)
	{
		printf("READING ENTRY IN THREAD TABLE\n");
		auto size = table_init->read_api.get_size(thread_t);
		printf("table size size: %d\n", size);
		
		data.u64 = 101;
		auto e = table_init->read_api.get_entry(thread_t, &data);
		if (e)
		{
			// table_init->read_api.read_entry_field(thread_t, e, pid_field, &data);
			// printf("pid: %ld, ", data.s64);
			// table_init->read_api.read_entry_field(thread_t, e, exe_field, &data);
			// printf("exe: '%s', ", data.str);
			table_init->read_api.read_entry_field(thread_t, e, hash_field, &data);
			printf("hash: '%s'\n", data.str);
		}

		printf("CLEARING THREAD TABLE\n");
		table_init->write_api.clear(thread_t);
		size = table_init->read_api.get_size(thread_t);
		printf("table size size: %d\n", size);
	}
	
	// auto end = std::chrono::steady_clock::now();
	// auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
	// printf("elapsed time in nanoseconds: %ld\n", (uint64_t) elapsed);
	// printf("nanoseconds/op: %f\n", (double) elapsed / (double) iterations);

	plugin_state *ret = new plugin_state();
	*rc = SS_PLUGIN_SUCCESS;
	return ret;
}

extern "C"
void plugin_destroy(ss_plugin_t* s)
{
	plugin_state *ps = (plugin_state *) s;

	delete(ps);
}

extern "C"
int32_t plugin_extract_fields(ss_plugin_t *s, const ss_plugin_event *evt, uint32_t num_fields, ss_plugin_extract_field *fields)
{
	return SS_PLUGIN_SUCCESS;
}
