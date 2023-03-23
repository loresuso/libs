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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "../userspace/plugin/plugin_api.h"

#include <chrono>
#include <thread>
#include <sstream>

static const char* open_count_fname = "open-evt-count";
static uint16_t open_evts[] = {2, 3, 102, 103, 306, 307, 326, 327, 336, 337};

static const char *pl_required_api_version = PLUGIN_API_VERSION_STR;
static uint32_t    pl_id                   = 999;
static const char *pl_name                 = "test_source";
static const char *pl_desc                 = "Test Plugin For Regression Tests";
static const char *pl_contact              = "github.com/falcosecurity/falco";
static const char *pl_version              = "0.1.0";
static const char *pl_event_source         = "syscall";
static const char *pl_fields               = "[" \
    "{\"type\": \"uint64\", \"name\": \"test.is_open\", \"desc\": \"Value is 1 if event is of open family\"}," \
    "{\"type\": \"uint64\", \"name\": \"test.count_open\", \"desc\": \"Counts event is of open family for each thread\"}," \
    "{\"type\": \"string\", \"name\": \"test.procname\", \"desc\": \"Name of the process\"}" \
    "]";

// This struct represents the state of a plugin. Just has a placeholder string value.
typedef struct plugin_state
{
    ss_plugin_table_t* thread_table;
    ss_plugin_table_field_t* opencount_field;
    ss_plugin_table_field_t* procname_field;
    uint64_t u64storage;
    ss_plugin_table_data tdatastorage;
} plugin_state;

typedef struct instance_state
{
    uint8_t evt_buf[2048];
    ss_plugin_event evt;
} instance_state;

extern "C"
const char* plugin_get_required_api_version()
{
	return pl_required_api_version;
}

extern "C"
uint32_t plugin_get_id()
{
	return pl_id;
}

extern "C"
const char* plugin_get_name()
{
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
const char* plugin_get_event_source()
{
	return pl_event_source;
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

extern "C"
ss_plugin_t* plugin_init(const char* config, int32_t* rc, ss_plugin_owner_t* o, const plugin_table_init_api* table_init)
{
	// Note: Using new/delete is okay, as long as the plugin
	// framework is not deleting the memory.
	plugin_state *ret = new plugin_state();
    ret->thread_table = table_init->get_table(o, "syscall_threads", ss_plugin_table_type::UINT64);
    if (!ret->thread_table)
    {
        fprintf(stderr, "Can't get thread table\n");
        *rc = SS_PLUGIN_FAILURE;
        return ret;
    }

    ret->opencount_field = table_init->field_api.add_field(
        ret->thread_table, open_count_fname, ss_plugin_table_type::UINT64);
    if (!ret->opencount_field)
    {
        fprintf(stderr, "Can't add open count field to thread table\n");
        *rc = SS_PLUGIN_FAILURE;
        return ret;
    }

    ret->procname_field = table_init->field_api.get_field(
        ret->thread_table, "exe", ss_plugin_table_type::STRING);
    if (!ret->procname_field)
    {
        fprintf(stderr, "Can't get proc name field to thread table\n");
        *rc = SS_PLUGIN_FAILURE;
        return ret;
    }

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
ss_instance_t* plugin_open(ss_plugin_t* s, const char* params, int32_t* rc)
{
	// Note: Using new/delete is okay, as long as the plugin
	// framework is not deleting the memory.
	instance_state *ret = new instance_state();
    ret->evt.evt.syscall = (ss_plugin_syscall_event *) &ret->evt_buf;
	*rc = SS_PLUGIN_SUCCESS;

	return ret;
}

extern "C"
void plugin_close(ss_plugin_t* s, ss_instance_t* i)
{
	instance_state *istate = (instance_state *) i;

	delete(istate);
}

extern "C"
int32_t plugin_next_batch(ss_plugin_t* s, ss_instance_t* i, uint32_t *nevts, ss_plugin_event **evts)
{
    instance_state *istate = (instance_state *) i;

    *nevts = 1;
    *evts = &istate->evt;
    istate->evt.evt.syscall->type = 3; // PPME_SYSCALL_OPEN_X
    istate->evt.evt.syscall->tid = 1;
    istate->evt.evt.syscall->ts = std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::high_resolution_clock::now().time_since_epoch()).count();
    istate->evt.evt.syscall->len = sizeof(ss_plugin_syscall_event);
    istate->evt.evt.syscall->nparams = 6;

    uint8_t* parambuf = &istate->evt_buf[0] + sizeof(ss_plugin_syscall_event);

    // lenghts
    *((uint16_t*) parambuf) = sizeof(uint64_t);
    parambuf += sizeof(uint16_t);
    *((uint16_t*) parambuf) = strlen("/tmp/the_file") + 1;
    parambuf += sizeof(uint16_t);
    *((uint16_t*) parambuf) = sizeof(uint32_t);
    parambuf += sizeof(uint16_t);
    *((uint16_t*) parambuf) = sizeof(uint32_t);
    parambuf += sizeof(uint16_t);
    *((uint16_t*) parambuf) = sizeof(uint32_t);
    parambuf += sizeof(uint16_t);
    *((uint16_t*) parambuf) = sizeof(uint64_t);
    parambuf += sizeof(uint16_t);

    // params
    *((uint64_t*) parambuf) = 3;
    parambuf += sizeof(uint64_t);
    strcpy((char*) parambuf, "/tmp/the_file");
    parambuf += strlen("/tmp/the_file") + 1;
    *((uint32_t*) parambuf) = ((1 << 0) | (1 << 1));
    parambuf += sizeof(uint32_t);
    *((uint32_t*) parambuf) = 0;
    parambuf += sizeof(uint32_t);
    *((uint32_t*) parambuf) = 5;
    parambuf += sizeof(uint32_t);
    *((uint64_t*) parambuf) = 123;
    parambuf += sizeof(uint64_t);

    istate->evt.evt.syscall->len += parambuf - (&istate->evt_buf[0] + sizeof(ss_plugin_syscall_event));
	return SS_PLUGIN_SUCCESS;
}

// This plugin does not implement plugin_next_batch, due to the lower
// overhead of calling C functions from the plugin framework compared
// to calling Go functions.

extern "C"
const char *plugin_event_to_string(ss_plugin_t *s, const uint8_t *data, uint32_t datalen)
{
	return "";
}

extern "C"
int32_t plugin_extract_fields(ss_plugin_t *s, const ss_plugin_event *evt, uint32_t num_fields, ss_plugin_extract_field *fields, const plugin_table_read_api* table_read)
{
    plugin_state *ps = (plugin_state *) s;
    ss_plugin_table_entry_t *evt_thread;

    for (uint32_t i = 0; i < num_fields; i++)
    {
        switch(fields[i].field_id)
        {
            case 0:
                ps->u64storage = 0;
                for (int j = 0; j < sizeof(open_evts) / sizeof(uint16_t); j++)
                {
                    if (open_evts[j] == evt->evt.syscall->type)
                    {
                        ps->u64storage = 1;
                    }
                }
                fields[i].res.u64 = &ps->u64storage;
                fields[i].res_len = 1;
                break;
            case 1:
                ps->u64storage = 0;
                ps->tdatastorage.u64 = evt->evt.syscall->tid;
                evt_thread = table_read->get_entry(ps->thread_table, &ps->tdatastorage);
                if (!evt_thread)
                {
                    return SS_PLUGIN_FAILURE;
                }
                table_read->read_entry_field(ps->thread_table, evt_thread, ps->opencount_field, &ps->tdatastorage);
                fields[i].res.u64 = &ps->tdatastorage.u64;
                fields[i].res_len = 1;
                break;
            case 2:
                ps->u64storage = 0;
                ps->tdatastorage.u64 = evt->evt.syscall->tid;
                evt_thread = table_read->get_entry(ps->thread_table, &ps->tdatastorage);
                if (!evt_thread)
                {
                    return SS_PLUGIN_FAILURE;
                }
                table_read->read_entry_field(ps->thread_table, evt_thread, ps->procname_field, &ps->tdatastorage);
                fields[i].res.str = &ps->tdatastorage.str;
                fields[i].res_len = 1;
                break;
            default:
                return SS_PLUGIN_FAILURE;
        }
    }
	return SS_PLUGIN_SUCCESS;
}

extern "C"
uint16_t* plugin_get_parse_event_types(uint32_t* num_types)
{
    static uint16_t types[] = {306, 307};
    *num_types = sizeof(types) / sizeof(uint16_t);
    return &types[0];
}

extern "C"
ss_plugin_rc plugin_parse_event(ss_plugin_t *s, const ss_plugin_event *evt, const plugin_table_read_api* table_read, const plugin_table_write_api* table_write)
{
    plugin_state *ps = (plugin_state *) s;

    if (evt->evt.syscall->type == 306 || evt->evt.syscall->type == 307)
    {
        ps->tdatastorage.u64 = evt->evt.syscall->tid;
        auto evt_thread = table_read->get_entry(ps->thread_table, &ps->tdatastorage);
        if (!evt_thread)
        {
            return SS_PLUGIN_FAILURE;
        }

        table_read->read_entry_field(ps->thread_table, evt_thread, ps->opencount_field, &ps->tdatastorage);
        ps->tdatastorage.u64++;
        table_write->write_entry_field(ps->thread_table, evt_thread, ps->opencount_field, &ps->tdatastorage);  

        return SS_PLUGIN_SUCCESS; 
    }
    return SS_PLUGIN_SUCCESS;
}
