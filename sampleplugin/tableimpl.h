#pragma once

#include "../userspace/plugin/plugin_api.h"

#include <cstring>
#include <string>
#include <vector>
#include <memory>
#include <unordered_map>

struct tableimpl
{
    struct entry
    {
        virtual ~entry()
        {
            for (auto &p : data)
            {
                delete p;
            }
        }
        std::vector<ss_plugin_table_data*> data;
    };

    std::string name;
    std::vector<ss_plugin_table_fieldinfo> fields;
    std::vector<std::string> strings;
    std::unordered_map<uint64_t, entry> entries;
};

static const char* get_name(ss_plugin_table_t* _t)
{
    auto t = static_cast<tableimpl*>(_t);
	return t->name.c_str();
}

static uint32_t get_size(ss_plugin_table_t* _t)
{
	auto t = static_cast<tableimpl*>(_t);
	return t->entries.size();
}

static ss_plugin_table_fieldinfo* list_fields(ss_plugin_table_t* _t, uint32_t* nfields)
{
    auto t = static_cast<tableimpl*>(_t);

	*nfields = (uint32_t) t->fields.size();
	return t->fields.data();
}

static ss_plugin_table_field_t* get_field(ss_plugin_table_t* _t, const char* name, ss_plugin_table_type data_type)
{
    auto t = static_cast<tableimpl*>(_t);

	for (size_t i = 0; i < t->fields.size(); i++)
	{
		if (strcmp(t->fields[i].name, name) == 0)
		{
			return (ss_plugin_table_field_t*) i;
		}
	}
	return nullptr;
}

static ss_plugin_table_field_t* add_field(ss_plugin_table_t* _t, const char* name, ss_plugin_table_type data_type)
{
    auto t = static_cast<tableimpl*>(_t);

    t->strings.push_back(name);
    ss_plugin_table_fieldinfo f;
    f.name = t->strings[t->strings.size() - 1].c_str();
    f.field_type = data_type;
    t->fields.push_back(f);
    return &t->fields[t->fields.size() - 1];
}

static ss_plugin_table_entry_t *get_entry(ss_plugin_table_t *_t, const ss_plugin_table_data *key)
{
    auto t = static_cast<tableimpl*>(_t);
    auto it = t->entries.find(key->u64);
    if (it != t->entries.end())
    {
        return static_cast<ss_plugin_table_entry_t*>(&it->second);
    }
    return nullptr;
}

static void read_entry_field(ss_plugin_table_t *_t, ss_plugin_table_entry_t *_e, const ss_plugin_table_field_t *_f, ss_plugin_table_data *out)
{
    auto t = static_cast<tableimpl*>(_t);
    auto e = static_cast<tableimpl::entry*>(_e);
    auto f = size_t (_f);
    while (e->data.size() <= f)
    {
        e->data.push_back(new ss_plugin_table_data());
    }
    memcpy(out, e->data[f], sizeof(ss_plugin_table_data));
}

static void clear(ss_plugin_table_t *_t)
{
    auto t = static_cast<tableimpl*>(_t);
    t->entries.clear();
}

static bool erase_entry(ss_plugin_table_t *_t, const ss_plugin_table_data *key)
{
    auto t = static_cast<tableimpl*>(_t);
    auto it = t->entries.find(key->u64);
    if (it != t->entries.end())
    {
        t->entries.erase(key->u64);
        return true;
    }
    return false;
}

static ss_plugin_table_entry_t *create_entry(ss_plugin_table_t *t)
{
    return static_cast<ss_plugin_table_entry_t*>(new tableimpl::entry());
}

static ss_plugin_table_entry_t *add_entry(ss_plugin_table_t *_t, const ss_plugin_table_data *key, ss_plugin_table_entry_t *_e)
{
    auto t = static_cast<tableimpl*>(_t);
    auto e = static_cast<tableimpl::entry*>(_e);
    t->entries.insert({ key->u64, *e });
    delete e;
    return &t->entries[key->u64];
}

static void write_entry_field(ss_plugin_table_t* _t, ss_plugin_table_entry_t* _e, const ss_plugin_table_field_t* _f, const ss_plugin_table_data* in)
{
    auto t = static_cast<tableimpl*>(_t);
    auto e = static_cast<tableimpl::entry*>(_e);
    auto f = size_t (_f);
    while (e->data.size() <= f)
    {
        e->data.push_back(new ss_plugin_table_data());
    }
    memcpy(e->data[f], in, sizeof(ss_plugin_table_data));
}

plugin_table_input new_table(const char* name)
{
    auto t = new tableimpl();
    t->name = name;
    return plugin_table_input {
        .name = t->name.c_str(),
        .table = t,
        .key_type = UINT64,
        .field_api = {
            .list_fields = list_fields,
            .get_field = get_field,
            .add_field = add_field,
        },
        .read_api = {
            .get_name = get_name,
            .get_size = get_size,
            .get_entry = get_entry,
            .read_entry_field = read_entry_field,
        },
        .write_api = {
            .clear = clear,
            .erase_entry = erase_entry,
            .create_entry = create_entry,
            .add_entry = add_entry,
            .write_entry_field = write_entry_field,
        }
    };
}

