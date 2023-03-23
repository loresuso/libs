/*
Copyright (C) 2023 The Falco Authors.

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

#include "plugin.h"

// todo(jasondellaluce): since we now have C++17, we can use string_view to improve performance around here
// todo(jaondellaluce): can we avoid all the type casts at least on the map key?

static inline ss_plugin_table_type as_plugin_table_type(const libsinsp::state::type_info& i)
{
    switch(i.kind())
    {
        case libsinsp::state::type_info::kind_t::INT64:
            return ss_plugin_table_type::INT64;
        case libsinsp::state::type_info::kind_t::UINT64:
            return ss_plugin_table_type::UINT64;
        case libsinsp::state::type_info::kind_t::STRING:
            return ss_plugin_table_type::STRING;
        default:
            // todo(jasondellaluce): handle other key types and throw errors
            throw sinsp_exception("can't convert type info to plugin table type: " + std::string(i.name()));
    }
}

// Wraps a plugin-owned table and makes it usable in the table registry
// to be accessed by other plugins. Accessing a plugin-owned table from
// a libsinsp' component is not fully supported for memory safety issues.
template <typename KeyType>
class plugin_table_wrap: public libsinsp::state::table<KeyType>
{
public:
    plugin_table_wrap(const plugin_table_input* i)
        : m_name(i->name), m_input(*i), m_fixed_fields(),
          m_dyn_fields(std::make_shared<dyn_fields_wrap>())
    {
        auto t = libsinsp::state::type_info::of<KeyType>();
        if (m_input.key_type != as_plugin_table_type(t))
        {
            throw sinsp_exception("constrasting key definitions in plugin api table wrapper");
        }
    }

    virtual ~plugin_table_wrap() = default;
    plugin_table_wrap(plugin_table_wrap&&) = default;
    plugin_table_wrap& operator = (plugin_table_wrap&&) = default;
    plugin_table_wrap(const plugin_table_wrap& s) = delete;
    plugin_table_wrap& operator = (const plugin_table_wrap& s) = delete;

    const libsinsp::state::fixed_struct::field_info_list& fixed_fields() const override
    {
        // note: plugin table entries have only dynamic fields
        return m_fixed_fields;
    }

    std::shared_ptr<libsinsp::state::dynamic_struct::field_info_list> dynamic_fields() override
    {
        uint32_t nfields = 0;
        auto fields = m_input.field_api.list_fields(m_input.table, &nfields);
        if (m_dyn_fields->infos().size() != (size_t) nfields)
        {
            for (uint32_t i = 0; i < nfields; i++)
            {
                auto& f = fields[i];
                switch (f.field_type)
                {
                    case ss_plugin_table_type::INT64:
                        m_dyn_fields->template add_info<int64_t>(f.name);
                        break;
                    case ss_plugin_table_type::UINT64:
                        m_dyn_fields->template add_info<uint64_t>(f.name);
                        break;
                    case ss_plugin_table_type::STRING:
                        m_dyn_fields->template add_info<std::string>(f.name);
                        break;
                    default:
                        // todo(jasondellaluce): handle errors
                        ASSERT(false);
                        break;
                }
            }
        }
        return m_dyn_fields;
    }

    const std::string& name() const override
    {
        return m_name;
    }

    size_t entries_count() const override
    {
        return m_input.read_api.get_size(m_input.table);
    }

    void clear_entries() override
    {
        throw sinsp_exception("can't use plugin-defined tables from libsinsp: clear_entries");
    }

    std::unique_ptr<libsinsp::state::table_entry> new_entry() const override
    {
        throw sinsp_exception("can't use plugin-defined tables from libsinsp: new_entry");
    }

    bool foreach_entry(std::function<bool(libsinsp::state::table_entry* e)> pred) override
    {
        // todo(jasondellaluce): remove this
        return false;
    }

    libsinsp::state::table_entry* get_entry(const KeyType& key) override
    {
        throw sinsp_exception("can't use plugin-defined tables from libsinsp: get_entry");
    }

    libsinsp::state::table_entry* add_entry(const KeyType& key, std::unique_ptr<libsinsp::state::table_entry> value) override
    {
        throw sinsp_exception("can't use plugin-defined tables from libsinsp: add_entry");
    }

    bool erase_entry(const KeyType& key) override
    {
        throw sinsp_exception("can't use plugin-defined tables from libsinsp: erase_entry");
    }
    
    plugin_table_input& input()
    {
        return m_input;
    }

private:
    class dyn_fields_wrap: public libsinsp::state::dynamic_struct::field_info_list
    {
    public:
        dyn_fields_wrap() = default;
        virtual ~dyn_fields_wrap() = default;
        dyn_fields_wrap(dyn_fields_wrap&&) = default;
        dyn_fields_wrap& operator = (dyn_fields_wrap&&) = default;
        dyn_fields_wrap(const dyn_fields_wrap& s) = default;
        dyn_fields_wrap& operator = (const dyn_fields_wrap& s) = default;

        void on_after_add_info(const libsinsp::state::dynamic_struct::field_info& i) override
        {
            throw sinsp_exception("can't use plugin-defined tables from libsinsp: add dynamic field info");
        }
    };

    std::string m_name;
    plugin_table_input m_input;
    libsinsp::state::fixed_struct::field_info_list m_fixed_fields;
    std::shared_ptr<dyn_fields_wrap> m_dyn_fields;
};

// Wraps a libsinsp-owned table and makes it usable in the plugin API
struct sinsp_table_wrap
{
    sinsp_table_wrap() = delete;
    virtual ~sinsp_table_wrap() = default;
    sinsp_table_wrap(sinsp_table_wrap&&) = default;
    sinsp_table_wrap& operator = (sinsp_table_wrap&&) = default;
    sinsp_table_wrap(const sinsp_table_wrap& s) = delete;
    sinsp_table_wrap& operator = (const sinsp_table_wrap& s) = delete;

    template <typename T> explicit sinsp_table_wrap(libsinsp::state::table<T>* t)
        : m_key_type(as_plugin_table_type(t->key_info())), m_table(t) { }

    // field accessor wrapper that works with both dynamic and fixed fields
    struct field_accessor
    {
        field_accessor(const libsinsp::state::dynamic_struct::raw_accessor_t& a)
            : dynamic(true), fix_accessor(0, a.info()), dyn_accessor(a) {}

        field_accessor(const libsinsp::state::fixed_struct::raw_accessor_t& a)
            : dynamic(false), fix_accessor(a), dyn_accessor(0, a.info()) {}

        inline void* access(libsinsp::state::table_entry* s) const
        {
            return dynamic ? s->get_dynamic_field(dyn_accessor) : s->get_fixed_field(fix_accessor);
        }

        const libsinsp::state::type_info& info() const
        {
            return dynamic ? dyn_accessor.info() : fix_accessor.info();
        }

        bool dynamic;
        libsinsp::state::fixed_struct::raw_accessor_t fix_accessor;
        libsinsp::state::dynamic_struct::raw_accessor_t dyn_accessor;
    };

    ss_plugin_table_type m_key_type;
    libsinsp::state::base_table* m_table;
    std::vector<ss_plugin_table_fieldinfo> m_field_infos;
    std::unordered_map<std::string, std::unique_ptr<field_accessor>> m_field_accessors;
};

static ss_plugin_table_fieldinfo* table_api_list_fields(ss_plugin_table_t *_t, uint32_t *nfields)
{
	// todo(jasondellaluce): check for exceptions in all the ones below too
    auto t = static_cast<sinsp_table_wrap*>(_t);
    t->m_field_infos.clear();
    for (auto& info : t->m_table->fixed_fields().infos())
    {
        ss_plugin_table_fieldinfo i;
        i.name = info.second.name().c_str();
        i.field_type = as_plugin_table_type(info.second.info());
        t->m_field_infos.push_back(i);
    }
    for (auto& info : t->m_table->dynamic_fields()->infos())
    {
        ss_plugin_table_fieldinfo i;
        i.name = info.second.name().c_str();
        i.field_type = as_plugin_table_type(info.second.info());
        t->m_field_infos.push_back(i);
    }
    *nfields = t->m_field_infos.size();
    return t->m_field_infos.data();
}

static ss_plugin_table_field_t* table_api_get_field(ss_plugin_table_t* _t, const char* name, ss_plugin_table_type data_type)
{
    auto t = static_cast<sinsp_table_wrap*>(_t);
    auto it = t->m_field_accessors.find(name);
    if (it != t->m_field_accessors.end())
    {
        return static_cast<ss_plugin_table_field_t*>(it->second.get());
    }

    // todo(jasondellaluce): check that there are no fixed and dynamic fields with same name
    auto fixed_it = t->m_table->fixed_fields().infos().find(name);
    if (fixed_it != t->m_table->fixed_fields().infos().end())
    {
        if (data_type != as_plugin_table_type(fixed_it->second.info()))
        {
            throw sinsp_exception("incompatible data types for field: " + std::string(name));
        }
        auto acc = fixed_it->second.raw_accessor();
        t->m_field_accessors[name] = std::unique_ptr<sinsp_table_wrap::field_accessor>(
            new sinsp_table_wrap::field_accessor(acc));
        return t->m_field_accessors[name].get();
    }

    auto dyn_it = t->m_table->dynamic_fields()->infos().find(name);
    if (dyn_it != t->m_table->dynamic_fields()->infos().end())
    {
        if (data_type != as_plugin_table_type(dyn_it->second.info()))
        {
            throw sinsp_exception("incompatible data types for field: " + std::string(name));
        }
        auto acc = dyn_it->second.raw_accessor();
        t->m_field_accessors[name] = std::unique_ptr<sinsp_table_wrap::field_accessor>(
            new sinsp_table_wrap::field_accessor(acc));
        return t->m_field_accessors[name].get();
    }
    return nullptr;
}

static ss_plugin_table_field_t* table_api_add_field(ss_plugin_table_t* _t, const char* name, ss_plugin_table_type data_type)
{
    auto t = static_cast<sinsp_table_wrap*>(_t);
    switch (data_type)
    {
        case ss_plugin_table_type::INT64:
            t->m_table->dynamic_fields()->add_info<int64_t>(name);
            break;
        case ss_plugin_table_type::UINT64:
            t->m_table->dynamic_fields()->add_info<uint64_t>(name);
            break;
        case ss_plugin_table_type::STRING:
            t->m_table->dynamic_fields()->add_info<std::string>(name);
            break;
        default:
            // todo(jasondellaluce): handle other key types and throw errors
            throw sinsp_exception("can't convert plugin table type to type info: " + std::to_string(data_type));
    }
    return table_api_get_field(_t, name, data_type);
}

static const char* table_api_get_name(ss_plugin_table_t* _t)
{
    auto t = static_cast<sinsp_table_wrap*>(_t);
    return t->m_table->name().c_str();
}

static uint32_t table_api_get_size(ss_plugin_table_t* _t)
{
    auto t = static_cast<sinsp_table_wrap*>(_t);
	return t->m_table->entries_count();
}

static ss_plugin_table_entry_t* table_api_get_entry(ss_plugin_table_t* _t, const ss_plugin_table_data* key)
{
    auto t = static_cast<sinsp_table_wrap*>(_t);
	switch (t->m_key_type)
    {
        case ss_plugin_table_type::INT64:
            return (ss_plugin_table_entry_t*) static_cast<libsinsp::state::table<int64_t>*>(t->m_table)->get_entry(key->s64);
        case ss_plugin_table_type::UINT64:
            return (ss_plugin_table_entry_t*) static_cast<libsinsp::state::table<uint64_t>*>(t->m_table)->get_entry(key->u64);
        case ss_plugin_table_type::STRING:
            return (ss_plugin_table_entry_t*) static_cast<libsinsp::state::table<std::string>*>(t->m_table)->get_entry(key->str);
        default:
            // todo(jasondellaluce): handle other key types and throw errors
            ASSERT(false);
            return nullptr;
    }
}

static bool table_api_foreach_entry(ss_plugin_table_t* t, bool (*iterator)(ss_plugin_table_entry_t*))
{
    // todo(jasondellaluce): remove this
	return false;
}

static void table_api_read_entry_field(ss_plugin_table_t* t, ss_plugin_table_entry_t* _e, const ss_plugin_table_field_t* f, ss_plugin_table_data* out)
{
    auto acc = static_cast<const sinsp_table_wrap::field_accessor*>(f);
    void* e = acc->access(static_cast<libsinsp::state::table_entry*>(_e));
    switch (acc->info().kind())
    {
        case libsinsp::state::type_info::kind_t::INT64:
            out->s64 = *((int64_t*) e);
            break;
        case libsinsp::state::type_info::kind_t::UINT64:
            out->u64 = *((uint64_t*) e);
            break;
        case libsinsp::state::type_info::kind_t::STRING:
            // note: we support both std::string and const char*
            out->str = (acc->info().size() == sizeof(std::string))
                ? ((std::string*) e)->c_str()
                : *((const char**) e);
            break;
        default:
            // todo(jasondellaluce): handle other key types and throw errors
            ASSERT(false);
            break;
    }
}

static void table_api_clear(ss_plugin_table_t* _t)
{
    auto t = static_cast<sinsp_table_wrap*>(_t);
	t->m_table->clear_entries();
}

static bool table_api_erase_entry(ss_plugin_table_t* _t, const ss_plugin_table_data* key)
{
    auto t = static_cast<sinsp_table_wrap*>(_t);
	switch (t->m_key_type)
    {
        case ss_plugin_table_type::INT64:
            return static_cast<libsinsp::state::table<int64_t>*>(t->m_table)->erase_entry(key->s64);
        case ss_plugin_table_type::UINT64:
            return static_cast<libsinsp::state::table<uint64_t>*>(t->m_table)->erase_entry(key->u64);
        case ss_plugin_table_type::STRING:
            return static_cast<libsinsp::state::table<std::string>*>(t->m_table)->erase_entry(key->str);
        default:
            // todo(jasondellaluce): handle other key types and throw errors
            ASSERT(false);
            break;
    }
    return false;
}

static ss_plugin_table_entry_t* table_api_create_entry(ss_plugin_table_t* _t)
{
	// todo(jasondellaluce): find a better way to drag around a unique_ptr.
    // if someone creates an entry but don't add it into the table,
    // then it is a memory leak. We can also consider forbidding this.
    // todo(jasondellaluce): create a destroy_entry function
    auto t = static_cast<sinsp_table_wrap*>(_t);
    libsinsp::state::table_entry* ret = nullptr;
    switch (t->m_key_type)
    {
        case ss_plugin_table_type::INT64:
            ret = static_cast<libsinsp::state::table<int64_t>*>(t->m_table)->new_entry().release();
            break;
        case ss_plugin_table_type::UINT64:
            ret =  static_cast<libsinsp::state::table<uint64_t>*>(t->m_table)->new_entry().release();
            break;
        case ss_plugin_table_type::STRING:
            ret =  static_cast<libsinsp::state::table<std::string>*>(t->m_table)->new_entry().release();
            break;
        default:
            // todo(jasondellaluce): handle other key types and throw errors
            ASSERT(false);
            break;
    }
    return static_cast<ss_plugin_table_entry_t*>(ret);
}

static ss_plugin_table_entry_t* table_api_add_entry(ss_plugin_table_t* _t, const ss_plugin_table_data* key, ss_plugin_table_entry_t* entry)
{
    auto t = static_cast<sinsp_table_wrap*>(_t);
	libsinsp::state::table_entry* ret = nullptr;
    auto e = std::unique_ptr<libsinsp::state::table_entry>(
        static_cast<libsinsp::state::table_entry*>(entry));
    switch (t->m_key_type)
    {
        case ss_plugin_table_type::INT64:
            ret = static_cast<libsinsp::state::table<int64_t>*>(t->m_table)->add_entry(key->s64, std::move(e));
            break;
        case ss_plugin_table_type::UINT64:
            ret = static_cast<libsinsp::state::table<uint64_t>*>(t->m_table)->add_entry(key->u64, std::move(e));
            break;
        case ss_plugin_table_type::STRING:
            ret = static_cast<libsinsp::state::table<std::string>*>(t->m_table)->add_entry(key->str, std::move(e));
            break;
        default:
            // todo(jasondellaluce): handle other key types and throw errors
            ASSERT(false);
            break;
    }
    return static_cast<ss_plugin_table_entry_t*>(ret);
}

static void table_api_write_entry_field(ss_plugin_table_t* _t, ss_plugin_table_entry_t* _e, const ss_plugin_table_field_t* f, const ss_plugin_table_data* in)
{
	auto acc = static_cast<const sinsp_table_wrap::field_accessor*>(f);
    void* e = acc->access(static_cast<libsinsp::state::table_entry*>(_e));
    switch (acc->info().kind())
    {
        case libsinsp::state::type_info::kind_t::INT64:
            *((int64_t*) e) = in->s64;
            break;
        case libsinsp::state::type_info::kind_t::UINT64:
            *((uint64_t*) e) = in->u64;
            break;
        case libsinsp::state::type_info::kind_t::STRING:
            // note: we support both std::string and const char*
            if (acc->info().size() == sizeof(std::string))
            {
                ((std::string*) e)->assign(in->str);
            }
            else
            {
                // todo(jasondellaluce): sinsp is the owner, so the string
                // must be copied, but how do we determine if the previous
                // string needs to be deallocated or not?
                throw sinsp_exception("unsupported operation");
            }
            break;
        default:
            // todo(jasondellaluce): handle other key types and throw errors
            ASSERT(false);
            break;
    }
}

void sinsp_plugin::table_input_deleter::operator()(plugin_table_input* i)
{
    delete static_cast<sinsp_table_wrap*>(i->table);
    delete i;
}

template <typename T>
static std::unique_ptr<plugin_table_input, sinsp_plugin::table_input_deleter> as_table_input(libsinsp::state::table<T>* t)
{
    auto state = new sinsp_table_wrap(t);
    std::unique_ptr<plugin_table_input, sinsp_plugin::table_input_deleter> res(
        new plugin_table_input(), sinsp_plugin::table_input_deleter());

    res->table = static_cast<ss_plugin_table_t*>(state);
	res->name = state->m_table->name().c_str();
    res->key_type = state->m_key_type;
	res->field_api.list_fields = table_api_list_fields;
	res->field_api.add_field = table_api_add_field;
	res->field_api.get_field = table_api_get_field;
	res->read_api.get_name = table_api_get_name;
	res->read_api.get_size = table_api_get_size;
	res->read_api.get_entry = table_api_get_entry;
	res->read_api.foreach_entry = table_api_foreach_entry;
	res->read_api.read_entry_field = table_api_read_entry_field;
	res->write_api.clear = table_api_clear;
	res->write_api.erase_entry = table_api_erase_entry;
	res->write_api.create_entry = table_api_create_entry;
	res->write_api.add_entry = table_api_add_entry;
	res->write_api.write_entry_field = table_api_write_entry_field;
    return res;
}

template <typename T>
ss_plugin_table_t* table_api_get_table_typed(
    const std::shared_ptr<libsinsp::state::table_registry>& r,
    std::unordered_map<std::string, std::unique_ptr<plugin_table_input, sinsp_plugin::table_input_deleter>>& tables,
    const char *name)
{
    auto t = r->get_table<T>(name);

    // if a plugin is accessing a plugin-owned table, we return it as-is
    // instead of wrapping it. This is both more performant and safer from
    // a memory ownership perspective, because the other plugin is the actual
    // total owner of the table's memory. Note, even though dynamic_cast is
    // generally quite expensive, the "get_table" primitive can only be
    // used during plugin initialization, so it's not in the hot path.
    auto pt = dynamic_cast<plugin_table_wrap<T>*>(t);
    if (pt)
    {
        return &pt->input();
    }

    tables[name] = as_table_input<T>(t);
    return tables[name].get();
}

ss_plugin_table_t* sinsp_plugin::table_api_get_table(ss_plugin_owner_t *o, const char *name, ss_plugin_table_type k)
{
	auto t = static_cast<sinsp_plugin*>(o);
	auto it = t->m_tables.find(name);
	if (it == t->m_tables.end())
	{
		switch (k)
		{
			case ss_plugin_table_type::INT64:
				return table_api_get_table_typed<int64_t>(t->m_table_registry, t->m_tables, name);
			case ss_plugin_table_type::UINT64:
				return table_api_get_table_typed<uint64_t>(t->m_table_registry, t->m_tables, name);
			case ss_plugin_table_type::STRING:
                // todo(jasondellaluce): how do we handle the const char* case? Do we really want to support it?
				return table_api_get_table_typed<std::string>(t->m_table_registry, t->m_tables, name);
			default:
				throw sinsp_exception("can't convert plugin table type to type info: " + std::to_string(k));
		}
	}
    return it->second.get();
}

ss_plugin_table_info* sinsp_plugin::table_api_list_tables(ss_plugin_owner_t* o, uint32_t* ntables)
{
	auto t = static_cast<sinsp_plugin*>(o);
	t->m_table_infos.clear();

	for (const auto &d : t->m_table_registry->tables())
	{
		ss_plugin_table_info info;
		info.name = d.second->name().c_str();
		info.key_type = as_plugin_table_type(d.second->key_info());
		t->m_table_infos.push_back(info);
	}

	*ntables = t->m_table_infos.size();
	return t->m_table_infos.data();
}

void sinsp_plugin::table_api_add_table(ss_plugin_owner_t *o, plugin_table_input* i)
{
    auto p = static_cast<sinsp_plugin*>(o);
    std::unique_ptr<libsinsp::state::base_table> t;
    switch (i->key_type)
    {
        case ss_plugin_table_type::INT64:
            t.reset(p->m_table_registry->add_table(i->name,
                new plugin_table_wrap<int64_t>(i)));
            break;
        case ss_plugin_table_type::UINT64:
            t.reset(p->m_table_registry->add_table(i->name,
                new plugin_table_wrap<uint64_t>(i)));
            break;
        case ss_plugin_table_type::STRING:
            t.reset(p->m_table_registry->add_table(i->name,
                new plugin_table_wrap<std::string>(i)));
            break;
        default:
            // todo(jasondellaluce): handle errors
            assert(false);
            break;
    }
    p->m_owned_tables[i->name] = std::move(t);
}
