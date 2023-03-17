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

static inline ss_plugin_table_type type_info_to_plugin_table_type(const libsinsp::state::type_info& i)
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

// a table view that wraps a sinsp C++ libsinsp::state::table implementation
class sinsp_table_api_view: public sinsp_plugin::table_api_view
{
public:
    sinsp_table_api_view() = delete;
    virtual ~sinsp_table_api_view() = default;
    sinsp_table_api_view(sinsp_table_api_view&&) = default;
    sinsp_table_api_view& operator = (sinsp_table_api_view&&) = default;
    sinsp_table_api_view(const sinsp_table_api_view& s) = delete;
    sinsp_table_api_view& operator = (const sinsp_table_api_view& s) = delete;

    template <typename T> explicit sinsp_table_api_view(libsinsp::state::table<T>* t)
        : m_key_type(type_info_to_plugin_table_type(t->key_info())), m_table(t) { }

    ss_plugin_table_fieldinfo* list_fields(uint32_t* nfields) override
    {
        m_field_infos.clear();
        for (auto& info : m_table->fixed_fields().infos())
        {
            ss_plugin_table_fieldinfo i;
            i.name = info.second.name().c_str();
            i.field_type = type_info_to_plugin_table_type(info.second.info());
            m_field_infos.push_back(i);
        }
        for (auto& info : m_table->dynamic_fields()->infos())
        {
            ss_plugin_table_fieldinfo i;
            i.name = info.second.name().c_str();
            i.field_type = type_info_to_plugin_table_type(info.second.info());
            m_field_infos.push_back(i);
        }
        *nfields = m_field_infos.size();
        return m_field_infos.data();
    }

    ss_plugin_table_field_t* get_field(const char* name, ss_plugin_table_type data_type) override
    {
        auto it = m_field_accessors.find(name);
        if (it != m_field_accessors.end())
        {
            return static_cast<ss_plugin_table_field_t*>(it->second.get());
        }

        // todo(jasondellaluce): check that there are no fixed and dynamic fields with same name
        auto fixed_it = m_table->fixed_fields().infos().find(name);
        if (fixed_it != m_table->fixed_fields().infos().end())
        {
            if (data_type != type_info_to_plugin_table_type(fixed_it->second.info()))
            {
                throw sinsp_exception("incompatible data types for field: " + std::string(name));
            }
            auto acc = fixed_it->second.raw_accessor();
            m_field_accessors[name] = std::unique_ptr<field_accessor_t>(new field_accessor_t(acc));
            return m_field_accessors[name].get();
        }

        auto dyn_it = m_table->dynamic_fields()->infos().find(name);
        if (dyn_it != m_table->dynamic_fields()->infos().end())
        {
            if (data_type != type_info_to_plugin_table_type(dyn_it->second.info()))
            {
                throw sinsp_exception("incompatible data types for field: " + std::string(name));
            }
            auto acc = dyn_it->second.raw_accessor();
            m_field_accessors[name] = std::unique_ptr<field_accessor_t>(new field_accessor_t(acc));
            return m_field_accessors[name].get();
        }
        return nullptr;
    }

    ss_plugin_table_field_t* add_field(const char* name, ss_plugin_table_type data_type) override
    {
        switch (data_type)
        {
            case ss_plugin_table_type::INT64:
                m_table->dynamic_fields()->add_info<int64_t>(name);
                break;
            case ss_plugin_table_type::UINT64:
                m_table->dynamic_fields()->add_info<uint64_t>(name);
                break;
            case ss_plugin_table_type::STRING:
                m_table->dynamic_fields()->add_info<std::string>(name);
                break;
            default:
                // todo(jasondellaluce): handle other key types and throw errors
                throw sinsp_exception("can't convert plugin table type to type info: " + std::to_string(data_type));
        }
        return get_field(name, data_type);
    }
    
    const char* get_name() override
    {
        return m_table->name().c_str();
    }

    uint32_t get_size() override
    {
        return m_table->entries_count();
    }

    ss_plugin_table_entry_t* get_entry(const ss_plugin_table_data* key) override
    {
        switch (m_key_type)
        {
            case ss_plugin_table_type::INT64:
                return (ss_plugin_table_entry_t*) static_cast<libsinsp::state::table<int64_t>*>(m_table)->get_entry(key->s64);
            case ss_plugin_table_type::UINT64:
                return (ss_plugin_table_entry_t*) static_cast<libsinsp::state::table<uint64_t>*>(m_table)->get_entry(key->u64);
            case ss_plugin_table_type::STRING:
                return (ss_plugin_table_entry_t*) static_cast<libsinsp::state::table<std::string>*>(m_table)->get_entry(key->str);
            default:
                // todo(jasondellaluce): handle other key types and throw errors
                ASSERT(false);
                return nullptr;
        }
    }

    bool foreach_entry(bool (*iterator)(ss_plugin_table_entry_t*)) override
    {
        auto _iterator = [iterator](libsinsp::state::table_entry *e)
        {
            return iterator(static_cast<ss_plugin_table_entry_t*>(e));
        };
        switch (m_key_type)
        {
            case ss_plugin_table_type::INT64:
                return (ss_plugin_table_entry_t*) static_cast<libsinsp::state::table<int64_t>*>(m_table)->foreach_entry(_iterator);
            case ss_plugin_table_type::UINT64:
                return (ss_plugin_table_entry_t*) static_cast<libsinsp::state::table<uint64_t>*>(m_table)->foreach_entry(_iterator);
            case ss_plugin_table_type::STRING:
                return (ss_plugin_table_entry_t*) static_cast<libsinsp::state::table<std::string>*>(m_table)->foreach_entry(_iterator);
            default:
                // todo(jasondellaluce): handle other key types and throw errors
                ASSERT(false);
                return false;
        }
    }

    void read_entry_field(ss_plugin_table_entry_t* _e, const ss_plugin_table_field_t* f, ss_plugin_table_data* out) override
    {
        auto acc = static_cast<const field_accessor_t*>(f);
        void* p = acc->access(static_cast<libsinsp::state::table_entry*>(_e));
        switch (acc->info().kind())
        {
            case libsinsp::state::type_info::kind_t::INT64:
                out->s64 = *((int64_t*) p);
                break;
            case libsinsp::state::type_info::kind_t::UINT64:
                out->u64 = *((uint64_t*) p);
                break;
            case libsinsp::state::type_info::kind_t::STRING:
                // note: we support both std::string and const char*
                out->str = (acc->info().size() == sizeof(std::string))
                    ? ((std::string*) p)->c_str()
                    : *((const char**) p);
                break;
            default:
                // todo(jasondellaluce): handle other key types and throw errors
                ASSERT(false);
                break;
        }
    }

    void clear() override
    {
        m_table->clear_entries();
    }

    bool erase_entry(const ss_plugin_table_data* key) override
    {
        switch (m_key_type)
        {
            case ss_plugin_table_type::INT64:
                return static_cast<libsinsp::state::table<int64_t>*>(m_table)->erase_entry(key->s64);
            case ss_plugin_table_type::UINT64:
                return static_cast<libsinsp::state::table<uint64_t>*>(m_table)->erase_entry(key->u64);
            case ss_plugin_table_type::STRING:
                return static_cast<libsinsp::state::table<std::string>*>(m_table)->erase_entry(key->str);
            default:
                // todo(jasondellaluce): handle other key types and throw errors
                ASSERT(false);
                break;
        }
        return false;
    }

    ss_plugin_table_entry_t* create_entry() override
    {
        // todo(jasondellaluce): find a better way to drag around a unique_ptr.
        // if someone creates an entry but don't add it into the table,
        // then it is a memory leak. We can also consider forbidding this.
        libsinsp::state::table_entry* ret = nullptr;
        switch (m_key_type)
        {
            case ss_plugin_table_type::INT64:
                ret = static_cast<libsinsp::state::table<int64_t>*>(m_table)->new_entry().release();
                break;
            case ss_plugin_table_type::UINT64:
                ret =  static_cast<libsinsp::state::table<uint64_t>*>(m_table)->new_entry().release();
                break;
            case ss_plugin_table_type::STRING:
                ret =  static_cast<libsinsp::state::table<std::string>*>(m_table)->new_entry().release();
                break;
            default:
                // todo(jasondellaluce): handle other key types and throw errors
                ASSERT(false);
                break;
        }
        return static_cast<ss_plugin_table_entry_t*>(ret);
    }

    ss_plugin_table_entry_t* add_entry(const ss_plugin_table_data* key, ss_plugin_table_entry_t* entry) override
    {
        libsinsp::state::table_entry* ret = nullptr;
        auto e = std::unique_ptr<libsinsp::state::table_entry>(
            static_cast<libsinsp::state::table_entry*>(entry));
        switch (m_key_type)
        {
            case ss_plugin_table_type::INT64:
                ret = static_cast<libsinsp::state::table<int64_t>*>(m_table)->add_entry(key->s64, std::move(e));
                break;
            case ss_plugin_table_type::UINT64:
                ret = static_cast<libsinsp::state::table<uint64_t>*>(m_table)->add_entry(key->u64, std::move(e));
                break;
            case ss_plugin_table_type::STRING:
                ret = static_cast<libsinsp::state::table<std::string>*>(m_table)->add_entry(key->str, std::move(e));
                break;
            default:
                // todo(jasondellaluce): handle other key types and throw errors
                ASSERT(false);
                break;
        }
        return static_cast<ss_plugin_table_entry_t*>(ret);
    }

    void write_entry_field(ss_plugin_table_entry_t* _e, const ss_plugin_table_field_t* f, const ss_plugin_table_data* in) override
    {
        auto acc = static_cast<const field_accessor_t*>(f);
        void* p = acc->access(static_cast<libsinsp::state::table_entry*>(_e));
        switch (acc->info().kind())
        {
            case libsinsp::state::type_info::kind_t::INT64:
                *((int64_t*) p) = in->s64;
                break;
            case libsinsp::state::type_info::kind_t::UINT64:
                *((uint64_t*) p) = in->u64;
                break;
            case libsinsp::state::type_info::kind_t::STRING:
                // note: we support both std::string and const char*
                if (acc->info().size() == sizeof(std::string))
                {
                    ((std::string*) p)->assign(in->str);
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

private:
    // field accessor wrapper that works with both dynamic and fixed fields
    struct field_accessor_t
    {
        field_accessor_t(const libsinsp::state::dynamic_struct::raw_accessor_t& a)
            : dynamic(true), fix_accessor(0, a.info()), dyn_accessor(a) {}

        field_accessor_t(const libsinsp::state::fixed_struct::raw_accessor_t& a)
            : dynamic(false), fix_accessor(a), dyn_accessor(0, a.info()) {}

        inline void* access(libsinsp::state::table_entry* s) const
        {
            return dynamic
                ? s->get_dynamic_field(dyn_accessor)
                : s->get_fixed_field(fix_accessor);
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
    std::unordered_map<std::string, std::unique_ptr<field_accessor_t>> m_field_accessors;
};

ss_plugin_table_t* sinsp_plugin::table_api_get_table(ss_plugin_owner_t *o, const char *name, ss_plugin_table_type k)
{
	auto t = static_cast<sinsp_plugin*>(o);
	auto it = t->m_table_views.find(name);
	if (it == t->m_table_views.end())
	{
		switch (k)
		{
			case ss_plugin_table_type::INT64:
				t->m_table_views[name] = table_get_api_view<int64_t>(t->m_table_registry->get_table<int64_t>(name));
				break;
			case ss_plugin_table_type::UINT64:
				t->m_table_views[name] = table_get_api_view<uint64_t>(t->m_table_registry->get_table<uint64_t>(name));
				break;
			case ss_plugin_table_type::STRING:
                // todo(jasondellaluce): how do we handle the const char* case? Do we really want to support it?
				t->m_table_views[name] = table_get_api_view<std::string>(t->m_table_registry->get_table<std::string>(name));
				break;
			default:
				throw sinsp_exception("can't convert plugin table type to type info: " + std::to_string(k));
		}
	}
	return t->m_table_views[name].get();
}

ss_plugin_table_info* sinsp_plugin::table_api_list_tables(ss_plugin_owner_t* o, uint32_t* ntables)
{
	auto t = static_cast<sinsp_plugin*>(o);
	t->m_table_list.clear();

	for (const auto &d : t->m_table_registry->tables())
	{
		ss_plugin_table_info info;
		info.name = d.second->name().c_str();
		info.key_type = type_info_to_plugin_table_type(d.second->key_info());
		t->m_table_list.push_back(info);
	}

	*ntables = t->m_table_list.size();
	return t->m_table_list.data();
}

template <typename T>
std::unique_ptr<sinsp_plugin::table_api_view> sinsp_plugin::table_get_api_view(libsinsp::state::table<T>* t)
{
    return std::unique_ptr<sinsp_plugin::table_api_view>(new sinsp_table_api_view(t));
}
