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

#pragma once

#include "sinsp_exception.h"

#include "type_info.h"

#include <cstdlib>
#include <string>
#include <vector>
#include <unordered_map>
#include <exception>
#include <functional>
#include <memory>

namespace libsinsp {
namespace state {

/**
 * @brief A base class for structs and classes that can be extended to contains
 * new data fields dynamically at runtime and make them available for discovery
 * and access.
 */
class dynamic_struct
{
public:
    /**
     * @brief An weakly-typed accessor for accessing a dynamic field of a struct.
     * @tparam T Type of the field.
     */
    class raw_accessor_t
    {
    public:
        raw_accessor_t(size_t i, const libsinsp::state::type_info& t)
            : m_index(i), m_info(t) { };
        ~raw_accessor_t() = default;
        raw_accessor_t(raw_accessor_t&&) = default;
        raw_accessor_t& operator = (raw_accessor_t&&) = default;
        raw_accessor_t(const raw_accessor_t& s) = default;
        raw_accessor_t& operator = (const raw_accessor_t& s) = default;

        const libsinsp::state::type_info& info() const
        {
            return m_info;
        }

    private:
        size_t m_index = 0;
        libsinsp::state::type_info m_info;

        friend class dynamic_struct;
    };

    /**
     * @brief An strongly-typed accessor for accessing a dynamic field of a struct.
     * @tparam T Type of the field.
     */
    template<typename T> class accessor_t
    {
    public:
        accessor_t(size_t i): m_index(i) { };
        ~accessor_t() = default;
        accessor_t(accessor_t&&) = default;
        accessor_t& operator = (accessor_t&&) = default;
        accessor_t(const accessor_t& s) = default;
        accessor_t& operator = (const accessor_t& s) = default;

    private:
        size_t m_index = 0;

        friend class dynamic_struct;
    };

    /**
     * @brief Metadata info about a given dynamic field of a struct.
     */
    class field_info
    {
    public:
        /**
         * @brief Creates a new metadata info for a given dynamic field.
         * 
         * @tparam T Type of the field.
         * @param name Display name of the field.
         * @param index Positional index of the field among the other dynamic
         * ones supported by a given struct.
         * @return field_info Metadata info of the field.
         */
        template<typename T>
        static field_info create(const std::string& name, size_t index)
        {
            return field_info(name, index, libsinsp::state::type_info::of<T>());
        }
        ~field_info() = default;
        field_info(field_info&&) = default;
        field_info& operator = (field_info&&) = default;
        field_info(const field_info& s) = default;
        field_info& operator = (const field_info& s) = default;

        const std::string& name() const
        {
            return m_name;
        }

        const libsinsp::state::type_info& info() const
        {
            return m_info;
        }

        /**
         * @brief Returns a weakly-typed accessor for the given field, that can be used
         * to access the field's memory in all instances of structs
         * where the field is defined.
         * 
         * @return raw_accessor_t Memory accessor for the field.
         */
        raw_accessor_t raw_accessor() const
        {
            return raw_accessor_t(m_index, info());
        }

        /**
         * @brief Returns a strongly-typed accessor for the given field, that can be used
         * to access the field's memory in all instances of structs
         * where the field is defined.
         * 
         * @tparam T Type of the field.
         * @return accessor_t<T> Memory accessor for the field.
         */
        template<typename T> 
        accessor_t<T> accessor() const
        {
            auto t = libsinsp::state::type_info::of<T>();
            if (!info().is_compatible(t))
            {
                throw sinsp_exception(
                    "dynamic struct field incompatible accessor: " + m_name
                    + ", type=" + info().name() + ", access=" + t.name());
            }
            return accessor_t<T>(m_index, info());
        }

    private:
        field_info(std::string name, size_t index, const libsinsp::state::type_info& info)
            : m_name(name), m_index(index), m_info(info) { }
        
        std::string m_name;
        size_t m_index;
        libsinsp::state::type_info m_info;

        friend class dynamic_struct;
    };

    /**
     * @brief List about the dynamic fields metadata of a given struct or class
     * that are discoverable and accessible dynamically at runtime.
     * All instances of the same struct or class must share the same
     * instance of field_info_list.
     */
    class field_info_list
    {
    public:
        inline const std::unordered_map<std::string, field_info>& infos() const
        {
            return m_definitions;
        }

        /**
         * @brief Adds metadata for a new field to the list. An exception is
         * thrown if two fields are defined with the same name and with
         * incompatible types, otherwise the previous definition is returned.
         * 
         * @tparam T Type of the field.
         * @param name Display name of the field.
         * @return const field_info& Metadata about the added field, or the
         * previously-added definition in case a field with the same name and
         * type was already present.
         */
        template<typename T>
        const field_info& add_info(const std::string& name)
        {
            const auto &it = m_definitions.find(name);
            if (it != m_definitions.end())
            {
                auto t = libsinsp::state::type_info::of<T>();
                if (!it->second.info().is_compatible(t))
                {
                    throw sinsp_exception("dynamic field multiple defs with incompatible types: "
                    + name + ", prevtype=" + it->second.info().name() + ", newtype=" + t.name());
                }
                return it->second;
            }
            m_definitions.insert({ name, field_info::create<T>(name, m_definitions.size()) });
            auto& def = m_definitions.at(name);
            m_definitions_ordered.push_back(&def);
            return def;
        }

    private:
        std::unordered_map<std::string, field_info> m_definitions;
        std::vector<const field_info*> m_definitions_ordered;
        friend class dynamic_struct;
    };
    
    dynamic_struct(const std::shared_ptr<field_info_list>& dynamic_fields)
        : m_fields_len(0), m_fields(), m_dynamic_fields(dynamic_fields) { }
    
    dynamic_struct(): dynamic_struct(nullptr) { }

    dynamic_struct(dynamic_struct&&) = default;
    dynamic_struct& operator = (dynamic_struct&&) = default;
    dynamic_struct(const dynamic_struct& s) = default;
    dynamic_struct& operator = (const dynamic_struct& s) = default;

    virtual ~dynamic_struct()
    {
        if (m_dynamic_fields)
        {
            for (size_t i = 0; i < m_fields.size(); i++)
            {
                m_dynamic_fields->m_definitions_ordered[i]->info().destroy(m_fields[i]);
                free(m_fields[i]);
            }
        }
    }

    /**
     * @brief Returns the list of metadata about the dynamic fields
     * defined and accessible for this struct. This needs to be shared
     * across all instances of the same struct.
     * 
     * @return field_info_list List of field metadata.
     */
    const std::shared_ptr<field_info_list>& dynamic_fields() const
    {
        return m_dynamic_fields;
    }

    /**
     * @brief Sets the list of metadata about the dynamic fields
     * defined and accessible for this struct. This needs to be shared
     * across all instances of the same struct. The metadata list can only
     * be set once, either through set_dynamic_fields or from the
     * dynamic_struct constructor, otherwise an exception is thrown.
     */
    void set_dynamic_fields(const std::shared_ptr<field_info_list>& fields)
    {
        if (m_dynamic_fields)
        {
            throw sinsp_exception("dynamic fields can only be set once");
        }
        m_dynamic_fields = fields;
    }

    /**
     * @brief Get a memory reference to a given fixed field within a struct
     * using an weakly-typed accessor.
     * 
     * @param accessor Accessor previously-created from the field's metadata.
     * @return void* Memory pointer of the field within the given struct.
     */
    inline void* get_dynamic_field(const raw_accessor_t& a)
    {
        return _get_dynamic_field(a.m_index);
    }

    /**
     * @brief Get a memory reference to a given fixed field within a struct
     * using an strongly-typed accessor.
     * 
     * @tparam T Type of the field.
     * @param accessor Accessor previously-created from the field's metadata.
     * @return T& Memory reference of the field within the given struct.
     */
    template <typename T>
    inline T& get_dynamic_field(const accessor_t<T>& a)
    {
        return *(reinterpret_cast<T*>(_get_dynamic_field(a.m_index)));
    }

private:
    inline void* _get_dynamic_field(size_t index)
    {
        if (!m_dynamic_fields)
        {
            throw sinsp_exception("dynamic struct has null field definitions");
        }
        // todo: add safety checks on m_dynamic_fields->m_definitions_ordered.size()
        // todo: can we chack that dynamic_fields are the same or do we trust this?
        if (index >= m_dynamic_fields->m_definitions_ordered.size())
        {
            throw sinsp_exception("dynamic struct access overflow: " + std::to_string(index));
        }
        while (m_fields_len <= index)
        {
            auto def = m_dynamic_fields->m_definitions_ordered[m_fields_len];
            void* fieldbuf = malloc(def->info().size());
            def->info().construct(fieldbuf);
            m_fields.push_back(fieldbuf);
            m_fields_len++;
        }
        return m_fields[index];
    }

    size_t m_fields_len;
    std::vector<void*> m_fields;
    std::shared_ptr<field_info_list> m_dynamic_fields;
};

}; // state
}; // libsinsp
