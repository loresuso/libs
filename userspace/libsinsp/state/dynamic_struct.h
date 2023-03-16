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
     * @brief An accessor for accessing a dynamic field of a struct.
     * @tparam T Type of the field.
     */
    template<typename T> struct accessor_t { size_t index = 0; };

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
            return field_info(
                sizeof(T), index, name,
                [](void* buf)
                {
                    std::allocator<T>().construct(reinterpret_cast<T*>(buf));
                },
                [](void* buf)
                {
                    std::allocator<T>().destroy(reinterpret_cast<T*>(buf));
                },
                typeid(T));
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

        const std::type_info* info() const
        {
            return m_info;
        }

        size_t size() const
        {
            return m_size;
        }

        /**
         * @brief Returns an accessor for the given field, that can be used
         * to access the field's memory in all instances of structs
         * where the field is defined.
         * 
         * @tparam T Type of the field.
         * @return accessor_t<T> Memory accessor for the field.
         */
        template<typename T> 
        accessor_t<T> accessor() const
        {
            if (typeid(T) != *m_info)
            {
                throw std::runtime_error("extension field accessed with incompatible types: " + m_name);
            }
            return accessor_t<T>{m_index};
        }

    private:
        using alloc_func_t = std::function<void(void*)>;

        field_info(size_t size, size_t index, std::string name,
            alloc_func_t cons, alloc_func_t destr, const std::type_info& info)
            : m_size(size), m_index(index), m_name(name), 
            m_construct(cons), m_destroy(destr), m_info(&info) { }

        void construct(void* p) const noexcept 
        {
            if (m_construct != nullptr) m_construct(p);
        }

        void destroy(void* p) const noexcept 
        {
            if (m_destroy != nullptr) m_destroy(p);
        }
        
        size_t m_size;
        size_t m_index;
        std::string m_name;
        alloc_func_t m_construct;
        alloc_func_t m_destroy;
        const std::type_info* m_info;

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
                if (*it->second.info() != typeid(T))
                {
                    throw std::runtime_error("multiple definitions of extension field with incompatible types: " + name);
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

        // internal optimization to ensure ordered access
        std::vector<const field_info*> m_definitions_ordered;
        friend class dynamic_struct;
    };


    dynamic_struct(const std::shared_ptr<field_info_list>& dynamic_fields)
        : m_fields_len(0), m_fields(), m_dynamic_fields(dynamic_fields) { }
    dynamic_struct(dynamic_struct&&) = default;
    dynamic_struct& operator = (dynamic_struct&&) = default;
    dynamic_struct(const dynamic_struct& s) = default;
    dynamic_struct& operator = (const dynamic_struct& s) = default;

    virtual ~dynamic_struct()
    {
        for (size_t i = 0; i < m_fields.size(); i++)
        {
            m_dynamic_fields->m_definitions_ordered[i]->destroy(m_fields[i]);
            free(m_fields[i]);
        }
    }

    /**
     * @brief Get a memory reference to a given dynamic field within a struct
     * using an accessor.
     * 
     * @tparam T Type of the field.
     * @param accessor Accessor previously-created from the field's metadata.
     * @return T& Memory reference of the field within the given struct.
     */
    template <typename T>
    inline T& get_dynamic_field(const accessor_t<T>& accessor)
    {
        // todo: add safety checks on m_dynamic_fields->m_definitions_ordered.size()
        // todo: can we chack that dynamic_fields are the same or do we trust this?
        if (accessor.index >= m_dynamic_fields->m_definitions_ordered.size())
        {
            throw std::runtime_error("dynamic_fields definition access overflow: " + std::to_string(accessor.index));
        }
        while (m_fields_len <= accessor.index)
        {
            auto def = m_dynamic_fields->m_definitions_ordered[m_fields_len];
            void* fieldbuf = malloc(def->size());
            def->construct(fieldbuf);
            m_fields.push_back(fieldbuf);
            m_fields_len++;
        }
        return *(reinterpret_cast<T*>(m_fields[accessor.index]));
    }

    /**
     * @brief Returns the list of metadata about the dynamic fields
     * defined and accessible for this struct. This needs to be shared
     * across all instances of the same struct.
     * 
     * @return field_info_list List of field metadata.
     */
    std::shared_ptr<field_info_list> dynamic_fields() const
    {
        return m_dynamic_fields;
    }

private:
    static void deleter_type(void*) { }

    size_t m_fields_len;
    std::vector<void*> m_fields;
    std::shared_ptr<field_info_list> m_dynamic_fields;
};

}; // state
}; // libsinsp
