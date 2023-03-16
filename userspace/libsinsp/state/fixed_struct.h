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

#include <string>
#include <unordered_map>
#include <exception>

// todo(jasondellaluce): implement a base class for invoking functions as well

namespace libsinsp {
namespace state {

/**
 * @brief A base class for structs and classes that expose metadata about
 * their data fields and provide means to discover and access them dynamically
 * at runtime.
 */
class fixed_struct
{
public:
    /**
     * @brief An accessor for accessing a fixed field of a struct.
     * @tparam T Type of the field.
     * 
     * @note The current implementation is equivalent to a simple
     * size_t but allows us to use a strong-ish typed template.
     * The only performance downside is an extra  "mov" CPU instruction
     * when using the accessor for accessing a field (just one, and
     * is compiler-dependent).
     */
    template<typename T> struct accessor_t { size_t offset = 0; };

    /**
     * @brief Metadata info about a given fixed field of a struct.
     */
    class field_info
    {
    public:
        /**
         * @brief Creates a new metadata info for a given fixed field.
         * 
         * @tparam T Type of the field.
         * @param name Display name of the field.
         * @param offset Memory offset of the field in the structure
         * layout of the struct or class in which the field is defined.
         * @return field_info Metadata info of the field.
         */
        template<typename T>
        static field_info create(const std::string& name, size_t offset)
        {
            return field_info(sizeof(T), offset, name, typeid(T));
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
                throw std::runtime_error("incompatible type for fixed struct field accessor: " + m_name);
            }
            return accessor_t<T>{m_offset};
        }

    private:
        field_info(size_t size, size_t offset, std::string name, const std::type_info& info)
            : m_size(size), m_offset(offset), m_name(name), m_info(&info) { }
        
        size_t m_size;
        size_t m_offset;
        std::string m_name;
        const std::type_info* m_info;
    };


    /**
     * @brief List about the fields metadata of a given struct or class
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
         * thrown if two fields are defined with the same name,, otherwise the
         * previous definition is returned.
         * 
         * @tparam T Type of the field.
         * @param baseptr "this" pointer of the struct containing the field,
         * which is used to compute the field's memory offset in other instances
         * of the same struct.
         * @param v Field of which metadata is added to the list.
         * @param name Display name of the field.
         * @return const field_info& Metadata about the added field.
         */
        template<typename T>
        const field_info& add_info(const void* baseptr, const T& v, const std::string& name)
        {
            const auto &it = m_definitions.find(name);
            if (it != m_definitions.end())
            {
                throw std::runtime_error("multiple definitions of fixed field in struct: " + name);
            }

            // todo(jasondellaluce): add safety boundary checks here
            size_t offset = (size_t)(((uintptr_t) &v) - (uintptr_t) baseptr);
            m_definitions.insert({ name, field_info::create<T>(name, offset) });
            return m_definitions.at(name);
        }

    private:
        std::unordered_map<std::string, field_info> m_definitions;
    };


    fixed_struct(void* this_ptr): m_this_ptr((uintptr_t) this_ptr) { } 
    virtual ~fixed_struct() = default;
    fixed_struct(fixed_struct&&) = default;
    fixed_struct& operator = (fixed_struct&&) = default;
    fixed_struct(const fixed_struct& s) = default;
    fixed_struct& operator = (const fixed_struct& s) = default;

    /**
     * @brief Get a memory reference to a given fixed field within a struct
     * using an accessor.
     * 
     * @tparam T Type of the field.
     * @param accessor Accessor previously-created from the field's metadata.
     * @return T& Memory reference of the field within the given struct.
     */
    template <typename T>
    inline T& get_fixed_field(const accessor_t<T>& accessor)
    {
        return *(reinterpret_cast<T*>(m_this_ptr + accessor.offset));
    }

    /**
     * @brief Returns the list of metadata about the fixed fields
     * accessible for this struct. Note, it's not mandatory for a struct
     * to expose metadata about all its fields.
     * 
     * @return field_info_list List of field metadata.
     * 
     * todo(jasondellaluce): would it make sense to make this a const ref?
     */
    virtual field_info_list fixed_fields() const = 0;

private:
    uintptr_t m_this_ptr;
};

}; // state
}; // libsinsp
