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
#include "state/table.h"

#include <unordered_map>

namespace libsinsp {
namespace state {


/**
 * @brief A registry for the available state tables. Table owners can register
 * their tables and make them available for discovery and retrieval by other
 * components.
 * 
 * @note The lifetype of the tables registered in the registry is regulated
 * by the owner of each tables. This means that a table pointer obtained
 * through get_table() will remain valid and available up until the owner
 * destroys the table.
 * 
 * todo(jasondellaluce): switch from opaque ptrs to shared ptrs, but the
 * current libsinsp implementation does not allow us to
 */
class table_registry
{
public:
    table_registry() = default;
    ~table_registry() = default;
    table_registry(table_registry&&) = default;
    table_registry& operator = (table_registry&&) = default;
    table_registry(const table_registry& s) = delete; // todo: should we make this copyable too?
    table_registry& operator = (const table_registry& s) = delete;


    /**
     * @brief Obtain a pointer to a table registered in the registry with
     * the given name. Throws an exception if a table with the given name
     * is defined with types incompatible with the ones provided in the
     * template.
     * 
     * @tparam KeyType Type of the table's key.
     * @param name Name of the table.
     * @return table<KeyType>* Pointer to the registered table,
     * or nullptr if no table is registered by the given name.
     */
    template <typename KeyType>
    table<KeyType>* get_table(const std::string& name) const
    {
        const auto &it = m_tables.find(name);
        if (it != m_tables.end())
        {
            if (!it->second->key_info().is_compatible(libsinsp::state::type_info::of<KeyType>()))
            {
                throw std::runtime_error("registered table accessed with incompatible types: " + name);
            }
            return static_cast<table<KeyType>*>(it->second);
        }
        return nullptr;
    }
    
    /**
     * @brief Registers a table in the registry with a given name and
     * returns a pointer to the table. If a table is already present with the
     * given name, it returns a pointer to the already-existing table.
     * Throws an exception if a table with the given name is defined with types
     * incompatible with the ones provided in the template.
     * 
     * @tparam KeyType Type of the table's key.
     * @param name Name of the table.
     * @param t Pointer to the table.
     * @return table<KeyType>* Pointer to the registered table,
     * or a pointer to the already-existing table.
     */
    template <typename KeyType>
    table<KeyType>* add_table(const std::string& name, table<KeyType>* t)
    {
        const auto &it = m_tables.find(name);
        if (it != m_tables.end())
        {
            throw std::runtime_error("table registered multiple tumes: " + name);
        }
        m_tables.insert({ name, t });
        return t;
    }

    /**
     * @brief Returns all the tables known in the registry.
     */
    const std::unordered_map<std::string, base_table*>& tables() const
    {
        return m_tables;
    }

private:
    std::unordered_map<std::string, base_table*> m_tables;
};

}; // state
}; // libsinsp
