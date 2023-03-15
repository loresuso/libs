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

#include "fixed_struct.h"
#include "dynamic_struct.h"

namespace libsinsp {
namespace state {

/**
 * @brief Base non-templated interface for state tables, defining
 * type-independent properties common to all tables.
 */
class base_table
{
public:
    /**
     * @brief Base class for entries of a table. This needs to be extended
     * by the value data types of the table entries of a given typed table.
     */
    struct entry: public fixed_struct, dynamic_struct
    {
        entry(const std::shared_ptr<dynamic_struct::field_info_list>& dynamic_fields)
            : fixed_struct(this), dynamic_struct(dynamic_fields) { }
        virtual ~entry() = default;
        entry(entry&&) = default;
        entry& operator = (entry&&) = default;
        entry(const entry& s) = default;
        entry& operator = (const entry& s) = default;
    };

    base_table(const std::type_info& key_info, const std::type_info& value_info)
        : m_key_info(&key_info), m_value_info(&value_info) { }
    virtual ~base_table() = default;
    base_table(base_table&&) = default;
    base_table& operator = (base_table&&) = default;
    base_table(const base_table& s) = default;
    base_table& operator = (const base_table& s) = default;
    
    /**
     * @brief Returns the non-null type info about the table's key. 
     */
    const std::type_info* key_info() const
    {
        return m_key_info;
    }

    /**
     * @brief Returns the non-null type info about the table's value. 
     */
    const std::type_info* value_info() const
    {
        return m_value_info;
    }

    /**
     * @brief Returns the name of the table.
     */
    virtual const std::string& name() const = 0;

    /**
     * @brief Returns the number of entries present in the table.
     */
    virtual size_t entries_count() const = 0;

    /**
     * @brief Erase all the entries present in the table.
     * After invoking this function, entries_count() will return true.
     */
    virtual void clear_entries() = 0;

    /**
     * @brief Returns the fields metadata list for the fixed fields defined
     * for the value data type of this table. This fields will be accessible
     * for all the entries of this table.
     */
    virtual const fixed_struct::field_info_list& fixed_fields() const = 0;

    /**
     * @brief Returns the fields metadata list for the dynamic fields defined
     * for the value data type of this table. This fields will be accessible
     * for all the entries of this table. The returned metadata list can
     * be expended at runtime by adding new dynamic fields, which will then
     * be allocated and accessible for all the present and future entries
     * present in the table.
     */
    virtual const std::shared_ptr<dynamic_struct::field_info_list>& dynamic_fields() = 0;

private:
    const std::type_info* m_key_info;
    const std::type_info* m_value_info;
};

/**
 * @brief Base interfaces for state tables, with strong templated type
 * definitions for both the table keys and entries types.
 */
template <typename KeyType, typename DataType>
class table: public base_table
{
    static_assert(
        std::is_default_constructible<KeyType>(),
        "table key type must have a default constructor");
    static_assert(
        std::is_base_of<base_table::entry, DataType>(),
        "table data type must extend 'base_table::entry'");

public:
    table(): base_table(typeid(KeyType), typeid(DataType)) {}
    virtual ~table() = default;
    table(table&&) = default;
    table& operator = (table&&) = default;
    table(const table& s) = delete; // todo: should we make this copyable too?
    table& operator = (const table& s) = delete;
    
    /**
     * @brief Allocates and returns a new entry for the table. This is just
     * a factory method, the entry will not automatically added to the table.
     * Once a new entry is allocated with this method, users must invoke
     * add_entry() in order to actually insert it in the table.
     */
    virtual std::unique_ptr<DataType> new_entry() const = 0;

    /**
     * @brief Returns a pointer to an entry present in the table at the given
     * key. The pointer is owned by the table, and will remain valid up until
     * the table is destroyed or the entry is removed from the table.
     * 
     * @param key Key of the entry to be retrieved.
     * @return DataType* Pointer to the entry if present in the table at the
     * given key, and nullptr otherwise.
     */
    virtual DataType* get_entry(const KeyType& key) = 0;

    /**
     * @brief Inserts a new entry in the table with the given key. If another
     * entry is already present with the same key, it gets replaced. After
     * insertion, table will be come the owner of the entry's pointer.
     * 
     * @param key Key of the entry to be added.
     * @param value Entry to be added with the given key.
     * @return DataType* Non-null pointer to the newly-added entry, which will
     * remain valid up until the table is destroyed or the entry is removed
     * from the table.
     */
    virtual DataType* add_entry(const KeyType& key, std::unique_ptr<DataType> value) = 0;

    /**
     * @brief Removes an entry from the table with the given key.
     * 
     * @param key Key of the entry to be removed.
     * @return true If an entry was present at the given key.
     * @return false If an entry was not present at the given key.
     */
    virtual bool erase_entry(const KeyType& key) = 0;

    /**
     * @brief Iterates over all the entries contained in the table and invokes
     * the given predicate for each of them.
     * 
     * @param pred The predicate to invoke for all the table's entries. The
     * predicate returns true if the iteration can proceed to the next entry,
     * and false if the iteration needs to break out.
     * @return true If the iteration proceeded successfully for all the entries.
     * @return false If the iteration broke out.
     */
    virtual bool foreach_entry(std::function<bool(DataType* e)> pred) const = 0;
};

}; // state
}; // libsinsp
