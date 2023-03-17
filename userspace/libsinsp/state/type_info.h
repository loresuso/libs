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

#include <string>
#include <vector>

namespace libsinsp {
namespace state {

class type_info
{
public:
    enum kind_t
    {
        STRUCT,
        INT64,
        UINT64,
        STRING,
    };

    template<typename T> static inline type_info of()
    {
        return type_info("struct", STRUCT, sizeof(T), &_construct<T>, &_destroy<T>);
    }

    type_info() = delete;
    ~type_info() = default;
    type_info(type_info&&) = default;
    type_info& operator = (type_info&&) = default;
    type_info(const type_info& s) = default;
    type_info& operator = (const type_info& s) = default;

    inline const char* name() const
    {
        return m_name;
    }

    inline kind_t kind() const
    {
        return m_kind;
    }

    inline size_t size() const
    {
        return m_size;
    }

    inline void construct(void* p) const noexcept 
    {
        if (m_construct != nullptr) m_construct(p);
    }

    inline void destroy(void* p) const noexcept 
    {
        if (m_destroy != nullptr) m_destroy(p);
    }

    inline bool is_compatible(const type_info& o) const
    {
        // todo(jasondellaluce): improve and formalize type compatibility logic
        return kind() == o.kind() && size() == o.size();
    }

private:
    template <typename T> static inline void _construct(void* p)
    {
        std::allocator<T>().construct(reinterpret_cast<T*>(p));
    }

    template <typename T> static inline void _destroy(void* p)
    {
        std::allocator<T>().destroy(reinterpret_cast<T*>(p));
    }

    inline type_info(const char* n, kind_t k, size_t s, void (*c)(void*), void (*d)(void*))
        : m_name(n), m_kind(k), m_size(s), m_construct(c), m_destroy(d) { }

    const char* m_name;
    kind_t m_kind;
    size_t m_size;
    void (*m_construct)(void*);
    void (*m_destroy)(void*);
};

template<> inline type_info type_info::of<int64_t>()
{
    return type_info("int64", INT64, sizeof(int64_t), _construct<int64_t>, _destroy<int64_t>);
}
template<> inline type_info type_info::of<uint64_t>()
{
    return type_info("uint64", UINT64, sizeof(uint64_t), _construct<uint64_t>, _destroy<uint64_t>);
}
template<> inline type_info type_info::of<std::string>()
{
    return type_info("string", STRING, sizeof(std::string), _construct<std::string>, _destroy<std::string>);
}
template<> inline type_info type_info::of<const char*>()
{
    return type_info("string", STRING, sizeof(const char*), _construct<const char*>, _destroy<const char*>);
}

}; // state
}; // libsinsp

