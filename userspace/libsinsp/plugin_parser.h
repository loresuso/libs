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

#include "plugin.h"
#include "plugin_manager.h"

#include <memory>
#include <string>
#include <vector>

// todo(jasondellaluce): add docs here
class sinsp_plugin_parser
{
public:
	sinsp_plugin_parser(
		const std::shared_ptr<const sinsp_plugin_manager>& m,
		const std::shared_ptr<sinsp_plugin>& p):
			m_evt(),
			m_compatible_syscall_source(false),
			m_compatible_plugin_sources_bitmap(),
			m_manager(m),
			m_plugin(p)
	{
		if (!(p->caps() & CAP_STATE))
		{
			throw sinsp_exception("Creating a sinsp_plugin_parser with a non state-capable plugin.");
		}
		m_compatible_syscall_source = sinsp_plugin::is_source_compatible(p->extract_event_sources(), "syscall");
	}

    virtual ~sinsp_plugin_parser() = default;
    sinsp_plugin_parser(sinsp_plugin_parser&&) = default;
    sinsp_plugin_parser& operator = (sinsp_plugin_parser&&) = default;
    sinsp_plugin_parser(const sinsp_plugin_parser& s) = default;
    sinsp_plugin_parser& operator = (const sinsp_plugin_parser& s) = default;

	inline bool process_event(sinsp_evt* evt)
	{
		if (!m_plugin->parse_event_codes().contains((ppm_event_code) evt->get_type()))
		{
			return false;
		}

		m_evt.evtnum = evt->get_num();
		if (evt->get_type() == PPME_PLUGINEVENT_E)
		{
			auto parinfo = evt->get_param(0);
			ASSERT(parinfo->m_len == sizeof(int32_t));
			uint32_t pgid = *(int32_t *) parinfo->m_val;

			// We know that plugin has source capabilities because it has an id and is sending events
			// todo(jasondellaluce): remove this check once we do it properly at initialization time on the consumer side
			bool pfound = false;
			auto psource = m_manager->source_idx_by_plugin_id(pgid, pfound);
			if (!pfound)
			{
				ASSERT(false);
				return false;
			}

			// lazily populate the compatibility bitmap
			while (m_compatible_plugin_sources_bitmap.size() <= psource)
			{
				auto src_idx = m_compatible_plugin_sources_bitmap.size();
				m_compatible_plugin_sources_bitmap.push_back(false);
				ASSERT(src_idx < m_manager->sources().size());
				const auto& source = m_manager->sources()[src_idx];
				auto compatible = sinsp_plugin::is_source_compatible(m_plugin->parse_event_sources(), source);
				m_compatible_plugin_sources_bitmap[src_idx] = compatible;
			}

			// the plugin is not compatible with the event's source
			if (!m_compatible_plugin_sources_bitmap[psource])
			{
				return false;
			}

			parinfo = evt->get_param(1);
			m_evt.plugin.data = (uint8_t *) parinfo->m_val;
			m_evt.plugin.datalen = parinfo->m_len;
			m_evt.plugin.ts = evt->get_ts();
		}
		else
		{
			if (!m_compatible_syscall_source)
			{
				return false;
			}
			m_evt.syscall = (ss_plugin_syscall_event*) evt->m_pevt;
		}

		return m_plugin->parse_event(m_evt);
	}

	inline std::shared_ptr<sinsp_plugin> plugin() const
	{
		return m_plugin;
	}

private:
	ss_plugin_event m_evt;
	bool m_compatible_syscall_source;
	std::vector<bool> m_compatible_plugin_sources_bitmap;
	std::shared_ptr<const sinsp_plugin_manager> m_manager;
	std::shared_ptr<sinsp_plugin> m_plugin;
};