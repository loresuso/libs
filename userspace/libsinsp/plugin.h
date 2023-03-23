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

#include <atomic>
#include <chrono>
#include <memory>
#include <set>
#include <string>
#include <vector>
#include <unordered_map>
#include <engine/source_plugin/source_plugin_public.h>
#include "event.h"
#include "version.h"
#include "../plugin/plugin_loader.h"
#include "state/table_registry.h"
#include "events/sinsp_events.h"

// todo(jasondellaluce: remove this forward declaration)
class sinsp_filter_check;

class sinsp_plugin_cap_common
{
public:
	virtual ~sinsp_plugin_cap_common() = default;

	virtual plugin_caps_t caps() const = 0;

	virtual bool init(const std::string &config, std::string &errstr) = 0;

	virtual void destroy() = 0;

	virtual std::string get_last_error() const = 0;

	virtual const std::string &name() const = 0;

	virtual const std::string &description() const = 0;

	virtual const std::string &contact() const = 0;

	virtual const sinsp_version &plugin_version() const = 0;

	virtual const sinsp_version &required_api_version() const = 0;

	virtual std::string get_init_schema(ss_plugin_schema_type& schema_type) const = 0;
};

class sinsp_plugin_cap_sourcing: public sinsp_plugin_cap_common
{
public:
	// Describes a valid parameter for the open() function.
	struct open_param {
		std::string value;
		std::string desc;
		std::string separator;
	};

	virtual ~sinsp_plugin_cap_sourcing() = default;

	virtual scap_source_plugin& as_scap_source() = 0;

	virtual uint32_t id() const = 0;

	virtual const std::string &event_source() const = 0;

	virtual std::string get_progress(uint32_t &progress_pct) const = 0;

	virtual std::string event_to_string(sinsp_evt* evt) const = 0;

	virtual std::vector<open_param> list_open_params() const = 0;
};

class sinsp_plugin_cap_extraction: public sinsp_plugin_cap_common
{
public:
	virtual ~sinsp_plugin_cap_extraction() = default;

	virtual const libsinsp::events::set<ppm_event_code>& extract_event_codes() const = 0;

	virtual const std::set<std::string> &extract_event_sources() const = 0;

	virtual bool extract_fields(ss_plugin_event &evt, uint32_t num_fields, ss_plugin_extract_field *fields) const = 0;

	virtual const std::vector<filtercheck_field_info>& fields() const = 0;
};

class sinsp_plugin_cap_state_management: public sinsp_plugin_cap_common
{
public:
	virtual ~sinsp_plugin_cap_state_management() = default;

	virtual const libsinsp::events::set<ppm_event_code>& parse_event_codes() const = 0;

	virtual const std::set<std::string>& parse_event_sources() const = 0;

	virtual bool parse_event(ss_plugin_event &evt) const = 0;
};

// Class that holds a plugin.
// it extends sinsp_plugin_cap itself because it exposes a
// resolve_dylib_symbols() logic for common plugin symbols
class sinsp_plugin:
		public sinsp_plugin_cap_sourcing,
		public sinsp_plugin_cap_extraction,
		public sinsp_plugin_cap_state_management
{
public:
	// Create a plugin from the dynamic library at the provided
	// path. On error, the shared_ptr will == nullptr and errstr is
	// set with an error.
	static std::shared_ptr<sinsp_plugin> create(
		const std::string &filepath,
		const std::shared_ptr<libsinsp::state::table_registry>& table_registry,
		std::string &errstr);

	// Return whether a filesystem object is loaded
	static bool is_plugin_loaded(std::string &filepath);

	// If the plugin has CAP_EXTRACTION capability, returns a filtercheck with
	// its exported fields. Returns NULL otherwise
	static sinsp_filter_check* new_filtercheck(std::shared_ptr<sinsp_plugin> plugin);

	sinsp_plugin(plugin_handle_t* handle, const std::shared_ptr<libsinsp::state::table_registry>& table_registry);
	virtual ~sinsp_plugin();

	/** Common API **/
	virtual bool init(const std::string &config, std::string &errstr) override;
	virtual void destroy() override;
	virtual std::string get_last_error() const override;
	virtual const std::string &name() const override;
	virtual const std::string &description() const override;
	virtual const std::string &contact() const override;
	virtual const sinsp_version &plugin_version() const override;
	virtual const sinsp_version &required_api_version() const override;
	virtual std::string get_init_schema(ss_plugin_schema_type& schema_type) const override;
	virtual plugin_caps_t caps() const override;

	/** Event Sourcing **/
	virtual scap_source_plugin& as_scap_source() override;
	virtual uint32_t id() const override;
	virtual const std::string &event_source() const override;
	virtual std::string get_progress(uint32_t &progress_pct) const override;
	virtual std::string event_to_string(sinsp_evt* evt) const override;
	virtual std::vector<sinsp_plugin_cap_sourcing::open_param> list_open_params() const override;

	/** Field Extraction **/
	virtual const libsinsp::events::set<ppm_event_code> &extract_event_codes() const override;
	virtual const std::set<std::string> &extract_event_sources() const override;
	virtual bool extract_fields(ss_plugin_event &evt, uint32_t num_fields, ss_plugin_extract_field *fields) const override;
	virtual const std::vector<filtercheck_field_info>& fields() const override;

	/** State Management **/
	virtual const libsinsp::events::set<ppm_event_code> &parse_event_codes() const override;
	virtual const std::set<std::string> &parse_event_sources() const override;
	virtual bool parse_event(ss_plugin_event &evt) const override;

	/* Helpers */
	static inline bool is_source_compatible(const std::set<std::string> &sources, const std::string& source)
	{
		return sources.empty() || sources.find(source) != sources.end();
	}

private:
	std::string m_name;
	std::string m_description;
	std::string m_contact;
	sinsp_version m_plugin_version;
	sinsp_version m_required_api_version;

	ss_plugin_t* m_state;
	plugin_caps_t m_caps;
	plugin_handle_t* m_handle;

	/** Event Sourcing **/
	uint32_t m_id;
	std::string m_event_source;
	scap_source_plugin m_scap_source_plugin;

	/** Field Extraction **/
	std::vector<filtercheck_field_info> m_fields;
	std::set<std::string> m_extract_event_sources;
	libsinsp::events::set<ppm_event_code> m_extract_event_codes;

	/** State management **/
	struct table_input_deleter { void operator()(plugin_table_input* r); };
	std::vector<ss_plugin_table_info> m_table_infos;
	std::shared_ptr<libsinsp::state::table_registry> m_table_registry;
	std::set<std::string> m_parse_event_sources;
	libsinsp::events::set<ppm_event_code> m_parse_event_codes;
	std::unordered_map<std::string, std::unique_ptr<plugin_table_input, table_input_deleter>> m_tables;
	std::unordered_map<std::string, std::unique_ptr<libsinsp::state::base_table>> m_owned_tables;

	void validate_init_config(std::string& config);
	bool resolve_dylib_symbols(std::string &errstr);
	void resolve_dylib_field_arg(Json::Value root, filtercheck_field_info &tf);
	void validate_init_config_json_schema(std::string& config, std::string &schema);

	static const plugin_table_init_api* table_init_api();
	static const plugin_table_read_api* table_read_api();
	static const plugin_table_write_api* table_write_api();
	static ss_plugin_table_info* table_api_list_tables(ss_plugin_owner_t* o, uint32_t* ntables);
	static ss_plugin_table_t *table_api_get_table(ss_plugin_owner_t *o, const char *name, ss_plugin_table_type key_type);
	static void table_api_add_table(ss_plugin_owner_t *o, plugin_table_input* input);
	static ss_plugin_table_fieldinfo* table_field_api_list_fields(ss_plugin_table_t *t, uint32_t *nfields);
};
