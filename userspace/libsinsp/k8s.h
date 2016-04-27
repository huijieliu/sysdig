//
// k8s.h
//
// extracts needed data from the k8s REST API interface
//

#pragma once

#include "json/json.h"
#include "k8s_common.h"
#include "k8s_component.h"
#include "k8s_state.h"
#include "k8s_event_data.h"
#include "k8s_net.h"
#include "sinsp_curl.h"
#include <sstream>
#include <utility>

class k8s_dispatcher;

class k8s
{
public:
#ifdef HAS_CAPTURE
	typedef sinsp_curl::ssl::ptr_t          ssl_ptr_t;
	typedef sinsp_curl::bearer_token::ptr_t bt_ptr_t;
#endif // HAS_CAPTURE

	class event_t
	{
	public:

		typedef std::set<std::string, ci_compare> type_list_t;

		event_t() = delete;

		event_t(const std::string& kind, const type_list_t& types):
			m_kind(kind), m_types(types)
		{
		}

		event_t(std::string&& kind, type_list_t&& types):
			m_kind(std::move(kind)), m_types(std::move(types))
		{
		}

		bool operator < (const event_t& other) const
		{
			return strcasecmp(m_kind.c_str(), other.m_kind.c_str()) < 0;
		}

		bool operator == (const event_t& other) const
		{
			bool retval = (strcasecmp(m_kind.c_str(), other.m_kind.c_str()) == 0);
			if(retval)
			{
				retval &= (other.m_types.size() <= this->m_types.size());
				if(retval)
				{
					type_list_t::const_iterator it = this->m_types.begin();
					for(const auto& t : other.m_types)
					{
						retval &= (strcasecmp(t.c_str(), it->c_str()) == 0);
						if(!retval) { break; }
						++it;
					}
				}
			}
			return retval;
		}

		const std::string& kind() const
		{
			return m_kind;
		}

		const type_list_t& types() const
		{
			return m_types;
		}

		bool has_type(const std::string& type) const
		{
			return m_types.find(type) != m_types.end() ||
					any_type();
		}

		bool any_type() const
		{
			return m_types.find("*") != m_types.end();
		}

	private:
		std::string m_kind;
		type_list_t m_types;
	};

	typedef std::set<event_t> event_filter_t;
	typedef std::shared_ptr<event_filter_t> event_filter_ptr_t;

	k8s(const std::string& uri = "http://localhost:80",
		bool start_watch = false,
		bool watch_in_thread = false,
		bool is_captured = false,
		const std::string& api = "/api/v1/",
#ifdef HAS_CAPTURE
		ssl_ptr_t ssl = 0,
		bt_ptr_t bt = 0,
#endif // HAS_CAPTURE
		bool curl_debug = false,
		event_filter_ptr_t event_filter = nullptr);

	~k8s();

	std::size_t count(k8s_component::type component) const;

	void on_watch_data(k8s_event_data&& msg);

	const k8s_state_t& get_state(bool rebuild = false);

	void watch();

	bool watch_in_thread() const;

	void stop_watching();

	bool is_alive() const;

#ifdef HAS_CAPTURE
	typedef k8s_state_t::event_list_t event_list_t;
	const event_list_t& get_capture_events() const { return m_state.get_capture_events(); }
	std::string dequeue_capture_event() { return m_state.dequeue_capture_event(); }
#endif // HAS_CAPTURE

	void simulate_watch_event(const std::string& json);

private:
	void extract_data(Json::Value& items, k8s_component::type component, const std::string& api_version);

	void build_state();

	void parse_json(const std::string& json, const k8s_component::type_map::value_type& component);

	void stop_watch();

	void cleanup();

	// due to deleted default dispatcher constructor, g++ has trouble instantiating map with values,
	// so we have to go with the forward declaration above and pointers here ...
	typedef std::map<k8s_component::type, k8s_dispatcher*> dispatch_map;
	dispatch_map make_dispatch_map(k8s_state_t& state);

	bool               m_watch;
	k8s_state_t        m_state;
	event_filter_ptr_t m_event_filter;
	dispatch_map       m_dispatch;
	bool               m_watch_in_thread;
#ifdef HAS_CAPTURE
	k8s_net*     m_net;
#endif

	static const k8s_component::type_map m_components;
	friend class k8s_test;
};

inline bool k8s::is_alive() const
{
#ifdef HAS_CAPTURE
	ASSERT(m_net);
	return m_net->is_healthy();
#endif
	return true;
}

inline bool k8s::watch_in_thread() const
{
	return m_watch_in_thread;
}
