/*
Copyright (C) 2013-2014 Draios inc.

This file is part of sysdig.

sysdig is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License version 2 as
published by the Free Software Foundation.

sysdig is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with sysdig.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include <memory>
#include <mutex>

//
// Wrapper class for user-configured events
//
class sinsp_user_event
{
public:
	typedef std::unordered_map<std::string, std::string> tag_map_t;
	static const uint32_t UNKNOWN_SEVERITY = static_cast<uint32_t>(~0);

	sinsp_user_event(const sinsp_user_event&) = delete;
	sinsp_user_event& operator=(const sinsp_user_event& other) = delete;

	sinsp_user_event();

	sinsp_user_event(uint64_t epoch_time_s, string&& name, string&& desc,
		string&& scope, tag_map_t&& tags, uint32_t sev);

	sinsp_user_event(sinsp_user_event&& other);

	sinsp_user_event& operator=(sinsp_user_event&& other);

	uint64_t epoch_time_s() const;
	const string& name() const;
	const string& description() const;
	uint32_t severity() const;
	const string& scope() const;
	const tag_map_t& tags() const;

	static std::string to_string(uint64_t timestamp,
								std::string&& name,
								std::string&& description,
								std::string&& scope,
								tag_map_t&& tags,
								uint32_t sev = UNKNOWN_SEVERITY);

private:
	uint64_t  m_epoch_time_s;
	string    m_name;
	string    m_description;
	uint32_t  m_severity;
	string    m_scope;
	tag_map_t m_tags;
};

inline uint64_t sinsp_user_event::epoch_time_s() const
{
	return m_epoch_time_s;
}

inline const string& sinsp_user_event::name() const
{
	return m_name;
}

inline const string& sinsp_user_event::description() const
{
	return m_description;
}

inline uint32_t sinsp_user_event::severity() const
{
	return m_severity;
}

inline const string& sinsp_user_event::scope() const
{
	return m_scope;
}

inline const sinsp_user_event::tag_map_t& sinsp_user_event::tags() const
{
	return m_tags;
}

//
// User-configured events queue
//
class user_event_queue
{
public:
	typedef std::shared_ptr<user_event_queue> ptr_t;
	typedef std::deque<sinsp_user_event> type_t;

	void add(sinsp_user_event&& evt);
	bool get(sinsp_user_event& evt);
	type_t::size_type count() const;

private:
	type_t m_queue;
	mutable std::mutex m_mutex;
};

inline void user_event_queue::add(sinsp_user_event&& evt)
{
	std::lock_guard<std::mutex> lock(m_mutex);
	m_queue.emplace_back(std::move(evt));
}

inline bool user_event_queue::get(sinsp_user_event& evt)
{
	std::lock_guard<std::mutex> lock(m_mutex);
	if(!m_queue.size())
	{
		return false;
	}
	evt = std::move(m_queue.front());
	m_queue.pop_front();
	return true;
}

inline user_event_queue::type_t::size_type user_event_queue::count() const
{
	std::lock_guard<std::mutex> lock(m_mutex);
	return m_queue.size();
}
