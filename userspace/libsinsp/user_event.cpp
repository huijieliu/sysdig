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

#include "sinsp.h"
#include "sinsp_int.h"
#include "user_event.h"

sinsp_user_event::sinsp_user_event() : m_epoch_time_s(0), m_severity(~0)
{
}

sinsp_user_event::sinsp_user_event(uint64_t epoch_time_s, string&& name, string&& desc,
	uint32_t sev, string&& scope, tag_map_t&& tags):
	m_epoch_time_s(epoch_time_s), m_name(std::move(name)), m_description(std::move(desc)),
	m_severity(sev), m_scope(std::move(scope)), m_tags(std::move(tags))
{
}

sinsp_user_event::sinsp_user_event(sinsp_user_event&& other):
	m_epoch_time_s(other.m_epoch_time_s),
	m_name(std::move(other.m_name)),
	m_description(std::move(other.m_description)),
	m_severity(other.m_severity),
	m_scope(std::move(other.m_scope)),
	m_tags(std::move(other.m_tags))
{
}

sinsp_user_event& sinsp_user_event::operator=(sinsp_user_event&& other)
{
	if(this != &other)
	{
		m_epoch_time_s = other.m_epoch_time_s;
		m_name = std::move(other.m_name);
		m_description = std::move(other.m_description);
		m_severity = other.m_severity;
		m_scope = std::move(other.m_scope);
		m_tags = std::move(other.m_tags);
	}

	return *this;
}
