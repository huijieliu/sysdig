//
// uri.cpp
//
// URI utility
//

#include "uri.h"
#include "sinsp.h"
#include <sstream>

uri::uri(std::string str)
{
	parsed_uri p_uri = parse_uri(str.c_str());
	if(p_uri.error)
	{
		str.insert(0, std::string("Invalid URI: [").append(1, ']'));
		throw sinsp_exception(str);
	}
	m_scheme = str.substr(p_uri.scheme_start, p_uri.scheme_end - p_uri.scheme_start);
	m_host = str.substr(p_uri.host_start, p_uri.host_end - p_uri.host_start);
	m_port = p_uri.port;
	m_path = str.substr(p_uri.path_start, p_uri.path_end - p_uri.path_start);
	m_query = str.substr(p_uri.query_start, p_uri.query_end - p_uri.query_start);
	if(p_uri.user_info_end != p_uri.user_info_start)
	{
		std::string auth = str.substr(p_uri.user_info_start, p_uri.user_info_end - p_uri.user_info_start);
		std::string::size_type pos = auth.find(':');
		if(pos == std::string::npos)
		{
			throw sinsp_exception("Invalid credentials format.");
		}
		m_user = auth.substr(0, pos);
		m_password = auth.substr(pos + 1);
	}
}

std::string uri::to_string(bool show_creds) const
{
	std::ostringstream ostr;
	ostr << m_scheme << "://";
	if(!m_user.empty())
	{
		if(show_creds)
		{
			ostr << m_user << ':' << m_password << '@';
		}
		else
		{
			ostr << "***:***@";
		}
	}
	ostr << m_host;
	if(m_port)
	{
		ostr << ':' << m_port;
	}
	ostr << m_path;
	if(!m_query.empty())
	{
		ostr << '?' << m_query;
	}
	return ostr.str();
}
