//
// uri.h
//
// URI utility
//

#pragma once

#include "uri_parser.h"
#include <string>

class uri
{
public:
	uri() = delete;
	
	uri(std::string str);

	const std::string& get_scheme() const;
	const std::string& get_user() const;
	const std::string& get_password() const;
	const std::string& get_host() const;
	const std::string& get_path() const;
	const std::string& get_query() const;
	int get_port() const;

	bool is_secure() const;
	std::string get_credentials() const;

	std::string to_string(bool show_creds = true) const;

private:
	std::string m_scheme, m_user, m_password, m_host, m_path, m_query;
    int m_port;
};

inline const std::string& uri::get_scheme() const
{
	return m_scheme;
}

inline const std::string& uri::get_user() const
{
	return m_user;
}

inline const std::string& uri::get_password() const
{
	return m_password;
}

inline const std::string& uri::get_host() const
{
	return m_host;
}

inline const std::string& uri::get_path() const
{
	return m_path;
}

inline const std::string& uri::get_query() const
{
	return m_query;
}

inline int uri::get_port() const
{
	return m_port;
}

inline bool uri::is_secure() const
{
	return "https" == m_scheme;
}

inline std::string uri::get_credentials() const
{
	std::string creds;
	if(!m_user.empty())
	{
		creds.append(m_user).append(1, ':').append(m_password);
	}
	return creds;
}
