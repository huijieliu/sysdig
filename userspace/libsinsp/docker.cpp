//
// docker.cpp
//

#include "docker.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include "user_event.h"

docker::docker(const std::string& url,
	const std::string& path,
	const std::string& http_version,
	int timeout_ms,
	bool is_captured,
	bool verbose,
	event_filter_ptr_t event_filter): m_id("docker"),
#ifdef HAS_CAPTURE
		m_url(!url.empty() ? url : std::string(scap_get_host_root()) + "/var/run/docker.sock"),
		m_collector(false),
#endif // HAS_CAPTURE
		m_timeout_ms(timeout_ms),
		m_is_captured(is_captured),
		m_verbose(verbose),
		m_event_filter(event_filter)
{
#ifdef HAS_CAPTURE
	g_logger.log(std::string("Creating Docker object for " +
							(m_url.empty() ? std::string("capture replay") : m_url),
				 sinsp_logger::SEV_DEBUG));

	m_event_http = std::make_shared<handler_t>(*this, "events", m_url, path, http_version, timeout_ms);
	m_event_http->set_json_callback(&docker::set_event_json);
	m_event_http->set_json_end("}\n");
	m_collector.add(m_event_http);
	send_data_request();

	m_severity_map["attach"] = sinsp_logger::SEV_EVT_INFORMATION;
	m_severity_map["commit"] = sinsp_logger::SEV_EVT_INFORMATION;
	m_severity_map["copy"] = sinsp_logger::SEV_EVT_INFORMATION;
	m_severity_map["create"] = sinsp_logger::SEV_EVT_INFORMATION;
	m_severity_map["destroy"] = sinsp_logger::SEV_EVT_INFORMATION;
	m_severity_map["die"] = sinsp_logger::SEV_EVT_WARNING;
	m_severity_map["exec_create"] = sinsp_logger::SEV_EVT_INFORMATION;
	m_severity_map["exec_start"] = sinsp_logger::SEV_EVT_INFORMATION;
	m_severity_map["export"] = sinsp_logger::SEV_EVT_INFORMATION;
	m_severity_map["kill"] = sinsp_logger::SEV_EVT_WARNING;
	m_severity_map["oom"] = sinsp_logger::SEV_EVT_INFORMATION;
	m_severity_map["pause"] = sinsp_logger::SEV_EVT_INFORMATION;
	m_severity_map["rename"] = sinsp_logger::SEV_EVT_INFORMATION;
	m_severity_map["resize"] = sinsp_logger::SEV_EVT_INFORMATION;
	m_severity_map["restart"] = sinsp_logger::SEV_EVT_INFORMATION;
	m_severity_map["start"] = sinsp_logger::SEV_EVT_INFORMATION;
	m_severity_map["stop"] = sinsp_logger::SEV_EVT_INFORMATION;
	m_severity_map["top"] = sinsp_logger::SEV_EVT_INFORMATION;
	m_severity_map["unpause"] = sinsp_logger::SEV_EVT_INFORMATION;
	m_severity_map["update"] = sinsp_logger::SEV_EVT_INFORMATION;
	m_severity_map["delete"] = sinsp_logger::SEV_EVT_INFORMATION;
	m_severity_map["import"] = sinsp_logger::SEV_EVT_INFORMATION;
	m_severity_map["pull"] = sinsp_logger::SEV_EVT_INFORMATION;
	m_severity_map["push"] = sinsp_logger::SEV_EVT_INFORMATION;
	m_severity_map["tag"] = sinsp_logger::SEV_EVT_INFORMATION;
	m_severity_map["untag"] = sinsp_logger::SEV_EVT_INFORMATION;
	m_severity_map["mount"] = sinsp_logger::SEV_EVT_INFORMATION;
	m_severity_map["unmount"] = sinsp_logger::SEV_EVT_INFORMATION;
	m_severity_map["connect"] = sinsp_logger::SEV_EVT_INFORMATION;
	m_severity_map["disconnect"] = sinsp_logger::SEV_EVT_INFORMATION;
#endif
}

docker::~docker()
{
}

#ifdef HAS_CAPTURE
void docker::send_event_data_request()
{
	if(m_event_http)
	{
		m_event_http->send_request();
	}
	else
	{
		throw sinsp_exception("Docker event HTTP client is null.");
	}
}

void docker::connect()
{
	if(!connect(m_event_http, &docker::set_event_json, 1))
	{
		throw sinsp_exception("Connection to Docker API failed.");
	}
}
#endif // HAS_CAPTURE

bool docker::is_alive() const
{
#ifdef HAS_CAPTURE
	if(m_event_http && !m_event_http->is_connected())
	{
		g_logger.log("Mesos state connection loss.", sinsp_logger::SEV_WARNING);
		return false;
	}
#endif // HAS_CAPTURE
	return true;
}

#ifdef HAS_CAPTURE

void docker::check_collector_status(int expected)
{
	if(!m_collector.is_healthy(expected))
	{
		throw sinsp_exception("Docker collector not healthy (has " + std::to_string(m_collector.subscription_count()) +
							  " connections, expected " + std::to_string(expected) + "); giving up on data collection in this cycle ...");
	}
}

void docker::send_data_request(bool collect)
{
	if(m_events.size()) { return; }
	connect();
	send_event_data_request();
	g_logger.log("Docker event request sent.", sinsp_logger::SEV_DEBUG);
	if(collect) { collect_data(); }
}

void docker::collect_data()
{
	if(m_collector.subscription_count())
	{
		m_collector.get_data();
		if(m_events.size())
		{
			for(auto evt : m_events)
			{
				if(evt && !evt->isNull())
				{
					handle_event(std::move(*evt));
				}
				else
				{
					g_logger.log(std::string("Docker event error: ") +
								(!evt ? "event is null." : (evt->isNull() ? "JSON is null." : "Unknown")),
								sinsp_logger::SEV_ERROR);
				}
			}
			m_events.clear();
		}
	}
}
#endif // HAS_CAPTURE

void docker::set_event_json(json_ptr_t json, const std::string&)
{
	if(m_event_filter)
	{
		m_events.emplace_back(json);
	}
}

void docker::handle_event(Json::Value&& root)
{
	if(m_event_filter)
	{
		std::string type = get_json_string(root, "Type");
		std::string status = get_json_string(root, "status");
		bool is_allowed = m_event_filter->allows_all();
		if(!is_allowed && !type.empty())
		{
			is_allowed = m_event_filter->allows_all(type);
		}
		else if(!is_allowed && !status.empty())
		{
			is_allowed = m_event_filter->has(type, status);
		}
		if(is_allowed)
		{
			severity_map_t::const_iterator it = m_severity_map.find(status);
			if(it == m_severity_map.end())
			{
				severity_t severity;
				std::string event_name = get_json_string(root, "from");
				std::string id = get_json_string(root, "id");
				if(id.length() >= 12) { id = id.substr(0, 12); }
				severity = (it != m_severity_map.end()) ? it->second : sinsp_logger::SEV_EVT_ERROR;

				uint64_t epoch_time_s = static_cast<uint64_t>(~0);
				Json::Value t = root["time"];
				if(!t.isNull() && t.isConvertibleTo(Json::uintValue))
				{
					epoch_time_s = t.asUInt64();
				}
				g_logger.log("Docker event: name=" + event_name + ", id=" + id +
							", status=" + status + ", time=" + std::to_string(epoch_time_s),
							sinsp_logger::SEV_DEBUG);
				if(m_verbose)
				{
					std::cout << Json::FastWriter().write(root) << std::endl;
				}

				std::string scope("container.id=");
				scope.append(id);
				const Json::Value& actor = root["Actor"];
				if(!actor.isNull() && actor.isObject())
				{
					const Json::Value& attrib = actor["Attributes"];
					if(!attrib.isNull() && attrib.isObject())
					{
						const Json::Value& img = attrib["image"];
						if(!img.isNull() && img.isConvertibleTo(Json::stringValue))
						{
							status.append("; Image: ").append(img.asString());
						}
						const Json::Value& name = attrib["name"];
						if(!name.isNull() && name.isConvertibleTo(Json::stringValue))
						{
							status.append("; Name: ").append(img.asString());
						}
					}
				}
				sinsp_user_event::tag_map_t tags;
				tags["sysdig_event_source"] = "docker";
				std::string evt = sinsp_user_event::to_string(epoch_time_s, std::move(event_name),
									std::move(status), std::move(scope), std::move(tags));
				g_logger.log(std::move(evt), severity);
				//g_logger.log(evt, sinsp_logger::SEV_DEBUG);
			}
			else
			{
				g_logger.log("Docker EVENT: status not supported: " + status, sinsp_logger::SEV_ERROR);
				g_logger.log(Json::FastWriter().write(root), sinsp_logger::SEV_DEBUG);
			}
		}
		else
		{
			g_logger.log("Docker EVENT: status not permitted by filter: " + type +':' + status, sinsp_logger::SEV_ERROR);
			g_logger.log(Json::FastWriter().write(root), sinsp_logger::SEV_DEBUG);
		}
	}
}
