//
// json_parser.h
//
// jq wrapper
//

#ifdef __linux__

#include "json_query.h"
#include "sinsp.h"

json_query::json_query(const std::string& json, const std::string& filter, bool dbg) :
	_jq(jq_init()), _input{0}, _result{0}, _processed(false)
{
	if(!_jq) { cleanup(); }
	process(json, filter, dbg);
}

json_query::~json_query()
{
	cleanup();
}

bool json_query::process(const std::string& json, const std::string& filter, bool dbg)
{
	cleanup(_input);
	cleanup(_result);
	clear();

	if(!_jq) { cleanup(); }
	if(!jq_compile(_jq, filter.c_str()))
	{
		_error = "Filter parsing failed.";
		return false;
	}

	_input = jv_parse/*_sized*/(json.c_str()/*, json.length()*/);
	if (!jv_is_valid(_input))
	{
		cleanup(_input, "JSON parse error.");
		return false;
	}

	jq_start(_jq, _input, dbg ? JQ_DEBUG_TRACE : 0);
	_input = {0}; // jq_start() freed it
	_result = jq_next(_jq);
	if (!jv_is_valid(_result))
	{
		cleanup(_result, "JQ filtering result invalid.");
		return false;
	}
	_json = json;
	_filter = filter;
	return _processed = true;
}

const std::string& json_query::result(int flags)
{
	if(_processed)
	{
		static const std::string ret;
		if(!_error.empty()) { return ret; }
		char* buf;
		size_t len;
		FILE* f = open_memstream(&buf, &len);
		if(f == NULL)
		{
			_error = "Can't open memory stream for writing.";
			return ret;
		}
		jv_dumpf(_result, f, flags);
		clear();
		fclose (f);
		_filtered_json.assign(buf, len);
		free (buf);
		_processed = false;
	}
	return _filtered_json;
}

void json_query::clear()
{
	_result = {0};
	_input = {0};
	_filtered_json.clear();
	_error.clear();
	_processed = false;
}

void json_query::cleanup()
{
	if(_jq)
	{
		cleanup(_input);
		cleanup(_result);
		clear();
		jq_teardown(&_jq);
		_jq = 0;
	}
	else
	{
		throw sinsp_exception("JQ handle is null.");
	}
}

void json_query::cleanup(jv& j, const std::string& msg)
{
	if(j.u.ptr)
	{
		jv_free(j);
		j = {0};
	}
	_error = msg;
}

#endif // __linux__
