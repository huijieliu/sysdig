--[[
Copyright (C) 2013-2015 Draios inc.
 
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License version 2 as
published by the Free Software Foundation.


This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
--]]

view_info = 
{
	id = "procs",
	name = "Processes",
	description = "This is the typical top/htop process list, showing usage of resources like CPU, memory, disk and network on a by process basis.",
	tips = {"This is a perfect view to start a drill down session. Click enter or double click on a process to dive into it and explore its behavior."},
	tags = {"Default"},
	view_type = "table",
	filter = "evt.type!=switch",
	applies_to = {"", "container.id", "fd.name", "fd.sport", "evt.type", "fd.directory", "fd.type", "k8s.pod.id", "k8s.rc.id", "k8s.svc.id", "k8s.ns.id"},
	is_root = true,
	drilldown_target = "threads",
	use_defaults = true,
	columns = 
	{
		{
			name = "NA",
			field = "thread.tid",
			is_key = true
		},
		{
			name = "NA",
			field = "proc.pid",
			is_groupby_key = true
		},
		{
			name = "PID",
			description = "Process PID.",
			field = "proc.pid",
			colsize = 7,
		},
		{
			tags = {"containers"},
			name = "VPID",
			field = "proc.vpid",
			description = "PID that the process has inside the container.",
			colsize = 8,
		},
		{
			name = "CPU",
			field = "thread.cpu",
			description = "Amount of CPU used by the proccess.",
			aggregation = "AVG",
			groupby_aggregation = "SUM",
			colsize = 8,
			is_sorting = true
		},
		{
			name = "USER",
			field = "user.name",
			colsize = 12
		},
		{
			name = "TH",
			field = "proc.nthreads",
			description = "Number of threads that the process contains.",
			aggregation = "MAX",
			groupby_aggregation = "MAX",
			colsize = 5
		},
		{
			name = "VIRT",
			field = "thread.vmsize",
			description = "total virtual memory for the process (as kb).",
			aggregation = "MAX",
			groupby_aggregation = "MAX",
			colsize = 9
		},
		{
			name = "RES",
			field = "thread.vmrss",
			description = "resident non-swapped memory for the process (as kb).",
			aggregation = "MAX",
			groupby_aggregation = "MAX",
			colsize = 9
		},
		{
			name = "FILE",
			field = "evt.buflen.file",
			description = "Total (input+output) file I/O bandwidth generated by the process, in bytes per second.",
			aggregation = "TIME_AVG",
			groupby_aggregation = "SUM",
			colsize = 8
		},
		{
			name = "NET",
			field = "evt.buflen.net",
			description = "Total (input+output) network I/O bandwidth generated by the process, in bytes per second.",
			aggregation = "TIME_AVG",
			groupby_aggregation = "SUM",
			colsize = 8
		},
		{
			tags = {"containers"},
			name = "Container",
			field = "container.name",
			colsize = 20
		},
		{
			name = "Command",
			description = "The full command line of the process.",
			field = "proc.exeline",
			aggregation = "MAX",
			colsize = 0
		}
	},
	actions = 
	{
		{
			hotkey = "k",
			command = "kill %proc.pid",
			description = "kill",
			wait_finish = false
		},
		{
			hotkey = "9",
			command = "kill -9 %proc.pid",
			description = "kill -9",
			wait_finish = false
		},
		{
			hotkey = "c",
			command = "gcore %proc.pid",
			description = "generate core",
		},
	},
}
