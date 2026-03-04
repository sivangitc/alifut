#define INITGUID
#include <windows.h>
#include <evntrace.h>
#include <iostream>
#include <strsafe.h>
#include <wmistr.h>
#include <vector>
#include <string>
#include <regex>
#include <tdh.h>
#pragma comment(lib, "tdh.lib")
#include "ProcessInfo.h"
#include "events.h"

#define START_OPCODE 1
#define END_OPCODE 2

#define PROCESS_TYPE PROCESS_VERSION
#define PROCESS_VERSION 4
#define PROCESS_PID_INDEX 1
#define PROCESS_IMAGEFILE_INDEX 8

#define NETWORK_TYPE NETWORK_VERSION
#define NETWORK_VERSION 2
#define CONNECT_OPCODE 12
#define NETWORK_PID_INDEX 0
#define NETWORK_DST_IP_INDEX 2
#define NETWORK_DST_PORT_INDEX 4

static int filter_pid = -1;
static std::string filter_name;

typedef struct {
	wchar_t exe_name[MAX_PATH];
} process_event_info_t;

typedef struct {
	int dst_port;
	wchar_t dst_ip[16];
} tcp_connect_event_info_t;

typedef struct {
	int type;
	int opcode;
	int pid;
	int tid;
	union {
		process_event_info_t process;
		tcp_connect_event_info_t tcp_connect;
	} data;
} event_info_t;


_Ret_z_ LPCWSTR TeiString(std::vector<BYTE> &buf, unsigned offset)
{
	return reinterpret_cast<LPCWSTR>(buf.data() + offset);
}

// filters out event types that are not ours
bool filter_event_basic(PEVENT_RECORD pevent_record, int* type) {
	int opcode = pevent_record->EventHeader.EventDescriptor.Opcode;
	int version = pevent_record->EventHeader.EventDescriptor.Version;
	switch (version) {
	case (PROCESS_VERSION):
		*type = PROCESS_TYPE;
		return (opcode == START_OPCODE || opcode == END_OPCODE);
	case (NETWORK_VERSION):
		*type = NETWORK_TYPE;
		return opcode == CONNECT_OPCODE;
	}
	return false;
}

bool filter_event_user(event_info_t* pevent_info) {
	if (pevent_info->type == PROCESS_TYPE) {
		if (filter_pid != -1) {
			return pevent_info->pid == filter_pid;
		}
		if (!filter_name.empty()) {
			std::wstring ws = pevent_info->data.process.exe_name;
			std::string conv_str(ws.begin(), ws.end());
			const std::regex r(filter_name);
			return std::regex_search(conv_str, r);
		}
	}
	return true;
}

void handle_process_property(int property_idx, std::vector<BYTE>& record_buf, EVENT_PROPERTY_INFO const& epi, 
	std::vector<wchar_t>& propertyBuffer, bool* is_last_prop, event_info_t* event_info) {
	switch (property_idx) {
	case (PROCESS_PID_INDEX):
		event_info->pid = std::stoul(propertyBuffer.data(), nullptr, 16);
		return;
	case (PROCESS_IMAGEFILE_INDEX):
		memcpy(event_info->data.process.exe_name, propertyBuffer.data(), propertyBuffer.size() * 2);
		*is_last_prop = true;
		return;
	}
}

void handle_network_property(int property_idx, std::vector<BYTE>& record_buf, EVENT_PROPERTY_INFO const& epi, 
	std::vector<wchar_t>& propertyBuffer, bool* is_last_prop, event_info_t* event_info) {
	switch (property_idx) {
	case (NETWORK_PID_INDEX):
		event_info->pid = std::stoul(propertyBuffer.data(), nullptr, 10);
		return;
	case (NETWORK_DST_IP_INDEX):
		memcpy(event_info->data.tcp_connect.dst_ip, propertyBuffer.data(), propertyBuffer.size() * 2);
		return;
	case (NETWORK_DST_PORT_INDEX):
		event_info->data.tcp_connect.dst_port = std::stoul(propertyBuffer.data(), nullptr, 10);
		*is_last_prop = true;
		return;
	}
}

void print_event(event_info_t* pevent_info) {
	switch (pevent_info->type) {
	case (PROCESS_TYPE):
		std::wcout << L"pid: " << pevent_info->pid << std::endl;
		std::wcout << L"executable: " << pevent_info->data.process.exe_name << std::endl;
		break;
	case (NETWORK_TYPE):
		std::wcout << L"pid: " << pevent_info->pid << std::endl;
		std::wcout << L"dest ip: " << pevent_info->data.tcp_connect.dst_ip << std::endl;
		std::wcout << L"dest port: " << pevent_info->data.tcp_connect.dst_port << std::endl;
		break;
	}
}

static VOID eventRecordCallback(PEVENT_RECORD pevent_record) {
	PTRACE_EVENT_INFO buf;
	std::vector<BYTE> teiBuffer;
	event_info_t event_info = { 0 };
	ULONG cb = static_cast<ULONG>(teiBuffer.size());
	
	if (!filter_event_basic(pevent_record, &event_info.type))
		return;

	event_info.tid = pevent_record->EventHeader.ThreadId;
	event_info.opcode = pevent_record->EventHeader.EventDescriptor.Opcode;
	TDHSTATUS status = TdhGetEventInformation(pevent_record, 0, NULL, reinterpret_cast<TRACE_EVENT_INFO*>(teiBuffer.data()), &cb);
	if (status == ERROR_INSUFFICIENT_BUFFER) {
		teiBuffer.resize(cb);
		status = TdhGetEventInformation(pevent_record, 0, NULL, reinterpret_cast<TRACE_EVENT_INFO*>(teiBuffer.data()), &cb);
	}
	if (status != ERROR_SUCCESS) {
		std::cout << "getEventInfo failed! " << status << std::endl;
		return;
	}
	
	unsigned long pointer_size = pevent_record->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER ? 4 : 8;

	buf = reinterpret_cast<TRACE_EVENT_INFO*>(teiBuffer.data());
	PBYTE pbData = static_cast<BYTE *>(pevent_record->UserData);
	BYTE const* pbDataEnd = pbData + pevent_record->UserDataLength;

	for (unsigned int i = 0; i < buf->TopLevelPropertyCount; i++) {
		bool is_last_property = false;
		EVENT_PROPERTY_INFO const& epi = buf->EventPropertyInfoArray[i];
		std::vector<wchar_t> propertyBuffer = { 0 };
		while (1) {
			ULONG cbBuffer = static_cast<ULONG>(propertyBuffer.size() * 2);
			USHORT cbUsed = 0;
			status = TdhFormatProperty(buf, NULL, pointer_size, epi.nonStructType.InType, epi.nonStructType.OutType,
				epi.length, (USHORT)(pbDataEnd - pbData), pbData, &cbBuffer, propertyBuffer.data(), &cbUsed);
			if (status == ERROR_INSUFFICIENT_BUFFER && propertyBuffer.size() < cbBuffer / 2) {
				propertyBuffer.resize(cbBuffer / 2);
				continue;
			}
			if (status != ERROR_SUCCESS) {
				std::cout << cbBuffer << " " << propertyBuffer.size() << std::endl;
				std::cout << "tdhformatProperty failed " << status << std::endl;
			}
			else {
				switch (event_info.type) {
				case (PROCESS_TYPE):
					handle_process_property(i, teiBuffer, epi, propertyBuffer, &is_last_property, &event_info);
					break;
				case (NETWORK_TYPE):
					handle_network_property(i, teiBuffer, epi, propertyBuffer, &is_last_property, &event_info);
					break;
				}
			}
			
			pbData += cbUsed;
			break;
		}
		if (is_last_property)
			break;
	}

	if (!filter_event_user(&event_info))
		return;
	std::wcout << L"\n" << TeiString(teiBuffer, buf->TaskNameOffset) << " " << TeiString(teiBuffer, buf->OpcodeNameOffset) << std::endl;
	print_event(&event_info);

	if (event_info.type == PROCESS_TYPE && event_info.opcode == START_OPCODE) {
		// -------------------IF THE THREAD IS SUSPENDED---------------
		//if(IsThreadSuspended(event_info.tid)){ // its a thread id.
		//	std::cout << " This thread is suspended" << std::endl;
		//}else{
		//	std::cout << " This thread is not suspened" << std::endl;
		//}
		// ---------------------------THE PROCESS DLLS-----------------
		std::cout << getProcDlls(event_info.pid) << std::endl;
	}
}


void set_event_trace_properties(PEVENT_TRACE_PROPERTIES ptrace_props, bool with_tcp) {
	ptrace_props->Wnode.BufferSize = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(KERNEL_LOGGER_NAMEW);
	ptrace_props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
	ptrace_props->Wnode.Guid = SystemTraceControlGuid;
	ptrace_props->Wnode.ClientContext = 1;
	ptrace_props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
	ptrace_props->EnableFlags = EVENT_TRACE_FLAG_PROCESS;
	if (with_tcp) {
		ptrace_props->EnableFlags |= EVENT_TRACE_FLAG_NETWORK_TCPIP;
	}
	ptrace_props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
	StringCbCopy((LPWSTR)((char*)ptrace_props + ptrace_props->LoggerNameOffset), sizeof(KERNEL_LOGGER_NAMEW), KERNEL_LOGGER_NAMEW);
}

void list_events(bool with_tcp) {
	TRACEHANDLE startTraceHandle;
	BYTE buf[sizeof(EVENT_TRACE_PROPERTIES) + sizeof(KERNEL_LOGGER_NAMEW)] = { 0 };
	EVENT_TRACE_PROPERTIES* ptrace_props = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(buf);
	set_event_trace_properties(ptrace_props, with_tcp);

	ULONG res = ControlTraceW(0, KERNEL_LOGGER_NAMEW, ptrace_props, EVENT_TRACE_CONTROL_STOP);
	if (res != ERROR_SUCCESS && res != ERROR_WMI_INSTANCE_NOT_FOUND) {
		std::cout << "ControlTrace failed! " << res << std::endl;
		return;
	}
	
	set_event_trace_properties(ptrace_props, with_tcp);
	res = StartTrace(&startTraceHandle, (LPWSTR)KERNEL_LOGGER_NAMEW, ptrace_props);
	if (res != ERROR_SUCCESS) {
		std::cout << "StartTrace failed! " << res << std::endl;
		return;
	}

	EVENT_TRACE_LOGFILE trace = { 0 };
	TDHSTATUS status = ERROR_SUCCESS;
	trace.LogFileName = NULL;
	trace.LoggerName = (LPWSTR)KERNEL_LOGGER_NAMEW;
	trace.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_RAW_TIMESTAMP | PROCESS_TRACE_MODE_EVENT_RECORD;
	trace.EventRecordCallback = eventRecordCallback;

	auto h_trace = OpenTrace(&trace);
	if (h_trace == INVALID_PROCESSTRACE_HANDLE) {
		std::cout << "OpenTrace failed :( " << GetLastError() << std::endl;
		return;
	}

	status = ProcessTrace(&h_trace, 1, 0, 0); // blocking
	std::cout << "status: " << status << std::endl;
	CloseTrace(h_trace);

	set_event_trace_properties(ptrace_props, with_tcp);
	res = ControlTraceW(0, KERNEL_LOGGER_NAMEW, ptrace_props, EVENT_TRACE_CONTROL_STOP);
	if (res != ERROR_SUCCESS && res != ERROR_WMI_INSTANCE_NOT_FOUND) {
		std::cout << "ControlTrace failed! " << res << std::endl;
		return;
	}
}

void filterEventsByPid(int pid)
{
	std::cout << " filterEventsByPid: " << pid << std::endl;
	filter_pid = pid;
	list_events();
}

void filterEventsByName(std::string name)
{
	std::cout << " filterEventsByName: " << name << std::endl;
	filter_name = name;
	list_events();
}

void filterWithTCP()
{
	std::cout << " filterEventsWithTCP" << std::endl;
	list_events(true);
}
