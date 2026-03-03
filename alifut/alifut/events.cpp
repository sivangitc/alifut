#define INITGUID
#include <windows.h>
#include <evntrace.h>
#include <iostream>
#include <strsafe.h>
#include <wmistr.h>
#include <vector>
#include <tdh.h>
#pragma comment(lib, "tdh.lib")

#include "events.h"

#define LOGGERNAME KERNEL_LOGGER_NAMEW
#define LOGSESSION_NAME KERNEL_LOGGER_NAMEW
//#define LOGSESSION_NAME L"CyberLogEvent"

// {AE44CB98-BD11-4069-8093-770EC9258A12}
static const GUID SessionGuid =
{ 0xae44cb98, 0xbd11, 0x4069, { 0x80, 0x93, 0x77, 0xe, 0xc9, 0x25, 0x8a, 0x12 } };

//PEVENT_RECORD_CALLBACK eventRecordCallback;

static VOID eventRecordCallback(PEVENT_RECORD pevent_record) {
	PTRACE_EVENT_INFO buf;
	std::vector<BYTE> teiBuffer;
	ULONG cb = static_cast<ULONG>(teiBuffer.size());
	TDHSTATUS status = TdhGetEventInformation(pevent_record, 0, NULL, reinterpret_cast<TRACE_EVENT_INFO*>(teiBuffer.data()), &cb);
	if (status == ERROR_INSUFFICIENT_BUFFER) {
		teiBuffer.resize(cb);
		status = TdhGetEventInformation(pevent_record, 0, NULL, reinterpret_cast<TRACE_EVENT_INFO*>(teiBuffer.data()), &cb);
	}
	if (status != ERROR_SUCCESS) {
		std::cout << "getEventInfo failed! " << status << std::endl;
		return;
	}
	
	buf = reinterpret_cast<TRACE_EVENT_INFO*>(teiBuffer.data());
	std::cout << "received event!" << pevent_record->EventHeader.ProcessId << std::endl;
	std::cout << buf->EventPropertyInfoArray. << " " << buf->EventMessageOffset << std::endl;
	std::cout << buf->EventDescriptor.Id << " " << (int)buf->EventDescriptor.Opcode << std::endl;
}


void set_event_trace_logfile(PEVENT_TRACE_LOGFILE plog_file) {
	plog_file->LogFileName = NULL;
	plog_file->LoggerName = (LPWSTR)LOGGERNAME;
	plog_file->ProcessTraceMode = 0;
	plog_file->EventRecordCallback = eventRecordCallback;
}

void set_event_trace_properties(PEVENT_TRACE_PROPERTIES ptrace_props) {
	ptrace_props->Wnode.BufferSize = 4096;
	ptrace_props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
	ptrace_props->Wnode.Guid = SystemTraceControlGuid;
	ptrace_props->Wnode.ClientContext = 1;
	ptrace_props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
	ptrace_props->EnableFlags = EVENT_TRACE_FLAG_PROCESS;
	ptrace_props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
	ptrace_props->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(LOGSESSION_NAME);
	StringCbCopy((LPWSTR)((char*)ptrace_props + ptrace_props->LogFileNameOffset), sizeof(LOGSESSION_NAME), LOGSESSION_NAME);
}

void list_events() {
	TRACEHANDLE startTraceHandle;
	EVENT_TRACE_PROPERTIES trace_props = { 0 };
	set_event_trace_properties(&trace_props);

	ULONG res = ControlTraceW(0, LOGGERNAME, &trace_props, EVENT_TRACE_CONTROL_STOP);
	if (res != ERROR_SUCCESS && res != ERROR_WMI_INSTANCE_NOT_FOUND) {
		std::cout << "ControlTrace failed! " << res << std::endl;
		return;
	}
	
	res = StartTrace(&startTraceHandle, (LPWSTR)LOGGERNAME, &trace_props);

	if (res != ERROR_SUCCESS) {
		std::cout << "StartTrace failed! " << res << std::endl;
		return;
	}

	//wchar_t loggerName[] = EVENT_LOGGER_NAMEW;
	//EVENT_TRACE_LOGFILE log_event_trace = { 0 };
	//set_event_trace_logfile(&log_event_trace, (LPWSTR)EVENT_LOGGER_NAMEW);
	//TRACEHANDLE traceHandle = OpenTrace(&log_event_trace);
	//if (traceHandle == INVALID_PROCESSTRACE_HANDLE) {
	//	std::cout << "traceHandle failed! " << GetLastError() << std::endl;
	//	//CloseTrace(startTraceHandle);
	//	return;
	//}

	create_realtime_consumer();

	std::cout << "all good!" << std::endl;

	CloseTrace(startTraceHandle);
}

void create_realtime_consumer()
{
	EVENT_TRACE_LOGFILE trace = { 0 };
	TDHSTATUS status = ERROR_SUCCESS;
	trace.LogFileName = NULL;
	trace.LoggerName = (LPWSTR)LOGGERNAME;
	trace.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_RAW_TIMESTAMP | PROCESS_TRACE_MODE_EVENT_RECORD; // create real time sesion + event should be represented as EVENT_RECORD structure
	trace.EventRecordCallback = eventRecordCallback;

	auto h_trace = OpenTrace(&trace);
	if (h_trace == INVALID_PROCESSTRACE_HANDLE)
		throw std::runtime_error("Unable to open trace");

	status = ProcessTrace(&h_trace, 1, 0, 0); // this call blocks until either the session is stopped or an exception is occurred in event_callback
	std::cout << "status: " << status << std::endl;
	CloseTrace(h_trace);
}
