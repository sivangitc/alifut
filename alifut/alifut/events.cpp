#define INITGUID
#include <windows.h>
#include <evntrace.h>
#include <iostream>
#include <strsafe.h>
#include <wmistr.h>
#include <vector>
#include <string>
#include <tdh.h>
#pragma comment(lib, "tdh.lib")

#include "events.h"

#define START_OPCODE 1
#define END_OPCODE 2

#define PROCESS_VERSION 3
#define PID_INDEX 1
#define IMAGEFILE_INDEX 8

#define NETWORK_VERSION 2
#define CONNECT_OPCODE 15

_Ret_z_ LPCWSTR TeiString(std::vector<BYTE> &buf, unsigned offset)
{
	return reinterpret_cast<LPCWSTR>(buf.data() + offset);
}

bool filter_event(PEVENT_RECORD pevent_record) {
	int opcode = pevent_record->EventHeader.EventDescriptor.Opcode;
	switch (pevent_record->EventHeader.EventDescriptor.Version) {
	case (PROCESS_VERSION):
		return (opcode == START_OPCODE || opcode == END_OPCODE);
	case (NETWORK_VERSION):
		return opcode == CONNECT_OPCODE;
	}
}

void handle_process_property(int property_idx, std::vector<BYTE>& record_buf, EVENT_PROPERTY_INFO const& epi, std::vector<wchar_t>& propertyBuffer) {
	switch (property_idx) {
	case (PID_INDEX):
		std::wcout << (epi.NameOffset ? TeiString(record_buf, epi.NameOffset) : L"(noname)");
		std::wcout << ": " << std::stoul(propertyBuffer.data(), nullptr, 16) << std::endl;
		return;
	case (IMAGEFILE_INDEX):
		std::wcout << (epi.NameOffset ? TeiString(record_buf, epi.NameOffset) : L"(noname)");
		std::wcout << ": " << propertyBuffer.data() << std::endl;
		return;
	}
}

static VOID eventRecordCallback(PEVENT_RECORD pevent_record) {
	PTRACE_EVENT_INFO buf;
	std::vector<BYTE> teiBuffer;
	ULONG cb = static_cast<ULONG>(teiBuffer.size());

	if (!filter_event(pevent_record))
		return;

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
	std::wcout << L"\n" << TeiString(teiBuffer, buf->TaskNameOffset) << " " << TeiString(teiBuffer, buf->OpcodeNameOffset) << std::endl;
	PBYTE pbData = static_cast<BYTE *>(pevent_record->UserData);
	BYTE const* pbDataEnd = pbData + pevent_record->UserDataLength;

	for (unsigned int i = 0; i < buf->TopLevelPropertyCount; i++) {
		EVENT_PROPERTY_INFO const& epi = buf->EventPropertyInfoArray[i];
		std::vector<wchar_t> propertyBuffer = { 0 };
		while (1) {
			ULONG cbBuffer = static_cast<ULONG>(propertyBuffer.size() * 2);
			USHORT cbUsed = 0;
			status = TdhFormatProperty(buf, NULL, pointer_size, epi.nonStructType.InType, epi.nonStructType.OutType,
				epi.length, pbDataEnd - pbData, pbData, &cbBuffer, propertyBuffer.data(), &cbUsed);
			if (status == ERROR_INSUFFICIENT_BUFFER && propertyBuffer.size() < cbBuffer / 2) {
				propertyBuffer.resize(cbBuffer / 2);
				continue;
			}
			if (status != ERROR_SUCCESS) {
				std::cout << cbBuffer << " " << propertyBuffer.size() << std::endl;
				std::cout << "tdhformatProperty failed " << status << std::endl;
			}
			else {
				handle_process_property(i, teiBuffer, epi, propertyBuffer);
			}
			
			pbData += cbUsed;
			break;
		}
	}
}


void set_event_trace_properties(PEVENT_TRACE_PROPERTIES ptrace_props) {
	ptrace_props->Wnode.BufferSize = 4096;
	ptrace_props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
	ptrace_props->Wnode.Guid = SystemTraceControlGuid;
	ptrace_props->Wnode.ClientContext = 1;
	ptrace_props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
	ptrace_props->EnableFlags = EVENT_TRACE_FLAG_PROCESS | EVENT_TRACE_FLAG_NETWORK_TCPIP;
	ptrace_props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
	ptrace_props->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(KERNEL_LOGGER_NAMEW);
	StringCbCopy((LPWSTR)((char*)ptrace_props + ptrace_props->LogFileNameOffset), sizeof(KERNEL_LOGGER_NAMEW), KERNEL_LOGGER_NAMEW);
}

void list_events() {
	TRACEHANDLE startTraceHandle;
	EVENT_TRACE_PROPERTIES trace_props = { 0 };
	set_event_trace_properties(&trace_props);

	ULONG res = ControlTraceW(0, KERNEL_LOGGER_NAMEW, &trace_props, EVENT_TRACE_CONTROL_STOP);
	if (res != ERROR_SUCCESS && res != ERROR_WMI_INSTANCE_NOT_FOUND) {
		std::cout << "ControlTrace failed! " << res << std::endl;
		return;
	}
	
	res = StartTrace(&startTraceHandle, (LPWSTR)KERNEL_LOGGER_NAMEW, &trace_props);
	if (res != ERROR_SUCCESS) {
		std::cout << "StartTrace failed! " << res << std::endl;
		return;
	}

	create_realtime_consumer();

	CloseTrace(startTraceHandle);
}

void create_realtime_consumer()
{
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
}
