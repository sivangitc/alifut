#include "event_listen.h"

#include <evntrace.h>
#include <Windows.h>
#include <psapi.h>


void set_event_trace_logfile(PEVENT_TRACE_LOGFILEW plog_file) {
	plog_file->LogFileName = NULL;
	plog_file->LoggerName = (LPWSTR)L"alifut trace session";
	plog_file->DUMMYUNIONNAME.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD;
}

void list_events() {
	EVENT_TRACE_LOGFILEW log_event_trace = ;
	PROCESSTRACE_HANDLE traceHandle = OpenTraceW(&log_event_trace);

}
