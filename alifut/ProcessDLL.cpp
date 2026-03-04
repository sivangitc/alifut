#include "ProcessDLL.h"
#include <iostream>
#include <vector>
#include <list>
#include <string>
#include <codecvt>
#include <locale>
#include <exception>

#include <Windows.h>
#include <psapi.h>

#define NAME_SIZE  256
#define MODULES_LIST_SIZE  100


/*
This function gets process and module handlers' and 
return the name of the module.
in:
HANDLE processHandle - the process handle.
HMODULE module - the moudle handle.
out:
string - the module name.
*/
std::string getMoudleName(HANDLE processHandle, HMODULE module) {
	TCHAR name[NAME_SIZE] = { 0 };
	// get the name.
	GetModuleFileNameEx(
		processHandle,
		module,
		name,
		NAME_SIZE
	);
	
	std::wstring wstr = std::wstring(name);
	//setup converter
	using convert_type = std::codecvt_utf8<wchar_t>;
	std::wstring_convert<convert_type, wchar_t> converter;

	//use converter (.to_bytes: wstr->str)
	std::string str = converter.to_bytes(wstr);
	return str;
}


/*
This function gets processs id and return the dlls as string.
in:
int pid - the process id.
out:
the dll's string.
*/
std::string getProcDlls(int pid) {
	std::string dlls = "";
	// get the process
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);;
	HMODULE modules[MODULES_LIST_SIZE];
	DWORD  size = 0;
	// loop over the moudles, and get the dlls as string.
	if (EnumProcessModules(hProcess, modules, sizeof(modules), &size)) {
		for (int i = 0; i < size / sizeof(HMODULE); i++) {
			std::string module = getMoudleName(hProcess, modules[i]);
			if (module.size() > 2 && module[module.size() - 1] == 'l') {
				dlls += module + "\n";
			}
		}
	}
	return dlls;
}

/*
This function is to check wether thread is suspended.
in:
int tid - the thread id.
out:
bool - if the thread is suspended or not.
*/			
bool IsThreadSuspended(int tid) {
	DWORD count = 0;
	HANDLE thread;
	// get the thread
	thread = OpenThread(THREAD_ALL_ACCESS, false, tid);
	count = ResumeThread(thread);
	if (count == (DWORD)-1) {
		//error
		throw std::exception();
	}

	if (count > 0) { // this mean it was suspended
		return true;
	}
	else { // the count was 0 == it wasn't suspended
		return false;
	}
}