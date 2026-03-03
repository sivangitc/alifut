#include "ProcessDLL.h"
#include <iostream>
#include <vector>
#include <list>
#include <string>
#include <codecvt>
#include <locale>

#include <Windows.h>
#include <psapi.h>

#define NAME_SIZE  256
#define MODULES_LIST_SIZE  100

std::string getMoudleName(HANDLE processHandle, HMODULE module) {

	TCHAR name[NAME_SIZE] = { 0 };
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


std::string getProcDlls(int pid) {
	std::string dlls = "";
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);;
	HMODULE modules[MODULES_LIST_SIZE];
	DWORD  size = 0;
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
