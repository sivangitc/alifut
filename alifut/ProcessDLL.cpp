#include "ProcessDLL.h"
#include <iostream>
#include <vector>
#include <list>
#include <string>
#include <Windows.h>
#include <psapi.h>

#define NAME_SIZE  256
#define MODULES_LIST_SIZE  100

std::string getMoudleName(HANDLE processHandle, HMODULE module) {

	char name[NAME_SIZE] = { 0 };
	GetModuleBaseName(
		processHandle,
		module,
		(LPWSTR)name,
		NAME_SIZE
	);
	std::cout << name << "noam";
	return std::string(name);
}


std::vector<std::string> ProcessDlls(int pid) {
	std::vector<std::string> procDLLs;
	HANDLE processHandle = OpenProcess(READ_CONTROL, TRUE, pid);
	HMODULE modules[MODULES_LIST_SIZE];
	int size_n = 0;
	int* size = &size_n;
	EnumProcessModules(
		processHandle,
		modules,
		MODULES_LIST_SIZE,
		(LPDWORD)size
	);
	std::cout << pid;
	for (int i = 0; i < *size; i++) {
		procDLLs.push_back(getMoudleName(processHandle, modules[i]));
	}
	return procDLLs;
}


std::string getProcDlls(int pid) {
	std::string dlls = "";
	std::vector<std::string> dlList = ProcessDlls(pid);
	for (int i = 0; i < dlList.size(); i++)
	{
		dlls += dlList[i] + ", ";
	}
	return dlls;
}