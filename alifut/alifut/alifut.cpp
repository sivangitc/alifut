#include "events.h"
#include <iostream>
#include <string>
#include <cctype>
#include <algorithm>

#define ERROR -1 
#define NAME_FLAG "--name"
#define PID_FLAG "--pid"
#define TCP_FLAG "--tcp"


// chaek if string is a number.
bool isNumber(const std::string& str) {
	return std::all_of(str.begin(), str.end(), ::isdigit);
}


int main(int argc, char* argv[])
{
	if (argc == 1) {
		list_events(true);
		return 0;
	}
	for (int i = 1; i < argc; i++) {
		if (std::strcmp(argv[i], TCP_FLAG) == 0) { // show tcp connections.
			filterWithTCP();
			break;
		}
		if (std::strcmp(argv[i], NAME_FLAG) == 0) { // filter by proces name.
			filterEventsByName(argv[i + 1]);
			break;
		}
		else if (std::strcmp(argv[i], PID_FLAG) == 0) { // filter by process id.
			if (isNumber(argv[i + 1]) == false) {
				std::cout << "USAGE: alifut.exe {[--pid <PID>] [--name <NAME>]}";
				return ERROR;
			}
			filterEventsByPid(std::stoi(argv[i + 1]));
			break;
		}
		else {
			std::cout << "USAGE: alifut.exe [--pid <PID>] [--name <NAME>]";
			return ERROR;
		}
	}
	return 0;
}
