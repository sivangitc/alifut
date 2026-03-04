#pragma once
#include <evntrace.h>
#include <string>

void list_events(bool with_tcp = false);
void filterEventsByPid(int pid);
void filterEventsByName(std::string name);
void filterWithTCP();



