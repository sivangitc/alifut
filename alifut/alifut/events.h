#pragma once
#include <evntrace.h>
#include <string>

void list_events();
void filterEventsByPid(int pid);
void filterEventsByName(std::string name);



