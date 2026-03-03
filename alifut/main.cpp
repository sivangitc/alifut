#include <iostream>
#include "ProcessDLL.h"

int main() {
	std::cout << getProcDlls(8036).c_str();
	return 0;
}
