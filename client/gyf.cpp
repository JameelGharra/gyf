#include "client.hpp"
#include <exception>
#include <iostream>
#define _CRTDBG_MAP_ALLOC
#include <crtdbg.h>


int main(int argc, char* argv[]) {
	//_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);

	try {
		Client client;
		client.start();
	}
	catch (std::exception& e) {
		std::cerr << e.what() << std::endl;
	}
	return 0;
}