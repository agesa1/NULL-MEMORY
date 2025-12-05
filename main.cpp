#include "JFK.h"

int sensitiveData = 0X8907457;
char buffer[256] = "wasted";

void ProcessData(int* data, size_t size) {
    std::cout << "\n[FUNCTION] ProcessData called" << std::endl;
    NULL_MEMORY(data, size);
}

void SecureBuffer(char* buf, size_t size) {
    std::cout << "\n[FUNCTION] SecureBuffer called" << std::endl;
    NULL_MEMORY(buf, size);
}

int main() {

    std::cout << "\n[INFO] Initial state:" << std::endl;
    std::cout << "[DATA] sensitiveData = " << sensitiveData << std::endl;
    std::cout << "[DATA] buffer = " << buffer << std::endl;

    ProcessData(&sensitiveData, sizeof(sensitiveData));
    SecureBuffer(buffer, sizeof(buffer));

    HIDE_MODULE(L"kernel32.dll");

    std::cout << "\n========================================" << std::endl;
    std::cout << "[INFO] All memory regions secured" << std::endl;
    std::cout << "[STATUS] Press Enter to exit..." << std::endl;
    std::cin.get();

    return 0;
}
