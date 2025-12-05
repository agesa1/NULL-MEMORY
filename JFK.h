#ifndef MER_H
#define MER_H

#include <windows.h>
#include <winternl.h>
#include <iostream>
#include <iomanip>

#define PROTECT_REGION(addr, size) ProtectMemoryRegion((LPVOID)addr, size)
#define HIDE_MODULE(name) HideModuleFromPEB(name)
#define NULL_MEMORY(addr, size) NullifyMemoryRegion((LPVOID)addr, size)

inline void PrintHexDump(LPVOID address, SIZE_T size) {
    unsigned char* ptr = static_cast<unsigned char*>(address);
    std::cout << "[HEX DUMP] Address: 0x" << std::hex << address << std::dec << " Size: " << size << " bytes" << std::endl;

    for (SIZE_T i = 0; i < size; i += 16) {
        std::cout << "  0x" << std::hex << std::setfill('0') << std::setw(8) << (uintptr_t)(ptr + i) << ": ";

        SIZE_T lineSize = (i + 16 <= size) ? 16 : (size - i);
        for (SIZE_T j = 0; j < lineSize; j++) {
            std::cout << std::setw(2) << (int)ptr[i + j] << " ";
        }

        for (SIZE_T j = lineSize; j < 16; j++) {
            std::cout << "   ";
        }

        std::cout << " | ";
        for (SIZE_T j = 0; j < lineSize; j++) {
            char c = ptr[i + j];
            std::cout << (c >= 32 && c <= 126 ? c : '.');
        }
        std::cout << std::dec << std::endl;
    }
}

inline void ProtectMemoryRegion(LPVOID address, SIZE_T size) {
    DWORD oldProtect;

    std::cout << "\n[DEBUG] Protecting memory region..." << std::endl;
    PrintHexDump(address, size);

    if (VirtualProtect(address, size, PAGE_NOACCESS, &oldProtect)) {
        std::cout << "[SUCCESS] Memory protected at: 0x" << std::hex << address << std::dec << " Size: " << size << std::endl;
    }
    else {
        std::cout << "[ERROR] Failed to protect memory at: 0x" << std::hex << address << std::endl;
    }
}

inline void NullifyMemoryRegion(LPVOID address, SIZE_T size) {
    DWORD oldProtect;

    std::cout << "\n[DEBUG] Before nullification:" << std::endl;
    PrintHexDump(address, size);

    if (VirtualProtect(address, size, PAGE_READWRITE, &oldProtect)) {
        ZeroMemory(address, size);

        std::cout << "\n[DEBUG] After nullification:" << std::endl;
        PrintHexDump(address, size);

        VirtualProtect(address, size, PAGE_NOACCESS, &oldProtect);
        std::cout << "[SUCCESS] Memory nullified and protected at: 0x" << std::hex << address << std::dec << " Size: " << size << std::endl;
    }
    else {
        std::cout << "[ERROR] Failed to nullify memory at: 0x" << std::hex << address << std::endl;
    }
}

inline void HideModuleFromPEB(const wchar_t* moduleName) {
    std::wcout << L"\n[DEBUG] Attempting to hide module: " << moduleName << std::endl;

    PPEB peb = (PPEB)__readgsqword(0x60);
    PLIST_ENTRY head = &peb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY current = head->Flink;

    while (current != head) {
        PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        if (entry->FullDllName.Buffer && wcsstr(entry->FullDllName.Buffer, moduleName)) {
            std::wcout << L"[DEBUG] Module found at: 0x" << std::hex << (uintptr_t)entry->DllBase << std::dec << std::endl;

            entry->InMemoryOrderLinks.Flink->Blink = entry->InMemoryOrderLinks.Blink;
            entry->InMemoryOrderLinks.Blink->Flink = entry->InMemoryOrderLinks.Flink;

            std::wcout << L"[SUCCESS] Module hidden from PEB: " << moduleName << std::endl;
            return;
        }
        current = current->Flink;
    }
    std::wcout << L"[ERROR] Module not found: " << moduleName << std::endl;
}

#endif
