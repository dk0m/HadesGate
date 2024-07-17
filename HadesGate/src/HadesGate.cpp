#include <iostream>
#include<vector>
#include "./Pe/Pe.h"


struct SystemCall {
    LPCSTR fnName;
    DWORD Ssn;
};

DWORD GetSSN(PBYTE fnAddr) {

    WORD cw = 0;
    while (TRUE) {

        // check for jmp, in this case we are done.
        if (*(PBYTE)(fnAddr + cw) == 0xE9) {
            return NULL;
        }

        // check for mov eax, XX_XX (XX_XX is SSN)

        if (*(PBYTE)(fnAddr + cw) == 0xB8) {

            DWORD ssn = *(PDWORD)(fnAddr + cw + 1); // XX_XX (the ssn)
            return ssn;
        }


        cw++;
    }
}

std::vector<SystemCall> GetSystemCalls() {
    std::vector<SystemCall> returnedSystemCalls;

    Pe peImage = ParsePeImage("ntoskrnl.exe");

    auto exportDirectory = peImage.ExportDirectory;
    auto peBase = (DWORD_PTR)peImage.ImageBase;

    PDWORD funcNames = (PDWORD)(peBase + exportDirectory->AddressOfNames);
    PDWORD funcAddrs = (PDWORD)(peBase + exportDirectory->AddressOfFunctions);
    PWORD funcNameOrds = (PWORD)(peBase + exportDirectory->AddressOfNameOrdinals);

    for (size_t i = 0; i < exportDirectory->NumberOfFunctions; i++)
    {
        LPCSTR fnName = (LPCSTR)(peBase + funcNames[i]);
        WORD fnOrd = (WORD)(funcNameOrds[i]);
        DWORD fnRva = (DWORD)(funcAddrs[fnOrd]);

        PBYTE fnAddr = (PBYTE)(peBase + fnRva);

        if (!_strnicmp(fnName, "Zw", 2)) {

            DWORD ssn = GetSSN(fnAddr);
            
            returnedSystemCalls.push_back(

                SystemCall {
                    fnName,
                    ssn
                }

            );

        }
    }

    return returnedSystemCalls;
}

int main()
{
    auto systemCalls = GetSystemCalls();

    for (SystemCall& systemCall : systemCalls) {

        if (systemCall.Ssn != NULL) {
            printf("[+] %s: 0x%x\n", systemCall.fnName, systemCall.Ssn);
        }
        
    }
    
}
