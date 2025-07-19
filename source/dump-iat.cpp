#include <cstdio>
#include <cstdlib>
#include <Windows.h>
#include <TlHelp32.h>
#include <memory>
#include <cwchar>
#include "IATDumper/IATDumper.h"


struct ParsedArgs {

    bool hasHelp = false;
    bool hasShowModuleBases = false;
    bool hasCheckIntegrity = false;

    bool hasMalformedArgument = false;
    const wchar_t* malformedArgumemt = nullptr;

    bool hasProcessName = false;
    const wchar_t* processName = nullptr;

    bool hasPid = false;
    const wchar_t* pid = nullptr;

    bool hasModuleToDump = false;
    const wchar_t* moduleToDump = nullptr;

    bool hasImportModule = false;
    const wchar_t* importModule = nullptr;

    
};




/*
 *  The function checks which arguments were passed and extracts their value into OUT ParsedArgs struct.
 *  It automatically exits if malformed argument or help argument has been found.
 */

// TODO: Add warnings if argument is used more than once.
void parseArguments(IN int argc, IN wchar_t** argv, OUT ParsedArgs* args) {

    memset(args, 0, sizeof(*args));

    for (int i = 1; i < argc; ++i) {

        if (wcscmp(argv[i], L"-h") == 0 || wcscmp(argv[i], L"--help") == 0) {
            args->hasHelp = true;
            return;
        }
        else if ((i + 1 < argc) && wcscmp(argv[i], L"-p") == 0 && *argv[i + 1] != L'-') {
            args->hasProcessName = true;
            args->processName = argv[++i];
        }
        else if ((i + 1 < argc) && wcscmp(argv[i], L"-pid") == 0 && *argv[i + 1] != L'-') {
            args->hasPid = true;
            args->pid = argv[++i];
        }
        else if ((i + 1 < argc) && wcscmp(argv[i], L"-m") == 0 && *argv[i + 1] != L'-') {
            args->hasModuleToDump = true;
            args->moduleToDump = argv[++i];
        }
        else if ((i + 1 < argc) && wcscmp(argv[i], L"-M") == 0 && *argv[i + 1] != L'-') {
            args->hasImportModule = true;
            args->importModule = argv[++i];
        }
        else if (wcscmp(argv[i], L"-b") == 0) {
            args->hasShowModuleBases = true;
        }
        else if (wcscmp(argv[i], L"--check-iat-integrity") == 0) {
            args->hasCheckIntegrity = true;
        }
        else {
            args->hasMalformedArgument = true;
            args->malformedArgumemt = argv[i];
            return;
        }

        
    }

}


void printHelp() {

    printf(" Usage: dump-iat [options]\n"
           "   -p   <process_name>            Specify target process by name.\n"
           "   -pid <process_id>              Specity targed process by ID.\n"
           "   -m   <module_name.dll/exe>     Dumps IAT of this specific module inside a process. Defaults to .exe if ignored.\n"
           "   -M   <module_name.dll/.exe>    Shows imports only from this specific module. The module has to be loaded inside the process.\n"
           "   -h, --help                     Shows this help message.\n"
           "   -b                             Shows the module load base alongside it's name when showing imports from it.\n"
           "   --check-iat-integrity          Attempts to check if the IAT entries were hooked."); // not implemented
}


int wmain(IN int argc, IN wchar_t** argv)
{

    if (!(argc > 1)) {
        printf(" Error: The number of passed arguments is invalid.\n"
               " Usage: dump-iat [options]. For more help use: dump-iat -h.\n");
        return 1;
    }

    ParsedArgs args;
    parseArguments(argc, argv, &args);

    if (args.hasMalformedArgument) { // possible page fault if args.malformedArgumemt == nullptr -> add checks later
        wprintf(L" Error: Malformed or invalid argument found: %s.\n"
                 " For more help use: dump-iat -h\n", args.malformedArgumemt);
        return 1;
    }

    if (args.hasHelp) {
        printHelp();
        return 0;
    }

    if (args.hasProcessName && args.hasPid) {
        printf(" Error: Ambigious argument use. Both -p and -pid were specified.\n"
               " For more help use: dump-iat -h\n");
        return 1;
    }

    if (!args.hasProcessName && !args.hasPid) {
        printf(" Error: No process specified. Use -p or -pid.\n"
               " For more help use: dump-iat -h\n");
        return 1;
    }



    DWORD pid;
    std::unique_ptr<IATDumper> pDumper;

    if (args.hasProcessName) {

        std::optional<DWORD> optPid = IATDumper::getPidByName(args.processName);
        if (!optPid.has_value()) {
            printf(" Error: Invalid process name specified via -p flag. Ensure its a valid process's executable name.\n"
                   " For more help use: dump-iat -h\n");
            return 1;
        }

        pid = optPid.value();
    }
    else {

        wchar_t* end_chr;

        pid = std::wcstoul(args.pid, &end_chr, 10);

        if (*end_chr != '\0') {
            printf(" Error: Invalid pid specified via -pid flag. Ensure its a valid numerical-only pid.\n"
                   " For more help use: dump-iat -h\n");
            return 1;

        }

    }

    if (args.hasModuleToDump)
        pDumper = std::make_unique<IATDumper>(pid, args.moduleToDump);
    else
        pDumper = std::make_unique<IATDumper>(pid);


    IATSTATUS status = pDumper->configure();

    switch (status) {

    case IATSTATUS::INVALID_PID:
        printf(" Error: Invalid pid/process name specified via -pid or -p flag or high privilege process (will be fixed later with a kernel driver)\n"
               " For more help use: dump-iat -h\n");
        return 1;

    case IATSTATUS::UNSUPPORTED_ARCHITECTURE:
        printf(" Error: The software does not support ARM CPU's and PE's or any other architecture which is not x86.\n");
        return 1;

    case IATSTATUS::FAILURE:
        printf(" Error: Unknown error. Could be old 32bit system?\n");
        return 1;

    case IATSTATUS::INVALID_MODULE_BASE: // replace xxxxxx by the flag after adding an ability to pass manually an address of a module to dump an iat of (like -m but with an address instead of a name)
        printf(" Error: Module address passed by xxxxxxx to dump IAT from does not point to a valid PE file. Make sure that its valid.\n"
               " For more help use: dump-iat -h\n");
        return 1;
       
    case IATSTATUS::MODULE_NAME_NOT_FOUND:
        printf(" Error: Module name passed via -m is not valid.\n"
               " For more help use: dump-iat -h\n");
        return 1;
    }



    BOOL printSelectedDLL(std::unique_ptr<IATDumper>&pDumper, ParsedArgs & args);




    uintptr_t idx = 0;

    if (args.hasImportModule) {

        while (true) {

            IATSTATUS status = pDumper->changeCurrentDLLImportsEntry(idx);

            if (status == IATSTATUS::FAILURE)
            {
                printf(" Error: Unknown memory error.\n");
                return 1;
            }

            if (status == IATSTATUS::NULL_ENTRY) {

                printf(" Error: Module to dump specified with -M not found.\n"
                       " For more help use: dump-iat -h\n");

                return 1;
            }

                
            


            if (_wcsicmp(pDumper->readCurrentDLLNameW().data(), args.importModule) == 0) {

                BOOL returnValue = printSelectedDLL(pDumper, args);

                if (returnValue)
                    return 0;

                return 1;


 
            }

            ++idx;

        }

    }
    else {

        while (true) {

            IATSTATUS status = pDumper->changeCurrentDLLImportsEntry(idx);

            if (status == IATSTATUS::FAILURE)
            {
                printf(" Error: Unknown memory error.\n");
                return 1;
            }

            if (status == IATSTATUS::NULL_ENTRY) break;

            BOOL returnValue = printSelectedDLL(pDumper, args);

            if (!returnValue) return 1;

            ++idx;

        }


    }

    return 0;


}

BOOL printSelectedDLL(std::unique_ptr<IATDumper>& pDumper, ParsedArgs& args) {


    if (args.hasShowModuleBases) {

        uintptr_t moduleBase;

        IATSTATUS status = pDumper->_getModuleBaseByName(pDumper->readCurrentDLLNameW(), moduleBase);

        if (status != IATSTATUS::SUCCESS) {
            printf(" Error: Unknown error\n");
            return FALSE;
        }
            

        wprintf(L" %s | base: %p | import descriptor VA: %p\n", pDumper->readCurrentDLLNameW().data(), (void*)moduleBase, (void*)pDumper->getCurrentImportsEntryVA());
    }
        
    else
        wprintf(L" %s | import descriptor VA: 0x%p\n", pDumper->readCurrentDLLNameW().data(), (void*)pDumper->getCurrentImportsEntryVA());


    uintptr_t idx = 0;

    while (true) {

        IATSTATUS status = pDumper->setCurrentILTandIATentriesByIndex(idx);

        if (status == IATSTATUS::FAILURE) {

            printf(" Error: Unknown memory error.\n");
            return FALSE;
        }

        if (status == IATSTATUS::NULL_ENTRY)
            return TRUE;

        if (pDumper->isCurrentFunctionByOrdinal()) {
            printf("   ordinal: %u | ILT entry VA: 0x%p | IAT entry VA: 0x%p -> 0x%p\n", pDumper->getCurrentOrdinal(), (void*)pDumper->getCurrentILTEntryVA(), (void*)pDumper->getCurrentIATEntryVA(), (void*)pDumper->getCurrentIATEntry());
        }
        else {
            std::optional<std::string> functionName = pDumper->getCurrentILTEntryFunctionName();

            if (!functionName) {
                printf("Error: Reading function name failed.\n");
                return FALSE;
            }



            printf("   %s | ILT entry VA: 0x%p | IAT entry VA: 0x%p -> 0x%p\n", functionName.value().c_str(), (void*)pDumper->getCurrentILTEntryVA(), (void*)pDumper->getCurrentIATEntryVA(), (void*)pDumper->getCurrentIATEntry());

        }



        ++idx;
    }

}
