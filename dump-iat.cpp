#include <cstdio>
#include <Windows.h>
#include <TlHelp32.h>
#include "utils/utils.h"


struct ParsedArgs {

    bool hasHelp = false;

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
            printf("kutas\n");
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
           "   -h, --help                     Shows this help message.\n");
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

   
}