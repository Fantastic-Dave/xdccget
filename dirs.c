
#include "dirs.h"

#ifdef WINDOWS_BUILD
	#include <windows.h>
	#include <Shlobj.h>
#else
	#include <pwd.h>
	#include <unistd.h>
	#include <sys/types.h>
#endif

const char* getPathSeperator() {
#ifdef WINDOWS_BUILD
	return "\\";
#else
	return "/";
#endif
}

const char* getHomeDir() {
#ifdef WINDOWS_BUILD
	WCHAR path[MAX_PATH];
	char *cpath = (char*) malloc(sizeof(char) * MAX_PATH);
	if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_PROFILE, NULL, 0, path))) {
		wcstombs(cpath,path,MAX_PATH);

		return (const char*) cpath;
	}
	return NULL;
#else
	struct passwd *pw = getpwuid(getuid());
	const char *homedir = pw->pw_dir;
	return homedir;
#endif
 }
