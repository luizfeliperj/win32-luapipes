#define WIN32_LEAN_AND_MEAN
#define VC_EXTRA_LEAN

#include <stdio.h>
#include <tchar.h>
#include <windows.h>
#include <string>

extern "C" {
    #include <lua/lua.h>
    #include <lua/lauxlib.h>
    #include <lua/lualib.h>
}

#define WILDCARD            "XXXXXXXXXX"
#define READPIPE            "\\\\.\\pipe\\read-"
#define WRITEPIPE           "\\\\.\\pipe\\write-"
#define LUA_POPEN           "POPEN"
#define ESC                 0x1B
#define PIPEBUFSZ           8192
#define RETURNWITHERROR \
        { char *err = getlasterrorstring();\
        lua_pushnil(L); \
        lua_pushinteger(L, GetLastError()); \
        lua_pushstring(L, err); \
        LocalFree(err);\
        return 3; }
        
using namespace std;

typedef struct {
    DWORD nRead;
    OVERLAPPED ov;
    HANDLE read, write;
    DWORD nCurrent, nLast;
    PROCESS_INFORMATION pi;
    BYTE buffer[PIPEBUFSZ];
    struct {
        BYTE buffer[PIPEBUFSZ];
        DWORD len;
    } line;
} popen_t;

lua_State *lua = NULL;

BOOL WINAPI sigint(DWORD dwCtrlType)
{
    if (lua)
        lua_close(lua);
    return FALSE;
}

static LPTSTR getlasterrorstring () {
    LPTSTR lpMsgBuf;
    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | 
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        GetLastError(),
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR) &lpMsgBuf,
        0, NULL );
	return lpMsgBuf;
}

static int popen_readline (lua_State *L, popen_t *pData, int timeout)
{
    BOOL fOverlapped;
    DWORD e, dwTimeout;
    LPBYTE lpBuffer = pData->buffer;
    HANDLE handles[] = { pData->pi.hProcess, pData->ov.hEvent };
    
    if (timeout < 0)
        dwTimeout = INFINITE;
    else
        dwTimeout = (DWORD) timeout;
    do
    {
        if (!ReadFile (pData->read, pData->buffer, PIPEBUFSZ, &pData->nRead, &pData->ov))
        {
            if (GetLastError() != ERROR_IO_PENDING)
                return -2;
            else
                fOverlapped = TRUE;
        }
        else
            fOverlapped = FALSE;
            
        if (fOverlapped) {
            DWORD dwLeap, dwCurTime, dwOldTime = GetTickCount();
            e = WaitForMultipleObjects(sizeof(handles)/sizeof(*handles), handles, FALSE, dwTimeout);
            dwCurTime = GetTickCount();
            
            dwLeap = dwCurTime - dwOldTime + 1;
            
            if (dwTimeout >= dwLeap)
                dwTimeout -= dwLeap;
            else dwTimeout = 0;
        }
        else
            e = WaitForSingleObject (handles[0], 0);
        
        switch (e)
        {
            case WAIT_OBJECT_0:

                BOOL result = GetExitCodeProcess (pData->pi.hProcess, &e);
                if (result == FALSE)
                    return -1;
                return 1;
                break;;

            case WAIT_OBJECT_0 + 1:
                if (!GetOverlappedResult (pData->read, &pData->ov, &pData->nRead, TRUE))
                    return -3;
                break;;

            case WAIT_TIMEOUT:
                    if (!CancelIo (pData->read))
                        return -4;
                        
                    if (!GetOverlappedResult (pData->read, &pData->ov, &pData->nRead, FALSE) && GetLastError() != ERROR_OPERATION_ABORTED)
                        return -5;
                    
                break;;
        }
        
        for (DWORD pos = 0; pos < pData->nRead; pos++)
        {
            if (lpBuffer[pos] == ESC)
            {
                pos++;
                if (lpBuffer[pos] == ']')
                {
                    pos++;
                    while (lpBuffer[pos] != ';') pos++;
                }
                else if (lpBuffer[pos] == '[')
                {
                    pos++;
                    while (lpBuffer[pos] < '@' || lpBuffer[pos] > '~') pos++;
                }
                else
                {
                    while (lpBuffer[pos] < '@' || lpBuffer[pos] > '_') pos++;;
                }
            }
            
            else if (lpBuffer[pos] >= ' ' && lpBuffer[pos] <= '~')
                pData->line.buffer[pData->line.len++] = lpBuffer[pos];
                
            else if (lpBuffer[pos] == '\n' )
            {
                lua_pushinteger(L, pData->nLast++);
                lua_pushlstring(L, (const char*)pData->line.buffer, pData->line.len);
                pData->line.len = 0;
                lua_settable(L, -3);
            }
        }

        pData->nRead = 0;
    } while ((dwTimeout > 0) && (pData->nCurrent == pData->nLast));
    
    return 0;
}

static popen_t* popen_checkarg (lua_State *L)
{
    popen_t *pData = (popen_t*) luaL_checkudata(L, 1, LUA_POPEN);
    luaL_argcheck(L, pData != NULL, 1, "popen type expected");
    
    return pData;
}

static int popen_read (lua_State *L)
{
    popen_t *pData = popen_checkarg(L);
    int timeout = (int) luaL_optinteger (L, 2, -1);

    lua_getfenv(L, 1);
    if (!lua_istable(L, -1))
        luaL_error (L, "popen_read: Environment is not a table!");

    if (pData->nCurrent == pData->nLast)
    {
        int err = popen_readline (L, pData, timeout);
        if (err < 0)
        {
            LPTSTR str = getlasterrorstring();
            luaL_error (L, "popen_readline returned %d: %s", err, str);
            LocalFree (str);
        }
    }
    
    if (pData->nCurrent < pData->nLast)
    {
        lua_pushinteger (L, pData->nCurrent++);
        lua_pushvalue(L, -1); /* repete o valor da linha corrente no stack */
        lua_gettable (L, -3); /* pega do environment a linha corrente */
        lua_insert (L, -3);   /* insere a linha corrente na posicao do stack anterior a tabela*/
        lua_pushnil(L);       /* colocar um nil no stack*/
        lua_settable(L, -3);  /* seta o valor nil na posicao corrente para liberar memoria */
    }
    else
    {
        lua_pushnil(L);
        lua_insert(L, -2);
    }
    
    lua_pop(L, 1);        /* tira a tabela do environment do stack*/
    return 1;
}

static int popen_write (lua_State *L)
{
    OVERLAPPED ov;
    popen_t *pData = popen_checkarg(L);
    const char *line = luaL_checkstring(L, 2);
    
    luaL_argcheck(L, line != NULL, 2, "String expected");
    
    ZeroMemory (&ov, sizeof(OVERLAPPED));
    ov.hEvent = CreateEvent (NULL, TRUE, FALSE, NULL);
    
    WriteFile (pData->write, line, _tcslen(line) * sizeof (TCHAR), NULL, &ov);
    WaitForSingleObject(ov.hEvent, INFINITE);
    FlushFileBuffers (pData->write);
    
    CloseHandle(ov.hEvent);
    
    return 0;
}

static int popen_close (lua_State *L)
{
    popen_t *pData = popen_checkarg(L);
    
    if (pData->pi.hProcess != INVALID_HANDLE_VALUE)
    {
        TerminateProcess (pData->pi.hProcess, 0);
        pData->pi.hProcess = INVALID_HANDLE_VALUE;
    }
    
    if (pData->read != INVALID_HANDLE_VALUE)
    {
        CloseHandle(pData->read);
        pData->read = INVALID_HANDLE_VALUE;
    }
    
    if (pData->write != INVALID_HANDLE_VALUE)
    {
        CloseHandle(pData->write);
        pData->write = INVALID_HANDLE_VALUE;
    }
    
    return 0;
}

static int popen_create (lua_State *L)
{
    BOOL result;
    popen_t *pData;
    STARTUPINFO si;
    SECURITY_ATTRIBUTES sa;
    struct {
        HANDLE read, write, error;
    } child;
    
    char readpipe[] = READPIPE WILDCARD;
    char writepipe[] = WRITEPIPE WILDCARD;
    
    srand(GetTickCount());

    for (DWORD sizew = strlen(writepipe), sizer = strlen(readpipe), idx = 0; idx < strlen(WILDCARD);)
    {
        char c = rand();
        if ( ( c > '0' && c < '9' ) ||
             ( c > 'a' && c < 'z' ) ||
             ( c > 'A' && c < 'Z' ) )
        {
            readpipe[sizer-idx-1] = c;
            writepipe[sizew-idx-1] = c;
            idx++;
        }
    }

    const char *cmd = luaL_checkstring(L, 1);
    luaL_argcheck(L, cmd != NULL, 1, "String expected");
    
    sa.nLength=sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor=NULL;
    sa.bInheritHandle=TRUE;
    
    pData = (popen_t *)lua_newuserdata(L, sizeof(popen_t));
    
    child.read = CreateNamedPipe ( readpipe,
                                PIPE_ACCESS_INBOUND,
                                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE,
                                PIPE_UNLIMITED_INSTANCES,
                                PIPEBUFSZ,
                                PIPEBUFSZ,
                                INFINITE,
                                &sa);
	if (child.read == INVALID_HANDLE_VALUE)
	   RETURNWITHERROR;

    child.write = CreateNamedPipe ( writepipe,
                                PIPE_ACCESS_OUTBOUND,
                                PIPE_TYPE_BYTE,
                                PIPE_UNLIMITED_INSTANCES,
                                PIPEBUFSZ,
                                PIPEBUFSZ,
                                INFINITE,
                                &sa);
	if (child.write == INVALID_HANDLE_VALUE)
    	RETURNWITHERROR;

	pData->write = CreateFile ( readpipe,
	                        GENERIC_WRITE,
                            0,
                            &sa,
                            OPEN_EXISTING,
                            FILE_FLAG_OVERLAPPED,
                            NULL);
	if (pData->write == INVALID_HANDLE_VALUE)
	   RETURNWITHERROR;

	pData->read = CreateFile ( writepipe,
	                        GENERIC_READ,
	                        0,
	                        &sa,
                            OPEN_EXISTING,
                            FILE_FLAG_OVERLAPPED,
                            NULL);
	if (pData->read == INVALID_HANDLE_VALUE)
	   RETURNWITHERROR;

    result = DuplicateHandle( GetCurrentProcess(),
                            child.write,
                            GetCurrentProcess(),
                            &child.error,
                            0,
                            TRUE,
                            DUPLICATE_SAME_ACCESS);
    if (result == FALSE)
        RETURNWITHERROR;
	
	ZeroMemory(&si,sizeof(STARTUPINFO));
    si.cb=sizeof(STARTUPINFO);
    
    si.dwFlags=STARTF_USESTDHANDLES;
    si.hStdInput=child.read;
    si.hStdOutput=child.write;
    si.hStdError=child.error;
    
    result = CreateProcess (
                            NULL,(LPSTR)cmd,
                            NULL, NULL, TRUE,
                            CREATE_NO_WINDOW,
                            NULL, NULL, &si, &pData->pi);
    if (result == FALSE)
        RETURNWITHERROR;
    
    CloseHandle(child.write);
    CloseHandle(child.read);
    CloseHandle(child.error);

    ZeroMemory (&pData->ov, sizeof(OVERLAPPED));
    pData->ov.hEvent = CreateEvent (NULL, TRUE, FALSE, NULL);

    pData->nCurrent = pData->nLast =  pData->line.len = 0;
    
    luaL_getmetatable(L, LUA_POPEN);
    lua_setmetatable(L, -2);
    
    lua_newtable(L);
    lua_setfenv(L, -2);
    
    return 1;
}

static int lua_Sleep (lua_State *L)
{
    int interval = luaL_checkint(L, 1);
    
    Sleep (interval);
    return 0;
}

static int lua_Ticks(lua_State *L)
{
    int ticks = GetTickCount();
    
    lua_pushinteger(L, ticks);
    return 1;
}

int main(int argc, char *argv[])
{
    char buffer[1024];
    
    printf("Partes do codigo baseado em " LUA_RELEASE ", " LUA_COPYRIGHT "\r\n");
    
    SetConsoleCtrlHandler (sigint, TRUE);
    GetModuleFileName( NULL, buffer, sizeof(buffer));

    string modulename = buffer;
    string basedir = modulename.substr(0, modulename.find_last_of('\\') + 1);
    string exename = modulename.substr(basedir.length(), modulename.length() - basedir.length() + 1);    
    string config = exename.replace(exename.find_last_of('.')+1, 3, "lua");
    
    lua = lua_open();
    luaL_openlibs(lua);
    
    lua_newtable (lua);

    for (int arg = 0; arg < argc; arg++)
    {
        lua_pushinteger(lua, arg + 1);
        lua_pushstring(lua, argv[arg]);
        lua_settable (lua, -3);
    }

    lua_setglobal(lua, "argv");
    
    const luaL_reg staticfunctions[] = {
        { "sleep", lua_Sleep },
        { "ticks", lua_Ticks }
    };
    
    for (unsigned int i = 0; i < (sizeof(staticfunctions) / sizeof(*staticfunctions)); i++)
        lua_register (lua, staticfunctions[i].name, staticfunctions[i].func);

    const luaL_reg popenfunctions[] = {
        { "read", popen_read },
        { "write", popen_write },
        { "close", popen_close},
        { "__gc", popen_close},
        { NULL, NULL},
        { "create", popen_create },
        { NULL, NULL},
    };

    luaL_newmetatable(lua, LUA_POPEN);
    lua_pushvalue(lua, -1);
    lua_setfield(lua, -2, "__index");
    luaL_register(lua, NULL, popenfunctions);
    lua_pop(lua, 1);
    
    lua_newtable(lua);
    
    for (unsigned int i = 0; i < (sizeof(popenfunctions) / sizeof(*popenfunctions)); i++) {
        if (popenfunctions[i].name == NULL)
            continue;
            
        lua_pushstring(lua, popenfunctions[i].name);
        lua_pushcfunction(lua, popenfunctions[i].func);
        lua_settable(lua, -3);
    }
    
    lua_setglobal(lua, "popen");
    
    if (luaL_dofile(lua, (basedir + config).c_str()))
    {
        if (GetLastError() != ERROR_SUCCESS)
        {
            LPTSTR msg = getlasterrorstring();
            fprintf(stderr, "Erro de configuracao [%s]: %s\n", config.c_str(), msg);
            LocalFree(msg);
        }
        else
            fprintf (stderr, "Parse error: %s\n", lua_tostring(lua, -1));
        
        lua_close(lua);
        return EXIT_FAILURE;
    }

	lua_getfield(lua, LUA_GLOBALSINDEX, "submit");
	if (lua_isnil(lua, -1) || (lua_type(lua, -1) != LUA_TFUNCTION)) 
	{
        fprintf(stderr, "Sem funcao submit() correspondente na configuracao! [%s]", lua_typename(lua, -1));
        lua_close(lua);
        return EXIT_FAILURE;
    }

    if ( lua_pcall (lua, 0, 1, 0) )
    {
        fprintf (stderr, "Call error: %s\n", lua_tostring(lua, -1));
        lua_close(lua);
        return EXIT_FAILURE;
    }
    
    int retcode = EXIT_SUCCESS;
    if (!lua_isnil(lua, -1 && (lua_type(lua, -1) == LUA_TNUMBER)))
        retcode = lua_tointeger(lua, -1);
        
    lua_pop(lua, 1);

    lua_close(lua);
    return (retcode);
}
