
#include "lib.h"


int rc = 0;

#define TO_STR(a) {a, #a}

typedef struct {
	int returnCode;
	const char *returnCodeString;
} ERROR_MESSAGE_t;
ERROR_MESSAGE_t gErrorMessage[] = {
	TO_STR(RC_MEMORY_ALLOCATE_FAILED),
	TO_STR(RC_BUFFER_FULL),
	TO_STR(RC_BUFFER_OVERFLOW),
	TO_STR(RC_BUFFER_TOO_SMALL),

	TO_STR(RC_FILE_REACH_EOF),
	TO_STR(RC_FILE_OPEN_ERROR),
	TO_STR(RC_FILE_CLOSE_ERROR),
	TO_STR(RC_FILE_SCAN_ERROR),
};
u32 gErrorMessageLen = LENGTH_OF_ARRAY(gErrorMessage);

void LibError_PrintErrorMessage(int retVal, bool verbose /* = false */)
{
	//DUMPD(gErrorMessageLen);
	for (u32 i=0; i<gErrorMessageLen; i++) {
		if (retVal == gErrorMessage[i].returnCode) {
			printf("[Error Message] : %s\n", gErrorMessage[i].returnCodeString);
			return;
		}
	}

	if (retVal != 0) {
		printf("[Error Message] : Return Code = %d\n", retVal);
	} else {
		if (verbose)
			printf("[Error Message] : No Error!! Return Code = %d\n", retVal);
	}
}

void LibError_Demo(void)
{
	//LibError_PrintErrorMessage(RC_FILE_REACH_EOF);
}


int LibError_SetExtErrorMessage(const char *errorStr, ...)
{
	return 0;
}

int LibError_PrintExtErrorMessage(const char *precStr)
{
	return 0;
}



/*
	Reference:
		http://timmurphy.org/2010/05/04/pthreads-in-c-a-minimal-working-example/
		https://linux.die.net/man/3/pthread_create
*/

typedef struct {
	pthread_t thread;
	THREAD_PRIORITY_t priority;
}THREAD_HANDLE_LINUX_t;
int LibThread_NewHandle(OUT THREAD_HANDLE_t *threadHdlPtr, THREAD_PRIORITY_t priority /* = TPRI_DEFAULT */)
{
	THREAD_HANDLE_LINUX_t *linuxThreadHdl = (THREAD_HANDLE_LINUX_t *)malloc(sizeof(THREAD_HANDLE_LINUX_t));
	if (linuxThreadHdl == NULL)
		return -1;

	linuxThreadHdl->priority = priority;
	*threadHdlPtr = linuxThreadHdl;
	return 0;
}

int LibThread_Create(THREAD_HANDLE_t threadHdl, ThreadEntryFunc entry, void *arg /* = NULL */)
{
	THREAD_HANDLE_LINUX_t *linuxThreadHdl = (THREAD_HANDLE_LINUX_t *)threadHdl;

	int retVal = pthread_create(&linuxThreadHdl->thread, NULL, entry, arg);

	return retVal;
}

int LibThread_WaitThread(THREAD_HANDLE_t threadHdl)
{
	THREAD_HANDLE_LINUX_t *linuxThreadHdl = (THREAD_HANDLE_LINUX_t *)threadHdl;

	/* wait for the thread to finish */
	int retVal = pthread_join(linuxThreadHdl->thread, NULL);

	return retVal;
}

int LibThread_WaitThreads(THREAD_HANDLE_t *threadHdlArray, u32 count)
{
	return 0;
}

int LibThread_DestroyHandle(THREAD_HANDLE_t threadHdl)
{
	free(threadHdl);
	return 0;
}



typedef struct {
	pthread_cond_t cond;
	pthread_mutex_t mutex;
}EVENT_HANDLE_LINUX_t;
int LibIPC_Event_Create(OUT EVENT_HANDLE_t *eventHdlPtr)
{
	EVENT_HANDLE_LINUX_t *eHdl = (EVENT_HANDLE_LINUX_t *)malloc(sizeof(EVENT_HANDLE_LINUX_t));
	if (eHdl == NULL)
		return -1;

	int retVal = pthread_cond_init(&eHdl->cond, NULL);
	RETURN_IF(retVal);
	retVal = pthread_mutex_init(&eHdl->mutex, NULL);
	RETURN_IF(retVal);

	*eventHdlPtr = eHdl;
	return 0;
}

int LibIPC_Event_Destroy(EVENT_HANDLE_t eventHdl)
{
	EVENT_HANDLE_LINUX_t *eHdl = (EVENT_HANDLE_LINUX_t *)eventHdl;

	int retVal = pthread_mutex_destroy(&eHdl->mutex);
	RETURN_IF(retVal);

	retVal = pthread_cond_destroy(&eHdl->cond);
	RETURN_IF(retVal);

	free(eventHdl);
	return 0;
}

int LibIPC_Event_Set(EVENT_HANDLE_t eventHdl)
{
	EVENT_HANDLE_LINUX_t *eHdl = (EVENT_HANDLE_LINUX_t *)eventHdl;
	//PRINT_FUNC;
	pthread_mutex_lock(&eHdl->mutex);
	pthread_cond_signal(&eHdl->cond);
	pthread_mutex_unlock(&eHdl->mutex);

	return 0;
}

int LibIPC_Event_Wait(EVENT_HANDLE_t eventHdl)
{
	EVENT_HANDLE_LINUX_t *eHdl = (EVENT_HANDLE_LINUX_t *)eventHdl;
	//PRINT_FUNC;
	pthread_mutex_lock(&eHdl->mutex);
	pthread_cond_wait(&eHdl->cond, &eHdl->mutex);
	pthread_mutex_unlock(&eHdl->mutex);

	return 0;
}

typedef struct {
	pthread_mutex_t mutex;
}MUTEX_HANDLE_LINUX_t;
int LibIPC_Mutex_Create(OUT MUTEX_HANDLE_t *mutexHdlPtr)
{
	MUTEX_HANDLE_LINUX_t *linuxMutexHdl = (MUTEX_HANDLE_LINUX_t *)malloc(sizeof(MUTEX_HANDLE_LINUX_t));

	int retVal = pthread_mutex_init(&linuxMutexHdl->mutex, NULL);

	*mutexHdlPtr = linuxMutexHdl;

	return retVal;
}

int LibIPC_Mutex_Destroy(MUTEX_HANDLE_t mutexHdl)
{
	MUTEX_HANDLE_LINUX_t *linuxMutexHdl = (MUTEX_HANDLE_LINUX_t *)mutexHdl;

	return pthread_mutex_destroy(&linuxMutexHdl->mutex);
}

int LibIPC_Mutex_Lock(MUTEX_HANDLE_t mutexHdl)
{
	MUTEX_HANDLE_LINUX_t *linuxMutexHdl = (MUTEX_HANDLE_LINUX_t *)mutexHdl;

	return pthread_mutex_lock(&linuxMutexHdl->mutex);
}

int LibIPC_Mutex_Unlock(MUTEX_HANDLE_t mutexHdl)
{
	MUTEX_HANDLE_LINUX_t *linuxMutexHdl = (MUTEX_HANDLE_LINUX_t *)mutexHdl;

	return pthread_mutex_unlock(&linuxMutexHdl->mutex);
}

u32 scan_u32(const char *str)
{
	static u32 temp_u32;
	if (sscanf(str, "%u", &temp_u32) == 0) {
		printf("Error: scan error!\n");
		exit(-1);
	}
	return temp_u32;
}

u16 scan_u16(const char *str)
{
	return (u16)scan_u32(str);
}

u8 scan_u8(const char *str)
{
	return (u8)scan_u32(str);
}

s32 scan_s32(const char *str)
{
	static s32 temp_s32;
	if (sscanf(str, "%d", &temp_s32) == 0) {
		printf("Error: scan error!\n");
		exit(-1);
	}
	return temp_s32;
}

s16 scan_s16(const char *str)
{
	return (s16)scan_s32(str);
}

s8 scan_s8(const char *str)
{
	return (s8)scan_s32(str);
}

u32 scan_x32(const char *str)
{
	static u32 temp_u32;
	if (sscanf(str, "%x", &temp_u32) == 0) {
		printf("Error: scan error!\n");
		exit(-1);
	}
	return temp_u32;
}

u16 scan_x16(const char *str)
{
	return (u16)scan_x32(str);
}

u8 scan_x8(const char *str)
{
	return (u8)scan_x32(str);
}

u32 scan_0x32(const char *str)
{
	static u32 temp_u32;
	if (sscanf(str, "0x%x", &temp_u32) == 0) {
		printf("Error: scan error!\n");
		exit(-1);
	}
	return temp_u32;
}

u16 scan_0x16(const char *str)
{
	return (u16)scan_0x32(str);
}

u8 scan_0x8(const char *str)
{
	return (u8)scan_0x32(str);
}

