#include<stdio.h>
#include<Windows.h>
int main(void)
{
	SetConsoleTitle("MyTest");
	HANDLE hHandle = NULL;
	hHandle = CreateMutex(NULL, FALSE, "mutexText");
	if (GetLastError() == ERROR_ALREADY_EXISTS)
	{
		// 如果已有互斥量存在则释放句柄并复位互斥量　
		printf("已存在互斥体");
	};
	getchar();
	return 0;
}