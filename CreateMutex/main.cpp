#include<stdio.h>
#include<Windows.h>
int main(void)
{
	SetConsoleTitle("MyTest");
	HANDLE hHandle = NULL;
	hHandle = CreateMutex(NULL, FALSE, "mutexText");
	if (GetLastError() == ERROR_ALREADY_EXISTS)
	{
		// ������л������������ͷž������λ��������
		printf("�Ѵ��ڻ�����");
	};
	getchar();
	return 0;
}