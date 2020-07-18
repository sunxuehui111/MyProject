
// MyProjectDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "MyProject.h"
#include "MyProjectDlg.h"
#include "afxdialogex.h"
#include <vector>
#include <windows.h>
#include <stdio.h>

#define NT_SUCCESS   ((NTSTATUS)0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004
typedef LONG NTSTATUS;
typedef NTSTATUS *PNTSTATUS;
#define SystemHandleInformation 16
#define ObjectBasicInformation 0
#define ObjectNameInformation 1
#define ObjectTypeInformation 2
using namespace std;
#define MAXSIZE 1024

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


HWND M_hwnd[200], MM_hwnd[200];
vector<HWND> m_hwndt;
CString m_path;
int M_t = 0;
int M_q = 0;
// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CMyProjectDlg 对话框



CMyProjectDlg::CMyProjectDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_MYPROJECT_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CMyProjectDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CMyProjectDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
END_MESSAGE_MAP()


// CMyProjectDlg 消息处理程序

BOOL CMyProjectDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码
	AfxBeginThread(Myexe, this);
	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CMyProjectDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CMyProjectDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CMyProjectDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



typedef NTSTATUS(NTAPI *_NtQuerySystemInformation)(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);
typedef NTSTATUS(NTAPI *_NtDuplicateObject)(
	HANDLE SourceProcessHandle,
	HANDLE SourceHandle,
	HANDLE TargetProcessHandle,
	PHANDLE TargetHandle,
	ACCESS_MASK DesiredAccess,
	ULONG Attributes,
	ULONG Options
	);
typedef NTSTATUS(NTAPI *_NtQueryObject)(
	HANDLE ObjectHandle,
	ULONG ObjectInformationClass,
	PVOID ObjectInformation,
	ULONG ObjectInformationLength,
	PULONG ReturnLength
	);

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _SYSTEM_HANDLE
{
	ULONG ProcessId;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG HandleCount;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef enum _POOL_TYPE
{
	NonPagedPool,
	PagedPool,
	NonPagedPoolMustSucceed,
	DontUseThisType,
	NonPagedPoolCacheAligned,
	PagedPoolCacheAligned,
	NonPagedPoolCacheAlignedMustS
} POOL_TYPE, *PPOOL_TYPE;

typedef struct _OBJECT_TYPE_INFORMATION
{
	UNICODE_STRING Name;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG TotalPagedPoolUsage;
	ULONG TotalNonPagedPoolUsage;
	ULONG TotalNamePoolUsage;
	ULONG TotalHandleTableUsage;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	ULONG HighWaterPagedPoolUsage;
	ULONG HighWaterNonPagedPoolUsage;
	ULONG HighWaterNamePoolUsage;
	ULONG HighWaterHandleTableUsage;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccess;
	BOOLEAN SecurityRequired;
	BOOLEAN MaintainHandleCount;
	USHORT MaintainTypeList;
	POOL_TYPE PoolType;
	ULONG PagedPoolUsage;
	ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;


BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lparam) //枚举窗口回调函数
{
	TCHAR lpWinTitle[255] = { 0 };
	int i;
	if (M_t < 200)
	{

		if (GetWindowText(hwnd, lpWinTitle, 255) != 0)
		{
			CString strT, str;
			strT.Format(L"%s", lpWinTitle);
			if (strT == L"MyTest")
			{

				M_hwnd[M_t] = hwnd;
				M_t++;

			}
		}
	}
	return true;
}
UINT CMyProjectDlg::Myexe(LPVOID pParam)
{

	NTSTATUS status;
	PSYSTEM_HANDLE_INFORMATION handleInfo;
	ULONG handleInfoSize = 0x10000;
	HANDLE processHandle;
	ULONG i;
	CString str, hwnds;
	POBJECT_TYPE_INFORMATION objectTypeInfo;
	ULONG returnLength;
	int hwnd, j, k;
	bool thao;
	m_hwndt.clear();
	DWORD pid[50];
	for (j = 0; j < 50; j++)
	{
		pid[j] = 0;
		M_hwnd[j] = 0;
		MM_hwnd[j] = 0;
	}

	HMODULE hNtDll = NULL;
	HANDLE dupHandle = NULL;
	SYSTEM_HANDLE handle;
	hNtDll = GetModuleHandle(TEXT("ntdll.dll"));
	_NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(hNtDll, "NtQuerySystemInformation");
	_NtDuplicateObject NtDuplicateObject = (_NtDuplicateObject)GetProcAddress(hNtDll, "NtDuplicateObject");
	_NtQueryObject NtQueryObject = (_NtQueryObject)GetProcAddress(hNtDll, "NtQueryObject");
	while (true)
	{

		Sleep(10);
		M_t = 0;
		::EnumWindows(EnumWindowsProc, 0);
		M_q = 0;
		for (i = 0; i < M_t; i++)
		{
			k = 0;
			for (j = m_hwndt.size() - 1; j >0 && k < M_t; j--)
			{
				k++;
				if (m_hwndt[j] == M_hwnd[i])
				{
					goto a_a;
				}
			}
			MM_hwnd[M_q] = M_hwnd[i];
			::GetWindowThreadProcessId(M_hwnd[i], &pid[M_q]);
			M_q++;
		a_a:;
		}
		j = M_q;
		if (j > 0)
		{
			handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);
			while ((status = NtQuerySystemInformation(
				SystemHandleInformation,
				handleInfo,
				handleInfoSize,
				NULL
			)) == STATUS_INFO_LENGTH_MISMATCH)
				handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize *= 2);
			for (i = 0; i < handleInfo->HandleCount; i++)
			{
				handle = handleInfo->Handles[i];
				thao = false;
				for (k = 0; k < j; k++) {
					if (handle.ProcessId == pid[k])
					{
						thao = true;
						break;
					}
				}
				if (thao == true)
				{
					thao = false;
					processHandle = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid[k]);
					if (processHandle != NULL)
					{
						status = NtDuplicateObject(processHandle, (HANDLE)handle.Handle, GetCurrentProcess(), &dupHandle, 0, 0, 0);
						if (status == 0)
						{
							objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(0x2000);
							if (NtQueryObject(dupHandle, ObjectTypeInformation, objectTypeInfo, 0x1000, NULL) == 0)
							{
								str = objectTypeInfo->Name.Buffer;
								if (str == L"Mutant")
								{
									NtQueryObject(dupHandle, ObjectNameInformation, objectTypeInfo, 0x1000, NULL);
									str = objectTypeInfo->Name.Buffer;
									if (str.Find(L"mutexText") > 1)
									{
										thao = true;
									}
								}
								else if (str == L"Semaphore")
								{
									NtQueryObject(dupHandle, ObjectNameInformation, objectTypeInfo, 0x1000, NULL);
									str = objectTypeInfo->Name.Buffer;
									if (str.Find(L"CreateMutex.exe") > 1)
									{
										thao = true;
									}
								}
							}
							CloseHandle(dupHandle);
							free(objectTypeInfo);
							objectTypeInfo = NULL;
							if (thao == true)
							{
								HANDLE h_another_proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid[k]);
								DuplicateHandle(h_another_proc, (HANDLE)handle.Handle, GetCurrentProcess(), &dupHandle, 0, FALSE, DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE); // 关闭      
								CloseHandle(dupHandle);
								CloseHandle(h_another_proc);
								m_hwndt.push_back(MM_hwnd[k]);

							}
						}
					}
					CloseHandle(processHandle);

				}
			}
			free(handleInfo);
			handleInfo = NULL;
		}
	}
}
