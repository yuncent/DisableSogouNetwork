#define _WIN32_WINNT 0x0600
#include <windows.h>
#include <tlhelp32.h>
#include <netfw.h>
#include <string>
#include <vector>
#include <set>
#include <filesystem>
#include <objbase.h>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "uuid.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(linker, "/subsystem:windows /entry:wWinMainCRTStartup")

namespace fs = std::filesystem;

const wchar_t* WIN_TITLE = L"搜狗输入法联网管理工具";
const wchar_t* BTN_SCAN = L"1. 扫描进程";
const wchar_t* BTN_BLOCK = L"2. 禁用网络";
const wchar_t* BTN_RESET = L"3. 恢复网络";

#define ID_SCAN  1001
#define ID_BLOCK 1002
#define ID_RESET 1003
#define ID_LIST  1004

class NetManager {
    INetFwPolicy2* pPolicy = nullptr;
public:
    NetManager() {
        CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
        CoCreateInstance(__uuidof(NetFwPolicy2), nullptr, CLSCTX_INPROC_SERVER, __uuidof(INetFwPolicy2), (void**)&pPolicy);
    }
    ~NetManager() { if (pPolicy) pPolicy->Release(); CoUninitialize(); }

    void UltraScan(std::set<std::wstring>& out) {
        std::vector<std::wstring> dirs = { L"D:\\SogouInput", L"C:\\Program Files (x86)\\SogouInput", L"C:\\Program Files\\SogouInput" };
        for (const auto& d : dirs) {
            try { if (fs::exists(d)) for (const auto& e : fs::recursive_directory_iterator(d)) if (e.is_regular_file() && e.path().extension() == ".exe") out.insert(e.path().wstring()); }
            catch (...) {}
        }
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe{ sizeof(pe) };
            if (Process32FirstW(hSnap, &pe)) {
                do {
                    HANDLE hP = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
                    if (hP) {
                        wchar_t p[MAX_PATH]{}; DWORD sz = MAX_PATH;
                        if (QueryFullProcessImageNameW(hP, 0, p, &sz))
                            if ((wcsstr(p, L"Sogou") || wcsstr(p, L"sogou")) && !wcsstr(p, L"DisableSogouNetwork") && !wcsstr(p, L"Project1")) out.insert(p);
                        CloseHandle(hP);
                    }
                } while (Process32NextW(hSnap, &pe));
            }
            CloseHandle(hSnap);
        }
    }

    void RemoveRulesByPath(const std::wstring& appPath) {
        if (!pPolicy) return;
        INetFwRules* pRules = nullptr; pPolicy->get_Rules(&pRules);
        IUnknown* pUnk = nullptr; pRules->get__NewEnum(&pUnk);
        IEnumVARIANT* pEnum = nullptr; pUnk->QueryInterface(__uuidof(IEnumVARIANT), (void**)&pEnum);
        VARIANT v; VariantInit(&v);
        std::vector<std::wstring> toDel;
        while (pEnum->Next(1, &v, nullptr) == S_OK) {
            INetFwRule* r = nullptr;
            if (SUCCEEDED(v.punkVal->QueryInterface(__uuidof(INetFwRule), (void**)&r))) {
                BSTR bstrApp = nullptr; r->get_ApplicationName(&bstrApp);
                if (bstrApp && _wcsicmp(bstrApp, appPath.c_str()) == 0) {
                    BSTR bstrName = nullptr; r->get_Name(&bstrName);
                    if (bstrName) toDel.push_back(bstrName);
                    SysFreeString(bstrName);
                }
                if (bstrApp) SysFreeString(bstrApp);
                r->Release();
            }
            VariantClear(&v);
        }
        for (const auto& n : toDel) pRules->Remove(SysAllocString(n.c_str()));
        pEnum->Release(); pUnk->Release(); pRules->Release();
    }

    void Apply(const std::vector<std::wstring>& paths, NET_FW_ACTION action) {
        if (!pPolicy) return;
        INetFwRules* pRules = nullptr; pPolicy->get_Rules(&pRules);
        for (const auto& path : paths) {
            RemoveRulesByPath(path);
            if (action == NET_FW_ACTION_BLOCK) {
                for (int dir : {1, 2}) {
                    INetFwRule* pR = nullptr;
                    CoCreateInstance(__uuidof(NetFwRule), nullptr, CLSCTX_INPROC_SERVER, __uuidof(INetFwRule), (void**)&pR);
                    std::wstring rName = L"Sogou_Net_Rule_" + fs::path(path).filename().wstring() + (dir == 1 ? L"_In" : L"_Out");
                    pR->put_Name(SysAllocString(rName.c_str()));
                    pR->put_ApplicationName(SysAllocString(path.c_str()));
                    pR->put_Action(NET_FW_ACTION_BLOCK);
                    pR->put_Direction(dir == 1 ? NET_FW_RULE_DIR_IN : NET_FW_RULE_DIR_OUT);
                    pR->put_Enabled(VARIANT_TRUE);
                    pR->put_Profiles(NET_FW_PROFILE2_ALL);
                    pRules->Add(pR); pR->Release();
                }
            }
        }
        pRules->Release();
    }
};

NetManager g_Net;
std::set<std::wstring> g_Paths;

LRESULT CALLBACK MyWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    static HWND hList;
    if (msg == WM_CREATE) {
        CreateWindowW(L"BUTTON", BTN_SCAN, WS_CHILD | WS_VISIBLE, 20, 20, 140, 40, hwnd, (HMENU)ID_SCAN, nullptr, nullptr);
        CreateWindowW(L"BUTTON", BTN_BLOCK, WS_CHILD | WS_VISIBLE, 180, 20, 140, 40, hwnd, (HMENU)ID_BLOCK, nullptr, nullptr);
        CreateWindowW(L"BUTTON", BTN_RESET, WS_CHILD | WS_VISIBLE, 340, 20, 140, 40, hwnd, (HMENU)ID_RESET, nullptr, nullptr);
        hList = CreateWindowW(L"LISTBOX", nullptr, WS_CHILD | WS_VISIBLE | LBS_EXTENDEDSEL | WS_BORDER | WS_VSCROLL | WS_HSCROLL, 20, 80, 460, 320, hwnd, (HMENU)ID_LIST, nullptr, nullptr);
    }
    else if (msg == WM_COMMAND) {
        int id = LOWORD(wp);
        if (id == ID_SCAN) {
            SendMessageW(hList, LB_RESETCONTENT, 0, 0); g_Paths.clear();
            g_Net.UltraScan(g_Paths);
            for (const auto& p : g_Paths) SendMessageW(hList, LB_ADDSTRING, 0, (LPARAM)p.c_str());
            // 扫描后不全选，解决“蓝屏幕”
            SendMessageW(hList, LB_SETHORIZONTALEXTENT, (WPARAM)800, 0); // 仅在有内容时激活滑动条
        }
        else if (id == ID_BLOCK || id == ID_RESET) {
            std::vector<std::wstring> sel;
            int cnt = (int)SendMessageW(hList, LB_GETCOUNT, 0, 0);
            for (int i = 0; i < cnt; i++) if (SendMessageW(hList, LB_GETSEL, i, 0)) {
                wchar_t b[MAX_PATH]; SendMessageW(hList, LB_GETTEXT, i, (LPARAM)b);
                std::wstring s = b; if (s.find(L"[") == 0) s = s.substr(s.find(L"]") + 2);
                sel.emplace_back(s);
            }
            // 如果没选，默认处理全部
            if (sel.empty()) {
                for (int i = 0; i < cnt; i++) {
                    wchar_t b[MAX_PATH]; SendMessageW(hList, LB_GETTEXT, i, (LPARAM)b);
                    std::wstring s = b; if (s.find(L"[") == 0) s = s.substr(s.find(L"]") + 2);
                    sel.emplace_back(s);
                }
            }
            if (sel.empty()) return 0;

            g_Net.Apply(sel, id == ID_BLOCK ? NET_FW_ACTION_BLOCK : NET_FW_ACTION_ALLOW);

            // 实时刷新明细
            SendMessageW(hList, LB_RESETCONTENT, 0, 0);
            for (const auto& p : sel) {
                std::wstring status = (id == ID_BLOCK ? L"[已禁用] " : L"[已恢复] ") + p;
                SendMessageW(hList, LB_ADDSTRING, 0, (LPARAM)status.c_str());
            }
            // 确保刷新后滚动条依然有效
            SendMessageW(hList, LB_SETHORIZONTALEXTENT, (WPARAM)800, 0);
        }
    }
    else if (msg == WM_DESTROY) PostQuitMessage(0);
    return DefWindowProcW(hwnd, msg, wp, lp);
}

int APIENTRY wWinMain(HINSTANCE h, HINSTANCE, LPWSTR, int n) {
    WNDCLASSW wc{ 0 }; wc.lpfnWndProc = MyWndProc; wc.hInstance = h; wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1); wc.lpszClassName = L"SogouStandardV4";
    RegisterClassW(&wc);
    HWND hwnd = CreateWindowW(L"SogouStandardV4", WIN_TITLE, WS_OVERLAPPEDWINDOW & ~WS_THICKFRAME, CW_USEDEFAULT, CW_USEDEFAULT, 520, 460, nullptr, nullptr, h, nullptr);
    ShowWindow(hwnd, n); MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) { TranslateMessage(&msg); DispatchMessageW(&msg); }
    return 0;
}
