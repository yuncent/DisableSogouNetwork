/**
 * 搜狗输入法联网管理工具
 *
 * 扫描搜狗拼音输入法的可执行文件，并通过 Windows 防火墙
 * 管理其出站/入站阻止规则。需要管理员权限才能操作防火墙。
 *
 * 作者：yuncent
 * 许可证：MIT
 */

#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0600
#include <windows.h>
#include <tlhelp32.h>
#include <netfw.h>
#include <string>
#include <vector>
#include <set>
#include <filesystem>
#include <objbase.h>
#include <shellapi.h>
#include <shlobj.h>
#include <commctrl.h>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "uuid.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "comctl32.lib")
 // 启用 Common Controls 6.0 视觉样式 (BS_SPLITBUTTON 需要)
#pragma comment(linker,"\"/manifestdependency:type='win32' \
name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

#pragma comment(linker, "/subsystem:windows /entry:wWinMainCRTStartup")

namespace fs = std::filesystem;

// ---------- 常量定义 ----------
const wchar_t* WIN_TITLE_BASE = L"搜狗输入法联网管理工具";
const wchar_t* BTN_SCAN = L"1. 扫描进程";
const wchar_t* BTN_BLOCK = L"2. 禁用网络";
const wchar_t* BTN_RESET = L"3. 恢复网络";

// 控件 ID
#define ID_SCAN   1001
#define ID_BLOCK  1002
#define ID_RESET  1003
#define ID_LIST   1004
#define IDM_SCAN_CHOOSE_DIR  2001

// 布局参数 (单位: 像素)
constexpr int kMargin = 30;   // 左右统一边距
constexpr int kBtnWidth = 140;
constexpr int kBtnHeight = 40;
constexpr int kBtnGap = 20;
constexpr int kBtnY = 15;   // 按钮顶部 Y 坐标
constexpr int kListTopMargin = 10;   // 按钮与列表间距
constexpr int kBottomMargin = 30;   // 列表底部留白
constexpr int kClientWidth = 520;  // 客户区宽度 = 460 (3按钮+2间距) + 2*30
constexpr int kClientHeight = 420;  // 客户区高度

struct AppInfo {
    std::wstring path;
    bool isBlocked = false;
};

// ---------- Windows 防火墙管理器 ----------
class NetManager {
    INetFwPolicy2* pPolicy = nullptr;

public:
    NetManager() {
        HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
        hr = CoCreateInstance(__uuidof(NetFwPolicy2), nullptr,
            CLSCTX_INPROC_SERVER, __uuidof(INetFwPolicy2),
            reinterpret_cast<void**>(&pPolicy));
        if (FAILED(hr)) pPolicy = nullptr;
    }

    ~NetManager() {
        if (pPolicy) pPolicy->Release();
        CoUninitialize();
    }

    bool IsAvailable() const { return pPolicy != nullptr; }

    // 检查指定可执行文件是否被防火墙阻止
    bool IsBlocked(const std::wstring& appPath) {
        if (!pPolicy) return false;

        INetFwRules* pRules = nullptr;
        if (FAILED(pPolicy->get_Rules(&pRules))) return false;

        IUnknown* pUnk = nullptr;
        IEnumVARIANT* pEnum = nullptr;
        bool blocked = false;

        if (SUCCEEDED(pRules->get__NewEnum(&pUnk)) &&
            SUCCEEDED(pUnk->QueryInterface(__uuidof(IEnumVARIANT),
                reinterpret_cast<void**>(&pEnum)))) {
            VARIANT v; VariantInit(&v);
            while (!blocked && pEnum->Next(1, &v, nullptr) == S_OK) {
                INetFwRule* r = nullptr;
                if (SUCCEEDED(v.punkVal->QueryInterface(
                    __uuidof(INetFwRule), reinterpret_cast<void**>(&r)))) {
                    BSTR bstrApp = nullptr;
                    r->get_ApplicationName(&bstrApp);
                    NET_FW_ACTION action = NET_FW_ACTION_ALLOW;
                    r->get_Action(&action);
                    if (bstrApp &&
                        _wcsicmp(bstrApp, appPath.c_str()) == 0 &&
                        action == NET_FW_ACTION_BLOCK) {
                        blocked = true;
                    }
                    if (bstrApp) SysFreeString(bstrApp);
                    r->Release();
                }
                VariantClear(&v);
            }
            pEnum->Release();
        }
        if (pUnk) pUnk->Release();
        pRules->Release();
        return blocked;
    }

    // 全面扫描：固定安装目录 + 运行中的进程
    void UltraScan(std::vector<AppInfo>& out) {
        std::set<std::wstring> uniquePaths;

        // 1. 扫描常见安装目录
        const std::vector<std::wstring> dirs = {
            L"D:\\SogouInput",
            L"C:\\Program Files (x86)\\SogouInput",
            L"C:\\Program Files\\SogouInput"
        };
        for (const auto& d : dirs) {
            try {
                if (fs::exists(d)) {
                    for (const auto& e :
                        fs::recursive_directory_iterator(
                            d, fs::directory_options::skip_permission_denied)) {
                        if (e.is_regular_file() &&
                            e.path().extension() == L".exe") {
                            uniquePaths.insert(
                                fs::absolute(e.path()).wstring());
                        }
                    }
                }
            }
            catch (...) {}
        }

        // 2. 枚举所有进程
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe{ sizeof(pe) };
            if (Process32FirstW(hSnap, &pe)) {
                do {
                    HANDLE hP = OpenProcess(
                        PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                        pe.th32ProcessID);
                    if (hP) {
                        wchar_t p[MAX_PATH]{};
                        DWORD sz = MAX_PATH;
                        if (QueryFullProcessImageNameW(hP, 0, p, &sz)) {
                            std::wstring path = p;
                            // 过滤包含 Sogou/sogou 关键字，且排除本工具自身
                            if ((wcsstr(p, L"Sogou") ||
                                wcsstr(p, L"sogou")) &&
                                !wcsstr(p, L"DisableSogouNetwork") &&
                                !wcsstr(p, L"Project1")) {
                                uniquePaths.insert(
                                    fs::absolute(path).wstring());
                            }
                        }
                        CloseHandle(hP);
                    }
                } while (Process32NextW(hSnap, &pe));
            }
            CloseHandle(hSnap);
        }

        // 生成结果
        out.clear();
        for (const auto& p : uniquePaths) {
            AppInfo info;
            info.path = p;
            info.isBlocked = IsBlocked(p);
            out.push_back(info);
        }
    }

    // 仅扫描用户选定的文件夹 (不扫描进程)
    void ScanFolder(const std::wstring& folderPath,
        std::vector<AppInfo>& out) {
        out.clear();
        std::set<std::wstring> uniquePaths;
        try {
            if (fs::exists(folderPath)) {
                for (const auto& e :
                    fs::recursive_directory_iterator(
                        folderPath,
                        fs::directory_options::skip_permission_denied)) {
                    if (e.is_regular_file() &&
                        e.path().extension() == L".exe") {
                        uniquePaths.insert(
                            fs::absolute(e.path()).wstring());
                    }
                }
            }
        }
        catch (...) {}

        for (const auto& p : uniquePaths) {
            AppInfo info;
            info.path = p;
            info.isBlocked = IsBlocked(p);
            out.push_back(info);
        }
    }

private:
    // 移除所有指向特定路径的防火墙规则
    void RemoveRulesByPath(const std::wstring& appPath) {
        if (!pPolicy) return;

        INetFwRules* pRules = nullptr;
        if (FAILED(pPolicy->get_Rules(&pRules))) return;

        IUnknown* pUnk = nullptr;
        IEnumVARIANT* pEnum = nullptr;
        std::vector<std::wstring> toDel;

        if (SUCCEEDED(pRules->get__NewEnum(&pUnk)) &&
            SUCCEEDED(pUnk->QueryInterface(
                __uuidof(IEnumVARIANT), reinterpret_cast<void**>(&pEnum)))) {
            VARIANT v; VariantInit(&v);
            while (pEnum->Next(1, &v, nullptr) == S_OK) {
                INetFwRule* r = nullptr;
                if (SUCCEEDED(v.punkVal->QueryInterface(
                    __uuidof(INetFwRule), reinterpret_cast<void**>(&r)))) {
                    BSTR bstrApp = nullptr;
                    r->get_ApplicationName(&bstrApp);
                    if (bstrApp &&
                        _wcsicmp(bstrApp, appPath.c_str()) == 0) {
                        BSTR bstrName = nullptr;
                        r->get_Name(&bstrName);
                        if (bstrName) {
                            toDel.push_back(bstrName);
                            SysFreeString(bstrName);
                        }
                    }
                    if (bstrApp) SysFreeString(bstrApp);
                    r->Release();
                }
                VariantClear(&v);
            }
            pEnum->Release();
        }
        if (pUnk) pUnk->Release();

        for (const auto& name : toDel) {
            BSTR b = SysAllocString(name.c_str());
            pRules->Remove(b);
            SysFreeString(b);
        }
        pRules->Release();
    }

public:
    // 为指定路径创建入站/出站阻止规则
    void BlockPaths(const std::vector<std::wstring>& paths) {
        if (!pPolicy) return;

        INetFwRules* pRules = nullptr;
        if (FAILED(pPolicy->get_Rules(&pRules))) return;

        for (const auto& path : paths) {
            RemoveRulesByPath(path);

            for (int dir : { NET_FW_RULE_DIR_IN, NET_FW_RULE_DIR_OUT }) {
                INetFwRule* pR = nullptr;
                HRESULT hr = CoCreateInstance(
                    __uuidof(NetFwRule), nullptr, CLSCTX_INPROC_SERVER,
                    __uuidof(INetFwRule), reinterpret_cast<void**>(&pR));
                if (FAILED(hr)) continue;

                std::wstring rName = L"Sogou_Net_Rule_" +
                    fs::path(path).filename().wstring() +
                    (dir == NET_FW_RULE_DIR_IN ? L"_In"
                        : L"_Out");
                BSTR bName = SysAllocString(rName.c_str());
                BSTR bPath = SysAllocString(path.c_str());
                pR->put_Name(bName);
                pR->put_ApplicationName(bPath);
                pR->put_Action(NET_FW_ACTION_BLOCK);
                pR->put_Direction(static_cast<NET_FW_RULE_DIRECTION>(dir));
                pR->put_Enabled(VARIANT_TRUE);
                pR->put_Profiles(NET_FW_PROFILE2_ALL);
                pR->put_Protocol(NET_FW_IP_PROTOCOL_ANY);
                pRules->Add(pR);
                SysFreeString(bName);
                SysFreeString(bPath);
                pR->Release();
            }
        }
        pRules->Release();
    }

    // 移除指定路径的所有防火墙规则
    void UnblockPaths(const std::vector<std::wstring>& paths) {
        for (const auto& p : paths) RemoveRulesByPath(p);
    }

    // 清除本工具创建的所有规则 (名称以 "Sogou_Net_Rule_" 开头)
    void RemoveAllSogouRules() {
        if (!pPolicy) return;

        INetFwRules* pRules = nullptr;
        if (FAILED(pPolicy->get_Rules(&pRules))) return;

        IUnknown* pUnk = nullptr;
        IEnumVARIANT* pEnum = nullptr;
        std::vector<std::wstring> toDelete;

        if (SUCCEEDED(pRules->get__NewEnum(&pUnk)) &&
            SUCCEEDED(pUnk->QueryInterface(
                __uuidof(IEnumVARIANT), reinterpret_cast<void**>(&pEnum)))) {
            VARIANT v; VariantInit(&v);
            while (pEnum->Next(1, &v, nullptr) == S_OK) {
                INetFwRule* r = nullptr;
                if (SUCCEEDED(v.punkVal->QueryInterface(
                    __uuidof(INetFwRule), reinterpret_cast<void**>(&r)))) {
                    BSTR bName = nullptr;
                    r->get_Name(&bName);
                    if (bName) {
                        std::wstring name(bName);
                        if (name.find(L"Sogou_Net_Rule_") == 0)
                            toDelete.push_back(name);
                        SysFreeString(bName);
                    }
                    r->Release();
                }
                VariantClear(&v);
            }
            pEnum->Release();
        }
        if (pUnk) pUnk->Release();

        for (const auto& name : toDelete) {
            BSTR b = SysAllocString(name.c_str());
            pRules->Remove(b);
            SysFreeString(b);
        }
        pRules->Release();
    }

    // 获取本工具创建但对应 .exe 文件已不存在的规则 (残留规则)
    std::vector<std::wstring> GetOrphanRules() {
        std::vector<std::wstring> orphanRules;
        if (!pPolicy) return orphanRules;

        INetFwRules* pRules = nullptr;
        if (FAILED(pPolicy->get_Rules(&pRules))) return orphanRules;

        IUnknown* pUnk = nullptr;
        IEnumVARIANT* pEnum = nullptr;

        if (SUCCEEDED(pRules->get__NewEnum(&pUnk)) &&
            SUCCEEDED(pUnk->QueryInterface(
                __uuidof(IEnumVARIANT), reinterpret_cast<void**>(&pEnum)))) {
            VARIANT v; VariantInit(&v);
            while (pEnum->Next(1, &v, nullptr) == S_OK) {
                INetFwRule* r = nullptr;
                if (SUCCEEDED(v.punkVal->QueryInterface(
                    __uuidof(INetFwRule), reinterpret_cast<void**>(&r)))) {
                    BSTR bName = nullptr;
                    r->get_Name(&bName);
                    if (bName) {
                        std::wstring name(bName);
                        if (name.find(L"Sogou_Net_Rule_") == 0) {
                            BSTR bApp = nullptr;
                            r->get_ApplicationName(&bApp);
                            std::wstring appPath = bApp ? bApp : L"";
                            SysFreeString(bApp);
                            if (!appPath.empty() && !fs::exists(appPath)) {
                                orphanRules.push_back(
                                    name + L" | " + appPath +
                                    L" [文件已删除]");
                            }
                        }
                        SysFreeString(bName);
                    }
                    r->Release();
                }
                VariantClear(&v);
            }
            pEnum->Release();
        }
        if (pUnk) pUnk->Release();
        pRules->Release();
        return orphanRules;
    }
};

// ---------- 全局变量 ----------
NetManager g_Net;
std::vector<AppInfo> g_Apps;
bool g_isAdmin = false;
HWND g_hwndMain = nullptr;

// 获取列表显示文本
std::wstring GetDisplayText(const AppInfo& info) {
    return (info.isBlocked ? L"[已禁用] " : L"[正常] ") + info.path;
}

// 刷新列表框内容
void RefreshList(HWND hList) {
    SendMessageW(hList, LB_RESETCONTENT, 0, 0);

    int appCount = static_cast<int>(g_Apps.size());
    wchar_t header[64];
    wsprintfW(header, L"扫描到 %d 个搜狗程序", appCount);
    SendMessageW(hList, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>(header));

    for (const auto& app : g_Apps) {
        std::wstring text = GetDisplayText(app);
        SendMessageW(hList, LB_ADDSTRING, 0,
            reinterpret_cast<LPARAM>(text.c_str()));
    }

    std::vector<std::wstring> orphanRules = g_Net.GetOrphanRules();
    if (!orphanRules.empty()) {
        SendMessageW(
            hList, LB_ADDSTRING, 0,
            reinterpret_cast<LPARAM>(L"残留的防火墙规则（文件已不存在）："));
        for (const auto& info : orphanRules) {
            std::wstring text = L"[防火墙残留] " + info;
            SendMessageW(hList, LB_ADDSTRING, 0,
                reinterpret_cast<LPARAM>(text.c_str()));
        }
    }

    // 智能水平滚动条
    HDC hDC = GetDC(hList);
    HFONT hFont = reinterpret_cast<HFONT>(
        SendMessageW(hList, WM_GETFONT, 0, 0));
    HGDIOBJ hOldObj = SelectObject(hDC, hFont);   // 保存原对象
    int maxWidth = 0;
    const int count = static_cast<int>(SendMessageW(hList, LB_GETCOUNT, 0, 0));
    for (int i = 0; i < count; ++i) {
        int len = static_cast<int>(SendMessageW(hList, LB_GETTEXTLEN, i, 0));
        if (len > 0) {
            std::wstring text(len + 1, L'\0');
            SendMessageW(hList, LB_GETTEXT, i,
                reinterpret_cast<LPARAM>(text.data()));
            SIZE sz;
            GetTextExtentPoint32W(hDC, text.c_str(), len, &sz);
            if (sz.cx > maxWidth) maxWidth = sz.cx;
        }
    }
    SelectObject(hDC, hOldObj);
    ReleaseDC(hList, hDC);

    RECT rc;
    GetClientRect(hList, &rc);
    const LONG listWidth = rc.right - rc.left;
    LONG style = GetWindowLong(hList, GWL_STYLE);

    if (maxWidth > listWidth - 10) {
        if (!(style & WS_HSCROLL)) {
            SetWindowLong(hList, GWL_STYLE, style | WS_HSCROLL);
            SetWindowPos(hList, nullptr, 0, 0, 0, 0,
                SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER |
                SWP_FRAMECHANGED);
        }
        SendMessageW(hList, LB_SETHORIZONTALEXTENT,
            static_cast<WPARAM>(maxWidth + 30), 0);
    }
    else {
        if (style & WS_HSCROLL) {
            SetWindowLong(hList, GWL_STYLE, style & ~WS_HSCROLL);
            SetWindowPos(hList, nullptr, 0, 0, 0, 0,
                SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER |
                SWP_FRAMECHANGED);
        }
        SendMessageW(hList, LB_SETHORIZONTALEXTENT, 0, 0);
    }
}

// ---------- 文件夹浏览对话框 ----------
bool BrowseForFolder(HWND hwndOwner, std::wstring& outFolder) {
    BROWSEINFOW bi = { 0 };
    bi.hwndOwner = hwndOwner;
    bi.lpszTitle = L"请选择搜狗输入法的安装目录（例如 D:\\SogouInput）";
    bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;

    LPITEMIDLIST pidl = SHBrowseForFolderW(&bi);
    if (pidl) {
        wchar_t path[MAX_PATH];
        if (SHGetPathFromIDListW(pidl, path)) {
            outFolder = path;
            CoTaskMemFree(pidl);
            return true;
        }
        CoTaskMemFree(pidl);
    }
    return false;
}

// ---------- 关于对话框 (MessageBox 居中于主窗口) ----------
HHOOK g_hHook = nullptr;

LRESULT CALLBACK CBTProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HCBT_CREATEWND && g_hwndMain) {
        HWND hMsgBox = reinterpret_cast<HWND>(wParam);
        RECT rcMain, rcMsg;
        GetWindowRect(g_hwndMain, &rcMain);
        GetWindowRect(hMsgBox, &rcMsg);
        const int msgW = rcMsg.right - rcMsg.left;
        const int msgH = rcMsg.bottom - rcMsg.top;
        const int x = rcMain.left + (rcMain.right - rcMain.left - msgW) / 2;
        const int y = rcMain.top + (rcMain.bottom - rcMain.top - msgH) / 2;
        SetWindowPos(hMsgBox, nullptr, x, y, 0, 0,
            SWP_NOSIZE | SWP_NOZORDER);
        if (g_hHook) {
            UnhookWindowsHookEx(g_hHook);
            g_hHook = nullptr;
        }
    }
    return CallNextHookEx(g_hHook, nCode, wParam, lParam);
}

void ShowAboutDialog(HWND hwndOwner) {
    g_hwndMain = hwndOwner;
    g_hHook = SetWindowsHookEx(WH_CBT, CBTProc, nullptr,
        GetCurrentThreadId());
    MessageBoxW(hwndOwner,
        L"搜狗输入法联网管理工具\r\n\r\n作者：yuncent",
        L"关于", MB_OK | MB_ICONINFORMATION);
    if (g_hHook) {
        UnhookWindowsHookEx(g_hHook);
        g_hHook = nullptr;
    }
}

// ---------- 主窗口过程 ----------
LRESULT CALLBACK MyWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    static HWND hList;

    switch (msg) {
    case WM_CREATE: {
        RECT rc;
        GetClientRect(hwnd, &rc);
        const int clientW = rc.right - rc.left;
        const int clientH = rc.bottom - rc.top;

        // 计算列表大小
        const int listY = kBtnY + kBtnHeight + kListTopMargin;
        const int listWidth = clientW - 2 * kMargin;
        const int listHeight = clientH - listY - kBottomMargin;

        // 创建按钮
        CreateWindowW(
            L"BUTTON", BTN_SCAN,
            WS_CHILD | WS_VISIBLE | BS_SPLITBUTTON,
            kMargin, kBtnY, kBtnWidth, kBtnHeight, hwnd,
            reinterpret_cast<HMENU>(ID_SCAN), nullptr, nullptr);

        CreateWindowW(
            L"BUTTON", BTN_BLOCK,
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            kMargin + kBtnWidth + kBtnGap, kBtnY,
            kBtnWidth, kBtnHeight, hwnd,
            reinterpret_cast<HMENU>(ID_BLOCK), nullptr, nullptr);

        CreateWindowW(
            L"BUTTON", BTN_RESET,
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            kMargin + (kBtnWidth + kBtnGap) * 2, kBtnY,
            kBtnWidth, kBtnHeight, hwnd,
            reinterpret_cast<HMENU>(ID_RESET), nullptr, nullptr);

        // 创建列表框
        hList = CreateWindowW(
            L"LISTBOX", nullptr,
            WS_CHILD | WS_VISIBLE | LBS_EXTENDEDSEL |
            LBS_HASSTRINGS | WS_VSCROLL | WS_BORDER |
            LBS_NOINTEGRALHEIGHT,
            kMargin, listY, listWidth, listHeight, hwnd,
            reinterpret_cast<HMENU>(ID_LIST), nullptr, nullptr);
        break;
    }

    case WM_SYSCOMMAND: {
        if (wp == SC_CONTEXTHELP) {
            ShowAboutDialog(hwnd);
            return 0;
        }
        return DefWindowProcW(hwnd, msg, wp, lp);
    }

    case WM_NOTIFY: {
        auto pnm = reinterpret_cast<NMHDR*>(lp);
        if (pnm->idFrom == ID_SCAN && pnm->code == BCN_DROPDOWN) {
            HWND hBtn = GetDlgItem(hwnd, ID_SCAN);
            RECT rc;
            GetWindowRect(hBtn, &rc);
            HMENU hMenu = CreatePopupMenu();
            AppendMenuW(hMenu, MF_STRING, IDM_SCAN_CHOOSE_DIR,
                L"选择目录…");
            TrackPopupMenu(hMenu, TPM_LEFTALIGN | TPM_TOPALIGN,
                rc.left, rc.bottom, 0, hwnd, nullptr);
            DestroyMenu(hMenu);
        }
        return 0;
    }

    case WM_COMMAND: {
        const int id = LOWORD(wp);

        if (id == IDM_SCAN_CHOOSE_DIR) {
            std::wstring folder;
            if (BrowseForFolder(hwnd, folder)) {
                if (!g_Net.IsAvailable()) {
                    MessageBoxW(
                        hwnd, L"防火墙接口不可用！", L"错误",
                        MB_OK | MB_ICONERROR);
                    return 0;
                }
                g_Net.ScanFolder(folder, g_Apps);
                RefreshList(hList);
            }
            return 0;
        }

        if (id == ID_SCAN) {
            g_Apps.clear();
            if (!g_Net.IsAvailable()) {
                MessageBoxW(hwnd, L"无法初始化Windows防火墙接口，请以管理员身份运行！",
                    L"错误", MB_OK | MB_ICONERROR);
                return 0;
            }
            g_Net.UltraScan(g_Apps);
            RefreshList(hList);
            return 0;
        }

        if (id == ID_BLOCK || id == ID_RESET) {
            if (!g_Net.IsAvailable()) {
                MessageBoxW(hwnd, L"防火墙接口未初始化！", L"错误",
                    MB_OK | MB_ICONERROR);
                return 0;
            }

            std::vector<std::wstring> sel;
            const int cnt =
                static_cast<int>(SendMessageW(hList, LB_GETCOUNT, 0, 0));
            bool anySelected = false;

            for (int i = 1; i < cnt; ++i) {
                if (SendMessageW(hList, LB_GETSEL, i, 0) > 0) {
                    anySelected = true;
                    const int appIdx = i - 1;
                    if (appIdx < static_cast<int>(g_Apps.size())) {
                        sel.push_back(g_Apps[appIdx].path);
                    }
                }
            }

            if (id == ID_RESET && !anySelected) {
                g_Net.RemoveAllSogouRules();
            }
            else {
                if (!anySelected) {
                    for (const auto& a : g_Apps)
                        sel.push_back(a.path);
                }
                if (sel.empty()) return 0;

                if (id == ID_BLOCK)
                    g_Net.BlockPaths(sel);
                else
                    g_Net.UnblockPaths(sel);
            }

            // 刷新阻止状态
            for (auto& a : g_Apps)
                a.isBlocked = g_Net.IsBlocked(a.path);
            RefreshList(hList);
            return 0;
        }
        break;
    }

    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

// ---------- 管理员权限检查 ----------
BOOL IsRunningAsAdmin() {
    BOOL isAdmin = FALSE;
    PSID admins = nullptr;
    SID_IDENTIFIER_AUTHORITY NtAuth = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&NtAuth, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0, &admins)) {
        CheckTokenMembership(nullptr, admins, &isAdmin);
        FreeSid(admins);
    }
    return isAdmin;
}

BOOL RestartAsAdmin() {
    wchar_t path[MAX_PATH];
    if (GetModuleFileNameW(nullptr, path, MAX_PATH)) {
        SHELLEXECUTEINFOW sei = { sizeof(sei) };
        sei.lpVerb = L"runas";
        sei.lpFile = path;
        sei.nShow = SW_SHOWNORMAL;
        return ShellExecuteExW(&sei);
    }
    return FALSE;
}

// ---------- 程序入口 ----------
int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
    _In_opt_ HINSTANCE /*hPrevInstance*/,
    _In_opt_ LPWSTR /*lpCmdLine*/,
    _In_ int nCmdShow) {
    // 初始化公共控件
    INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_STANDARD_CLASSES };
    InitCommonControlsEx(&icc);

    g_isAdmin = IsRunningAsAdmin();
    if (!g_isAdmin) {
        if (RestartAsAdmin()) return 0;
        MessageBoxW(nullptr,
            L"未能获取管理员权限，防火墙管理功能可能不可用。",
            L"提示", MB_OK | MB_ICONWARNING);
    }

    std::wstring title = WIN_TITLE_BASE;
    title += g_isAdmin ? L" [管理员]" : L" [非管理员]";

    // 注册窗口类
    WNDCLASSW wc = {};
    wc.lpfnWndProc = MyWndProc;
    wc.hInstance = hInstance;
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    wc.lpszClassName = L"SogouNetMgr";
    RegisterClassW(&wc);

    // 计算窗口精确尺寸，确保客户区符合预期
    RECT desiredClient = { 0, 0, kClientWidth, kClientHeight };
    DWORD style = WS_OVERLAPPEDWINDOW &
        ~(WS_MAXIMIZEBOX | WS_MINIMIZEBOX | WS_THICKFRAME);
    DWORD exStyle = WS_EX_CONTEXTHELP;
    AdjustWindowRectEx(&desiredClient, style, FALSE, exStyle);
    const int winWidth = desiredClient.right - desiredClient.left;
    const int winHeight = desiredClient.bottom - desiredClient.top;
    const int x = (GetSystemMetrics(SM_CXSCREEN) - winWidth) / 2;
    const int y = (GetSystemMetrics(SM_CYSCREEN) - winHeight) / 2;

    HWND hwnd = CreateWindowExW(exStyle, L"SogouNetMgr", title.c_str(),
        style, x, y, winWidth, winHeight,
        nullptr, nullptr, hInstance, nullptr);
    if (!hwnd) return 1;

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return static_cast<int>(msg.wParam);
}