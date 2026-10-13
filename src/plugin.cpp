#include <windows.h>
#include <shobjidl.h>
#include <shlwapi.h>
#include <tlhelp32.h>
#include <detours.h>
#include <algorithm>
#include <cstring>
#include <memory>
#include <new>
#include <unordered_map>
#include "plugin2.h"
// SDK releases mix UTF-8 and CP932 comments. This header's API is ASCII.
#pragma warning(push)
#pragma warning(disable: 4828)
#include "logger2.h"
#pragma warning(pop)
#include "native_layout.h"
#include "folder_menu.h"

namespace {

using Constructor = void* (__fastcall*)(void*, int);
using Destructor = void (__fastcall*)(void*);
using HostDeleteObject = void (__fastcall*)(void*, std::size_t);
using Recreate = void (__fastcall*)(void*, bool);
using ControlInitialize = void (__fastcall*)(void*);
using BrowserInitialize = HRESULT (STDMETHODCALLTYPE*)(IExplorerBrowser*, HWND, const RECT*, const FOLDERSETTINGS*);
using PathContextMenu = void (__fastcall*)(void*);
using media_dock::Pidl;
using media_dock::FolderCommand;

struct PathMenuContext {
    void* owner;
    ULONG_PTR generation;
    bool tracking = false;
    FolderCommand selected = FolderCommand::None;
};

struct BrowserSubscription {
    IExplorerBrowser* browser = nullptr; // Borrowed from the native control.
    DWORD cookie = 0;
    bool advised = false;
    ~BrowserSubscription() { if (advised) browser->Unadvise(cookie); }
};

struct Instance {
    ULONG_PTR generation = 0;
    std::unique_ptr<BrowserSubscription> subscription;
    int index = 0;
    int original_capability = 0;
    IExplorerBrowser* browser = nullptr; // Borrowed; the native control owns it.
    Pidl restore_folder;
};

media_dock::NativeLayout g_layout;
Constructor g_constructor = nullptr;
Destructor g_destructor = nullptr;
HostDeleteObject g_delete_object = nullptr;
Recreate g_recreate = nullptr;
ControlInitialize g_control_initialize = nullptr;
BrowserInitialize g_browser_initialize = nullptr;
PathContextMenu g_path_context_menu = nullptr;
decltype(&TrackPopupMenu) g_track_popup_menu = &TrackPopupMenu;
decltype(&TrackPopupMenuEx) g_track_popup_menu_ex = &TrackPopupMenuEx;
LOG_HANDLE* g_logger = nullptr;
bool g_installed = false;
HWND g_events_window = nullptr;
HMODULE g_plugin_module = nullptr;
ULONG_PTR g_generation = 0;
constexpr wchar_t kEventsClass[] = L"MediaExplorerDock.Events";
constexpr UINT kResizeBrowser = WM_APP + 1;
constexpr UINT kOpenSystemExplorer = WM_APP + 2;
constexpr UINT kNavigateClipboard = WM_APP + 3;
std::wstring g_status;
std::unordered_map<void*, Instance> g_instances;
std::unordered_map<void*, void*> g_controls;
thread_local void* g_reconstructing_allocation = nullptr;
thread_local bool g_delete_suppressed = false;
thread_local void* g_initializing_owner = nullptr;
thread_local HWND g_initializing_parent = nullptr;
thread_local PathMenuContext* g_path_menu_context = nullptr;

void Log(bool warning, const std::wstring& text) {
    OutputDebugStringW((L"[MediaExplorerDock] " + text + L"\n").c_str());
    if (g_logger) {
        if (warning) g_logger->warn(g_logger, text.c_str());
        else g_logger->info(g_logger, text.c_str());
    }
}

// WindowMouse stores its rendering HWND near the head of the object. Locate
// it by Win32 identity rather than assuming a member offset in the host ABI.
HWND ParentWindow(void* owner) {
    const auto* p = static_cast<const unsigned char*>(owner);
    const auto limit = (std::min)(g_layout.object_size, std::size_t{0x200});
    for (std::size_t offset = sizeof(void*); offset + sizeof(HWND) <= limit; offset += sizeof(void*)) {
        HWND hwnd;
        std::memcpy(&hwnd, p + offset, sizeof(hwnd));
        DWORD process = 0;
        if (GetWindowThreadProcessId(hwnd, &process) != GetCurrentThreadId() || process != GetCurrentProcessId()) continue;
        if (GetAncestor(hwnd, GA_ROOT) == hwnd &&
            GetClassLongPtrW(hwnd, GCLP_HMODULE) == reinterpret_cast<ULONG_PTR>(GetModuleHandleW(nullptr))) return hwnd;
    }
    return nullptr;
}

Pidl CurrentFolder(IExplorerBrowser* browser) {
    if (!browser) return {};
    IFolderView* view = nullptr;
    if (FAILED(browser->GetCurrentView(IID_PPV_ARGS(&view)))) return {};
    IPersistFolder2* folder = nullptr;
    const auto hr = view->GetFolder(IID_PPV_ARGS(&folder));
    view->Release();
    if (FAILED(hr)) return {};
    PIDLIST_ABSOLUTE pidl = nullptr;
    folder->GetCurFolder(&pidl);
    folder->Release();
    return Pidl(pidl);
}

void ActionError(void* owner, const std::wstring& text) {
    Log(true, text);
    MessageBoxW(ParentWindow(owner), text.c_str(), L"メディアエクスプローラー", MB_OK | MB_ICONWARNING);
}

void RunFolderCommand(void* owner, Instance& instance, UINT message) {
    if (!instance.browser) {
        ActionError(owner, L"フォルダーの準備ができていません。少し待ってからもう一度お試しください。");
        return;
    }
    if (message == kOpenSystemExplorer) {
        const auto folder = CurrentFolder(instance.browser);
        // A PIDL also handles Desktop/Libraries without constructing an
        // explorer.exe command line or interpreting user-controlled switches.
        if (!folder || FAILED(SHOpenFolderAndSelectItems(folder.get(), 0, nullptr, 0)))
            ActionError(owner, L"Windows エクスプローラーで現在のフォルダーを開けませんでした。");
    } else {
        auto target = media_dock::ReadClipboardFolder(g_events_window);
        if (!target) { ActionError(owner, target.error); return; }
        // Native navigation events update the path bar and persisted folder.
        if (FAILED(instance.browser->BrowseToIDList(target.folder.get(), SBSP_ABSOLUTE)))
            ActionError(owner, L"コピーされたアドレスのフォルダーに移動できませんでした。");
    }
}

// ExplorerBrowser can create its new SHELLDLL_DefView after the host's last
// SetRect, leaving that *inner* view at 0 x 0 even though the browser HWND is
// correctly sized. Re-deliver its current size after navigation completes.
// Queue on our own HWND: do not re-enter COM/layout inside the shell callback.
LRESULT CALLBACK EventsWindowProc(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam) {
    if (message == kResizeBrowser) {
        const auto found = g_instances.find(reinterpret_cast<void*>(wparam));
        if (found == g_instances.end() || found->second.generation != static_cast<ULONG_PTR>(lparam)) return 0;
        HWND shell = nullptr;
        RECT rect{};
        if (found->second.browser && SUCCEEDED(IUnknown_GetWindow(found->second.browser, &shell)) &&
            GetClientRect(shell, &rect) && rect.right > 0 && rect.bottom > 0)
            SendMessageW(shell, WM_SIZE, SIZE_RESTORED, MAKELPARAM(rect.right, rect.bottom));
        return 0;
    }
    if (message == kOpenSystemExplorer || message == kNavigateClipboard) {
        const auto found = g_instances.find(reinterpret_cast<void*>(wparam));
        // A queued command must not target an instance reconstructed while its
        // popup was open, even if the allocation address stayed the same.
        if (found == g_instances.end() || found->second.generation != static_cast<ULONG_PTR>(lparam)) return 0;
        try { RunFolderCommand(found->first, found->second, message); }
        catch (...) { Log(true, L"フォルダーメニューの操作を実行できませんでした。"); }
        return 0;
    }
    return DefWindowProcW(hwnd, message, wparam, lparam);
}

class BrowserEvents final : public IExplorerBrowserEvents {
    LONG references_ = 1;
    void* owner_;
    ULONG_PTR generation_;
public:
    BrowserEvents(void* owner, ULONG_PTR generation) : owner_(owner), generation_(generation) {}
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** out) override {
        if (!out) return E_POINTER;
        *out = nullptr;
        if (iid != IID_IUnknown && iid != IID_IExplorerBrowserEvents) return E_NOINTERFACE;
        *out = static_cast<IExplorerBrowserEvents*>(this);
        AddRef();
        return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return static_cast<ULONG>(InterlockedIncrement(&references_)); }
    ULONG STDMETHODCALLTYPE Release() override {
        const auto count = static_cast<ULONG>(InterlockedDecrement(&references_));
        if (!count) delete this;
        return count;
    }
    HRESULT STDMETHODCALLTYPE OnNavigationPending(PCIDLIST_ABSOLUTE) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE OnViewCreated(IShellView*) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE OnNavigationComplete(PCIDLIST_ABSOLUTE) override {
        if (g_events_window)
            PostMessageW(g_events_window, kResizeBrowser, reinterpret_cast<WPARAM>(owner_), static_cast<LPARAM>(generation_));
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE OnNavigationFailed(PCIDLIST_ABSOLUTE) override { return S_OK; }
};

bool CreateEventsWindow() {
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCWSTR>(&EventsWindowProc), &g_plugin_module)) return false;
    WNDCLASSW wc{};
    wc.hInstance = g_plugin_module;
    wc.lpszClassName = kEventsClass;
    wc.lpfnWndProc = EventsWindowProc;
    if (!RegisterClassW(&wc)) return false;
    g_events_window = CreateWindowExW(0, kEventsClass, L"", 0, 0, 0, 0, 0, HWND_MESSAGE, nullptr, g_plugin_module, nullptr);
    if (!g_events_window) UnregisterClassW(kEventsClass, g_plugin_module);
    return g_events_window != nullptr;
}

void DestroyEventsWindow() {
    if (!g_events_window) return;
    DestroyWindow(g_events_window);
    g_events_window = nullptr;
    UnregisterClassW(kEventsClass, g_plugin_module);
}

void* __fastcall ConstructorHook(void* owner, int index) {
    void* result = g_constructor(owner, index);
    if (result != owner || *static_cast<void***>(owner) != g_layout.explorer_vtable ||
        *reinterpret_cast<int*>(static_cast<unsigned char*>(owner) + g_layout.index_offset) != index) {
        // Never enable floating unless construction matches the resolver.
        Log(true, L"エクスプローラー生成時の構造検証に失敗しました。分離制限は変更しません。");
        return result;
    }
    auto* control = static_cast<unsigned char*>(owner) + g_layout.control_offset;
    if (*reinterpret_cast<void***>(control) != g_layout.control_vtable) {
        Log(true, L"エクスプローラーのコントロールを確認できません。分離制限は変更しません。");
        return result;
    }
    Instance instance;
    instance.generation = ++g_generation;
    instance.index = index;
    auto* capability = reinterpret_cast<int*>(static_cast<unsigned char*>(owner) + g_layout.float_capability_offset);
    instance.original_capability = *capability;
    g_instances.insert_or_assign(owner, std::move(instance));
    g_controls.insert_or_assign(control, owner);
    if (*capability == 0) *capability = 1;
    return result;
}

void __fastcall DestructorHook(void* argument) {
    void* owner = g_layout.destructor_is_deleter ? *static_cast<void**>(argument) : argument;
    if (owner) {
        g_controls.erase(static_cast<unsigned char*>(owner) + g_layout.control_offset);
        g_instances.erase(owner);
    }
    g_destructor(argument);
}

void __fastcall DeleteObjectHook(void* allocation, std::size_t size) {
    if (allocation && allocation == g_reconstructing_allocation) {
        g_delete_suppressed = true;
        return;
    }
    g_delete_object(allocation, size);
}

void __fastcall RecreateHook(void* owner, bool show) {
    const auto found = g_instances.find(owner);
    if (found == g_instances.end()) {
        // This cannot occur for an instance whose floating capability we enabled.
        g_recreate(owner, show);
        return;
    }
    const int index = found->second.index;
    auto folder = CurrentFolder(found->second.browser);
    // Keep the allocation and pointer unchanged: the host's multi-instance
    // owner vector still holds this address. Use the host's real destructors
    // (Unadvise, shell state/config persistence, D2D and floating HWND cleanup).
    // Then use its real constructor to bind the *new* rendering/window context.
    {
        struct Scope {
            void* old_allocation = g_reconstructing_allocation;
            bool old_suppressed = g_delete_suppressed;
            ~Scope() { g_reconstructing_allocation = old_allocation; g_delete_suppressed = old_suppressed; }
        } scope;
        g_reconstructing_allocation = owner;
        g_delete_suppressed = false;
        void* holder = owner;
        DestructorHook(g_layout.destructor_is_deleter ? &holder : owner);
        if (g_layout.destructor_is_deleter && !g_delete_suppressed) {
            // All discovered deleting destructors must reach the root delete.
            // Do not write to an allocation if that invariant unexpectedly fails.
            Log(true, L"エクスプローラーのメモリー保持を確認できなかったため、再生成を中断しました。");
            return;
        }
    }
    std::memset(owner, 0, g_layout.object_size);
    ConstructorHook(owner, index);
    const auto rebuilt = g_instances.find(owner);
    if (rebuilt == g_instances.end()) {
        Log(true, L"エクスプローラーを再生成しましたが、分離機能の再登録に失敗しました。");
        return;
    }
    rebuilt->second.restore_folder = std::move(folder);
    const auto show_method = reinterpret_cast<Recreate>((*static_cast<void***>(owner))[g_layout.show_slot]);
    show_method(owner, show);
}

HRESULT STDMETHODCALLTYPE BrowserInitializeHook(IExplorerBrowser* browser, HWND hwnd,
                                                const RECT* rect, const FOLDERSETTINGS* settings) {
    // The stock control always passes the main HWND, even after floating.
    // Correct the COM Initialize argument itself, not just SetParent afterwards:
    // ExplorerBrowser must know its real parent for sizing, focus and shell D&D.
    if (g_initializing_owner && g_initializing_parent) hwnd = g_initializing_parent;
    const auto hr = g_browser_initialize(browser, hwnd, rect, settings);
    if (SUCCEEDED(hr) && g_initializing_owner) {
        const auto instance = g_instances.find(g_initializing_owner);
        if (instance != g_instances.end()) {
            auto subscription = std::unique_ptr<BrowserSubscription>(new (std::nothrow) BrowserSubscription);
            auto* events = new (std::nothrow) BrowserEvents(g_initializing_owner, instance->second.generation);
            instance->second.browser = browser;
            if (subscription && events) {
                subscription->browser = browser;
                subscription->advised = SUCCEEDED(browser->Advise(events, &subscription->cookie));
                if (subscription->advised) instance->second.subscription = std::move(subscription);
            }
            if (events) events->Release();
            if (!instance->second.subscription)
                Log(true, L"ExplorerBrowser のナビゲーション通知を登録できません。ファイル一覧の再描画が遅れる可能性があります。");
        }
    }
    return hr;
}

void __fastcall ControlInitializeHook(void* control) {
    const auto found = g_controls.find(control);
    if (found == g_controls.end()) {
        g_control_initialize(control);
        return;
    }
    struct Scope {
        void* old_owner = g_initializing_owner;
        HWND old_parent = g_initializing_parent;
        ~Scope() { g_initializing_owner = old_owner; g_initializing_parent = old_parent; }
    } scope;
    const auto owner = found->second;
    g_initializing_owner = owner;
    g_initializing_parent = ParentWindow(owner);
    g_control_initialize(control);
    const auto instance = g_instances.find(owner);
    if (instance != g_instances.end() && instance->second.browser && instance->second.restore_folder) {
        auto folder = std::move(instance->second.restore_folder);
        if (FAILED(instance->second.browser->BrowseToIDList(folder.get(), SBSP_ABSOLUTE)))
            Log(true, L"分離前のフォルダーを復元できませんでした。本体に保存されたパスを使用します。");
    }
}

void __fastcall PathContextMenuHook(void* owner) {
    const auto found = g_instances.find(owner);
    if (found == g_instances.end()) { g_path_context_menu(owner); return; }
    PathMenuContext context{owner, found->second.generation};
    {
        struct Scope {
            PathMenuContext* previous = g_path_menu_context;
            ~Scope() { g_path_menu_context = previous; }
        } scope;
        g_path_menu_context = &context;
        g_path_context_menu(owner);
    }
    // Return "cancel" for our IDs to the native popup callback table, then
    // execute on the UI queue only after the native menu has fully unwound.
    // Neither its private std::function map nor its menu-object ABI is modified.
    if (context.selected != FolderCommand::None && g_events_window) {
        const UINT message = context.selected == FolderCommand::OpenSystemExplorer ? kOpenSystemExplorer : kNavigateClipboard;
        if (!PostMessageW(g_events_window, message, reinterpret_cast<WPARAM>(owner), static_cast<LPARAM>(context.generation)))
            Log(true, L"フォルダーメニューの操作をキューに登録できませんでした。");
    }
}

template<class Track>
auto TrackPathPopup(HMENU menu, UINT flags, Track original) -> decltype(original()) {
    auto* context = g_path_menu_context;
    if (!context || context->tracking || !(flags & TPM_RETURNCMD)) return original();
    context->tracking = true; // Also guards nested TrackPopupMenu/Ex calls.
    std::unique_ptr<media_dock::FolderMenuItems> additions;
    try {
        const auto instance = g_instances.find(context->owner);
        if (instance != g_instances.end() && instance->second.generation == context->generation) {
            const bool can_open = static_cast<bool>(CurrentFolder(instance->second.browser));
            additions = std::make_unique<media_dock::FolderMenuItems>(menu, can_open,
                IsClipboardFormatAvailable(CF_UNICODETEXT) != FALSE);
            if (!additions->inserted()) Log(true, L"既存のフォルダーメニューに項目を追加できませんでした。");
        }
    } catch (...) { Log(true, L"フォルダーメニューの追加に失敗しました。既存のメニューをそのまま表示します。"); }
    // Never retry a native API call if the host throws during its modal loop.
    const auto result = original();
    if (additions) {
        const auto command = additions->command(static_cast<UINT>(result));
        if (command != FolderCommand::None) {
            context->selected = command;
            return 0;
        }
    }
    return result; // Original IDs and cancellation keep their native behavior.
}

BOOL WINAPI TrackPopupMenuHook(HMENU menu, UINT flags, int x, int y, int reserved, HWND hwnd, const RECT* rect) {
    return TrackPathPopup(menu, flags, [&] { return g_track_popup_menu(menu, flags, x, y, reserved, hwnd, rect); });
}

BOOL WINAPI TrackPopupMenuExHook(HMENU menu, UINT flags, int x, int y, HWND hwnd, LPTPMPARAMS parameters) {
    return TrackPathPopup(menu, flags, [&] { return g_track_popup_menu_ex(menu, flags, x, y, hwnd, parameters); });
}

bool LocateBrowserInitialize() {
    const HRESULT com = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(com) && com != RPC_E_CHANGED_MODE) return false;
    IExplorerBrowser* browser = nullptr;
    const HRESULT hr = CoCreateInstance(CLSID_ExplorerBrowser, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&browser));
    if (SUCCEEDED(hr)) {
        // IExplorerBrowser's documented COM ABI: IUnknown (3), Initialize (1).
        g_browser_initialize = reinterpret_cast<BrowserInitialize>((*reinterpret_cast<void***>(browser))[3]);
        HMODULE module = nullptr;
        // The detour must not outlive an unloaded shell implementation DLL.
        const bool pinned = GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
            reinterpret_cast<LPCWSTR>(g_browser_initialize), &module) != FALSE;
        browser->Release();
        if (!pinned) g_browser_initialize = nullptr;
    }
    if (SUCCEEDED(com)) CoUninitialize();
    return g_browser_initialize != nullptr;
}

LONG ChangeHooks(bool attach) {
    struct Transaction {
        bool active = false;
        std::vector<HANDLE> threads;
        ~Transaction() {
            if (active) DetourTransactionAbort();
            for (const auto thread : threads) CloseHandle(thread);
        }
    } transaction;
    LONG error = DetourTransactionBegin();
    if (error != NO_ERROR) return error;
    transaction.active = true;
    const auto change = [&](auto& original, auto hook) {
        if (error != NO_ERROR) return;
        if (attach) error = DetourAttach(reinterpret_cast<PVOID*>(&original), reinterpret_cast<PVOID>(hook));
        else error = DetourDetach(reinterpret_cast<PVOID*>(&original), reinterpret_cast<PVOID>(hook));
    };
    change(g_constructor, ConstructorHook);
    change(g_destructor, DestructorHook);
    if (g_delete_object) change(g_delete_object, DeleteObjectHook);
    change(g_recreate, RecreateHook);
    change(g_control_initialize, ControlInitializeHook);
    change(g_browser_initialize, BrowserInitializeHook);
    change(g_path_context_menu, PathContextMenuHook);
    change(g_track_popup_menu, TrackPopupMenuHook);
    change(g_track_popup_menu_ex, TrackPopupMenuExHook);
    if (error != NO_ERROR) return error;
    // Native UI hooks only run on the main thread, but the deleting-destructor
    // variant shares the host's free implementation with worker threads. Enlist
    // all existing process threads so their instruction pointers are moved to
    // trampolines safely when the transaction is committed.
    const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return static_cast<LONG>(GetLastError());
    struct Snapshot { HANDLE handle; ~Snapshot() { CloseHandle(handle); } } close_snapshot{snapshot};
    THREADENTRY32 entry{};
    entry.dwSize = sizeof(entry);
    if (!Thread32First(snapshot, &entry)) return static_cast<LONG>(GetLastError());
    do {
        if (entry.th32OwnerProcessID != GetCurrentProcessId() || entry.th32ThreadID == GetCurrentThreadId()) continue;
        const HANDLE thread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION,
                                          FALSE, entry.th32ThreadID);
        if (!thread) {
            const DWORD code = GetLastError();
            if (code == ERROR_INVALID_PARAMETER) continue; // already exited
            return static_cast<LONG>(code);
        }
        try { transaction.threads.push_back(thread); }
        catch (...) { CloseHandle(thread); throw; }
    } while (Thread32Next(snapshot, &entry));
    // Open/enumerate all handles before suspending any thread.
    for (const auto thread : transaction.threads) {
        error = DetourUpdateThread(thread);
        if (error != NO_ERROR) return error;
    }
    error = DetourTransactionCommit();
    transaction.active = false;
    return error;
}

COMMON_PLUGIN_TABLE g_plugin = {
    L"Media Explorer Dock",
    L"Media Explorer Dock 1.1.0 / メディアエクスプローラーの標準ウィンドウ分離・フォルダーメニュー"
};

#ifdef MEDIA_DOCK_SMOKE_TEST
void StartSmokeTest(HOST_APP_TABLE* host);
#endif

} // namespace

extern "C" __declspec(dllexport) COMMON_PLUGIN_TABLE* GetCommonPluginTable() { return &g_plugin; }

extern "C" __declspec(dllexport) void InitializeLogger(LOG_HANDLE* logger) { g_logger = logger; }

extern "C" __declspec(dllexport) bool InitializePlugin(DWORD /*version*/) {
    try {
        const auto resolved = media_dock::ResolveNativeLayout(GetModuleHandleW(nullptr));
        g_status = resolved.message;
        if (!resolved.success) { Log(!resolved.native_support, g_status); return true; }
        g_layout = resolved.layout;
        g_constructor = reinterpret_cast<Constructor>(g_layout.constructor);
        g_destructor = reinterpret_cast<Destructor>(g_layout.destructor);
        g_delete_object = reinterpret_cast<HostDeleteObject>(g_layout.delete_object);
        g_recreate = reinterpret_cast<Recreate>(g_layout.recreate);
        g_control_initialize = reinterpret_cast<ControlInitialize>(g_layout.initialize_browser);
        g_path_context_menu = reinterpret_cast<PathContextMenu>(g_layout.path_context_menu);
        if (!LocateBrowserInitialize()) {
            g_status = L"ExplorerBrowser の初期化処理を取得できません。本体への変更は行いません。";
            Log(true, g_status);
            return true;
        }
        if (!CreateEventsWindow()) {
            g_status = L"ExplorerBrowser の描画通知ウィンドウを作成できません。本体への変更は行いません。";
            Log(true, g_status);
            return true;
        }
        const LONG error = ChangeHooks(true);
        g_installed = error == NO_ERROR;
        if (!g_installed) DestroyEventsWindow();
        if (!g_installed) g_status = L"Hook の登録に失敗しました。本体への変更は行いません。Win32 error=" + std::to_wstring(error);
        Log(!g_installed, g_status);
        return true;
    } catch (...) {
        // No exceptions may cross an SDK entry point. If hooks were installed,
        // keep the module loaded even if logging/allocation subsequently failed.
        if (g_installed) return true;
        DestroyEventsWindow();
        Log(true, L"プラグインを初期化できません。本体への変更は行いません。");
        return false;
    }
}

extern "C" __declspec(dllexport) void RegisterPlugin(HOST_APP_TABLE* host) {
    (void)host;
#ifdef MEDIA_DOCK_SMOKE_TEST
    StartSmokeTest(host);
#endif
}

extern "C" __declspec(dllexport) void UninitializePlugin() {
    if (!g_installed) return;
    // AviUtl normally destroys all native clients before unloading modules.
    // If it does not, restore the original capability on live instances too.
    for (const auto& item : g_instances)
        *reinterpret_cast<int*>(static_cast<unsigned char*>(item.first) + g_layout.float_capability_offset) = item.second.original_capability;
    LONG error = ERROR_NOT_ENOUGH_MEMORY;
    try { error = ChangeHooks(false); }
    catch (...) { /* The transaction guard rolls back on allocation failure. */ }
    if (error != NO_ERROR) {
        // Keep our DLL resident if another detour prevented safe detachment.
        HMODULE module = nullptr;
        GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
            reinterpret_cast<LPCWSTR>(&UninitializePlugin), &module);
        Log(true, L"Hook を解除できなかったため、安全のためプラグイン DLL を保持します。");
        return;
    }
    g_installed = false;
    g_controls.clear();
    g_instances.clear(); // Unadvise before the callback code is unloaded.
    DestroyEventsWindow();
}

#ifdef MEDIA_DOCK_SMOKE_TEST
#include "../tests/smoke_test.inc"
#endif
