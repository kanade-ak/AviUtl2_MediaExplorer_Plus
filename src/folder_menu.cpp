#include "folder_menu.h"
#include <algorithm>
#include <cwctype>
#include <set>

namespace media_dock {
namespace {

bool DriveAbsolute(std::wstring_view path) {
    return path.size() >= 3 && ((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z')) &&
        path[1] == L':' && path[2] == L'\\';
}

bool UncAbsolute(std::wstring_view path) {
    const auto slash = path.find(L'\\');
    return slash != std::wstring_view::npos && slash > 0 && slash + 1 < path.size() &&
        path[slash + 1] != L'\\' && path.substr(0, slash) != L"." && path.substr(0, slash) != L"?";
}

bool CollectIds(HMENU menu, std::set<HMENU>& visited, std::set<UINT>& ids) {
    if (!visited.insert(menu).second) return true;
    const int count = GetMenuItemCount(menu);
    if (count < 0) return false;
    for (int i = 0; i < count; ++i) {
        MENUITEMINFOW item{sizeof(item)};
        item.fMask = MIIM_ID | MIIM_FTYPE | MIIM_SUBMENU;
        if (!GetMenuItemInfoW(menu, static_cast<UINT>(i), TRUE, &item)) return false;
        if (!(item.fType & MFT_SEPARATOR)) ids.insert(item.wID);
        if (item.hSubMenu && !CollectIds(item.hSubMenu, visited, ids)) return false;
    }
    return true;
}

} // namespace

std::optional<std::wstring> NormalizeFolderPath(std::wstring_view text) {
    while (!text.empty() && std::iswspace(text.front())) text.remove_prefix(1);
    while (!text.empty() && std::iswspace(text.back())) text.remove_suffix(1);
    if (text.size() >= 2 && text.front() == L'"' && text.back() == L'"') {
        text.remove_prefix(1);
        text.remove_suffix(1);
    }
    if (text.empty() || text.size() >= 32767) return {};
    for (wchar_t c : text) if (c < L' ' || c == L'"') return {};
    std::wstring path(text);
    std::replace(path.begin(), path.end(), L'/', L'\\');
    bool absolute = DriveAbsolute(path);
    if (path.compare(0, 4, L"\\\\?\\") == 0) {
        const auto tail = std::wstring_view(path).substr(4);
        absolute = DriveAbsolute(tail) || (tail.size() > 4 &&
            std::towupper(tail[0]) == L'U' && std::towupper(tail[1]) == L'N' &&
            std::towupper(tail[2]) == L'C' && tail[3] == L'\\' && UncAbsolute(tail.substr(4)));
    } else if (path.compare(0, 2, L"\\\\") == 0) {
        absolute = UncAbsolute(std::wstring_view(path).substr(2));
    }
    if (!absolute) return {};
    return path;
}

FolderTarget ParseFolderTarget(std::wstring_view text) {
    const auto path = NormalizeFolderPath(text);
    if (!path) return {{}, L"クリップボードには、フォルダーの絶対パスを1つコピーしてください。"};
    const auto file_attributes = GetFileAttributesW(path->c_str());
    if (file_attributes == INVALID_FILE_ATTRIBUTES || !(file_attributes & FILE_ATTRIBUTE_DIRECTORY))
        return {{}, L"コピーされたパスのフォルダーが見つからないか、アクセスできません。ファイルではなくフォルダーのパスを指定してください。"};
    PIDLIST_ABSOLUTE raw = nullptr;
    SFGAOF attributes = SFGAO_FOLDER | SFGAO_FILESYSTEM;
    const auto hr = SHParseDisplayName(path->c_str(), nullptr, &raw, attributes, &attributes);
    Pidl folder(raw);
    if (FAILED(hr) || !folder || (attributes & (SFGAO_FOLDER | SFGAO_FILESYSTEM)) != (SFGAO_FOLDER | SFGAO_FILESYSTEM))
        return {{}, L"コピーされたパスのフォルダーが見つからないか、アクセスできません。ファイルではなくフォルダーのパスを指定してください。"};
    return {std::move(folder), {}};
}

FolderTarget ReadClipboardFolder(HWND clipboard_owner) {
    std::wstring text;
    {
        if (!OpenClipboard(clipboard_owner))
            return {{}, L"クリップボードを読み取れませんでした。少し待ってからもう一度お試しください。"};
        struct Close { ~Close() { CloseClipboard(); } } close;
        const auto handle = GetClipboardData(CF_UNICODETEXT);
        if (!handle) return {{}, L"クリップボードにフォルダーのパスがありません。テキスト形式でパスをコピーしてください。"};
        const auto bytes = GlobalSize(handle);
        if (!bytes || bytes > 1024 * 1024 || bytes % sizeof(wchar_t))
            return {{}, L"クリップボードのテキストを読み取れませんでした。"};
        const auto* data = static_cast<const wchar_t*>(GlobalLock(handle));
        if (!data) return {{}, L"クリップボードのテキストを読み取れませんでした。"};
        struct Unlock { HGLOBAL handle; ~Unlock() { GlobalUnlock(handle); } } unlock{handle};
        const auto length = bytes / sizeof(wchar_t);
        const auto* end = std::find(data, data + length, L'\0');
        if (end == data + length) return {{}, L"クリップボードのテキストが不正です。パスをコピーし直してください。"};
        text.assign(data, end);
    } // Release the clipboard before any shell/filesystem operation.
    return ParseFolderTarget(text);
}

FolderMenuItems::FolderMenuItems(HMENU menu, bool can_open, bool can_paste) : menu_(menu) {
    std::set<HMENU> visited;
    std::set<UINT> used;
    if (!CollectIds(menu, visited, used)) return;
    // Stay within the conventional 16-bit command range, excluding system
    // commands, and do not assume a host-reserved plugin range exists.
    for (UINT id = 0xefff; id > 0; --id) {
        if (used.count(id)) continue;
        if (!open_id_) open_id_ = id;
        else { paste_id_ = id; break; }
    }
    if (!open_id_ || !paste_id_) return;
    const auto insert = [&](UINT position, UINT id, const wchar_t* text, bool enabled) {
        MENUITEMINFOW item{sizeof(item)};
        item.fMask = MIIM_ID | MIIM_FTYPE | MIIM_STATE | MIIM_DATA;
        item.wID = id;
        item.fType = text ? MFT_STRING : MFT_SEPARATOR;
        item.fState = enabled ? MFS_ENABLED : MFS_DISABLED;
        item.dwItemData = reinterpret_cast<ULONG_PTR>(this);
        if (text) { item.fMask |= MIIM_STRING; item.dwTypeData = const_cast<LPWSTR>(text); }
        return InsertMenuItemW(menu_, position, TRUE, &item) != FALSE;
    };
    if (insert(0, open_id_, L"PC側のエクスプローラーで開く", can_open) &&
        insert(1, paste_id_, L"コピーしたアドレスに移動", can_paste) && insert(2, 0, nullptr, true))
        inserted_ = true;
    else RemoveEntries();
}

FolderMenuItems::~FolderMenuItems() { RemoveEntries(); }

FolderCommand FolderMenuItems::command(UINT id) const {
    if (!inserted_) return FolderCommand::None;
    if (id == open_id_) return FolderCommand::OpenSystemExplorer;
    if (id == paste_id_) return FolderCommand::NavigateClipboard;
    return FolderCommand::None;
}

void FolderMenuItems::RemoveEntries() noexcept {
    for (int i = GetMenuItemCount(menu_) - 1; i >= 0; --i) {
        MENUITEMINFOW item{sizeof(item)};
        item.fMask = MIIM_DATA;
        if (GetMenuItemInfoW(menu_, static_cast<UINT>(i), TRUE, &item) && item.dwItemData == reinterpret_cast<ULONG_PTR>(this))
            RemoveMenu(menu_, static_cast<UINT>(i), MF_BYPOSITION);
    }
    inserted_ = false;
}

} // namespace media_dock
