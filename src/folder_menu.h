#pragma once

#include <windows.h>
#include <shlobj.h>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

namespace media_dock {

struct PidlDeleter {
    using pointer = PIDLIST_ABSOLUTE;
    void operator()(pointer p) const { CoTaskMemFree(p); }
};
using Pidl = std::unique_ptr<ITEMIDLIST, PidlDeleter>;

// Accept one absolute filesystem path, optionally quoted as in Windows
// Explorer's "Copy as path". Never interpret clipboard text as a command/URL.
std::optional<std::wstring> NormalizeFolderPath(std::wstring_view text);

struct FolderTarget {
    Pidl folder;
    std::wstring error;
    explicit operator bool() const { return folder != nullptr; }
};
FolderTarget ParseFolderTarget(std::wstring_view text);
FolderTarget ReadClipboardFolder(HWND clipboard_owner);

enum class FolderCommand { None, OpenSystemExplorer, NavigateClipboard };

// Owns only the three injected entries, not the host's HMENU or callbacks.
// IDs are chosen against the *entire* menu tree. Entries are marked so removal
// remains safe if another extension changes positions while the menu is open.
class FolderMenuItems {
public:
    FolderMenuItems(HMENU menu, bool can_open, bool can_paste);
    ~FolderMenuItems();
    FolderMenuItems(const FolderMenuItems&) = delete;
    FolderMenuItems& operator=(const FolderMenuItems&) = delete;
    bool inserted() const { return inserted_; }
    FolderCommand command(UINT id) const;
    UINT open_id() const { return open_id_; }
    UINT paste_id() const { return paste_id_; }
private:
    void RemoveEntries() noexcept;
    HMENU menu_;
    UINT open_id_ = 0;
    UINT paste_id_ = 0;
    bool inserted_ = false;
};

} // namespace media_dock
