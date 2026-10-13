#pragma once

#include <windows.h>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace media_dock {

// These are discovered from the loaded image, never from a version/address table.
struct NativeLayout {
    void* constructor = nullptr;
    void* destructor = nullptr;
    // Some releases inline the destructor into a unique_ptr deleter. In that
    // case its argument is void**, and the root delete is suppressed only
    // during in-place reconstruction (all subobject cleanup still runs).
    bool destructor_is_deleter = false;
    void* delete_object = nullptr;
    void* recreate = nullptr;
    void* initialize_browser = nullptr;
    // The explorer's own path-bar menu method, found by its native bookmark
    // labels and membership in the primary RTTI vtable (no fixed slot).
    void* path_context_menu = nullptr;
    void** explorer_vtable = nullptr;
    void** control_vtable = nullptr;
    std::size_t recreate_slot = 0;
    std::size_t show_slot = 0;
    std::size_t object_size = 0;
    std::size_t index_offset = 0;
    std::size_t control_offset = 0;
    std::size_t float_capability_offset = 0;
    // Used by the integration test, not needed by the plugin itself.
    void* change_floating = nullptr;
};

struct ResolveResult {
    NativeLayout layout;
    bool success = false;
    bool native_support = false;
    std::wstring message;
};

ResolveResult ResolveNativeLayout(HMODULE module);

} // namespace media_dock
