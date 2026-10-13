#include "native_layout.h"
#include <detours.h>
#include <algorithm>
#include <array>
#include <cstring>
#include <cwchar>
#include <map>
#include <set>
#include <stdexcept>
#include <utility>

namespace media_dock {
namespace {

using Byte = unsigned char;

struct Function {
    Byte* begin = nullptr;
    Byte* end = nullptr;
    explicit operator bool() const { return begin && end > begin; }
};

struct Section {
    Byte* begin;
    std::size_t size;
    DWORD flags;
};

class Image {
public:
    explicit Image(HMODULE module) : base_(reinterpret_cast<Byte*>(module)) {
        if (!base_) throw std::runtime_error("No host image");
        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base_);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0)
            throw std::runtime_error("Invalid DOS header");
        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base_ + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE || nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
            nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            throw std::runtime_error("The host is not a PE64 image");
        size_ = nt->OptionalHeader.SizeOfImage;
        const auto* sh = IMAGE_FIRST_SECTION(nt);
        for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            if (sh[i].VirtualAddress >= size_) throw std::runtime_error("Invalid PE section");
            const auto size = (std::min)(static_cast<std::size_t>(sh[i].Misc.VirtualSize),
                                        size_ - sh[i].VirtualAddress);
            sections_.push_back({base_ + sh[i].VirtualAddress, size, sh[i].Characteristics});
        }
        const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if (!dir.VirtualAddress || dir.VirtualAddress + static_cast<std::size_t>(dir.Size) > size_)
            throw std::runtime_error("No valid x64 unwind table");
        const auto* entries = reinterpret_cast<const RUNTIME_FUNCTION*>(base_ + dir.VirtualAddress);
        std::map<DWORD, DWORD> extents;
        for (std::size_t i = 0; i < dir.Size / sizeof(RUNTIME_FUNCTION); ++i) {
            if (entries[i].BeginAddress >= entries[i].EndAddress || entries[i].EndAddress > size_) continue;
            auto root = entries[i];
            for (unsigned depth = 0; depth < 16; ++depth) {
                if (root.UnwindData >= size_ || size_ - root.UnwindData < 4)
                    throw std::runtime_error("Invalid unwind info");
                const auto* unwind = base_ + root.UnwindData;
                if (!((unwind[0] >> 3) & UNW_FLAG_CHAININFO)) break;
                const auto offset = 4u + ((static_cast<unsigned>(unwind[2]) + 1u) & ~1u) * 2u;
                if (!contains(unwind + offset, sizeof(RUNTIME_FUNCTION)))
                    throw std::runtime_error("Invalid chained unwind info");
                std::memcpy(&root, unwind + offset, sizeof(root));
                if (depth == 15) throw std::runtime_error("Cyclic unwind chain");
            }
            // MSVC splits prologue, hot/cold and epilogue regions into separate
            // .pdata entries. A hook must use the canonical prologue, not a
            // chained region in the middle of the function.
            auto& end = extents[root.BeginAddress];
            end = (std::max)(end, entries[i].EndAddress);
        }
        for (const auto& extent : extents)
            functions_.push_back({base_ + extent.first, base_ + extent.second});
    }

    bool contains(const void* address, std::size_t size = 1) const {
        const auto a = reinterpret_cast<std::uintptr_t>(address);
        const auto b = reinterpret_cast<std::uintptr_t>(base_);
        return a >= b && a - b <= size_ && size <= size_ - (a - b);
    }

    bool executable(const void* address) const {
        for (const auto& s : sections_)
            if ((s.flags & IMAGE_SCN_MEM_EXECUTE) && address >= s.begin && address < s.begin + s.size) return true;
        return false;
    }

    Function function(const void* address) const {
        const auto it = std::upper_bound(functions_.begin(), functions_.end(), address,
            [](const void* p, Function f) { return p < f.begin; });
        if (it == functions_.begin()) return {};
        const auto f = *std::prev(it);
        return address < f.end ? f : Function{};
    }

    std::vector<Byte*> strings(const char* value) const {
        return find_bytes(value, std::strlen(value) + 1);
    }

    std::vector<Byte*> wide_strings(const wchar_t* value) const {
        return find_bytes(value, (std::wcslen(value) + 1) * sizeof(wchar_t));
    }

    std::vector<Byte*> find_bytes(const void* value, std::size_t size) const {
        std::vector<Byte*> result;
        for (const auto& s : sections_) {
            if (s.flags & IMAGE_SCN_MEM_EXECUTE || s.size < size) continue;
            for (std::size_t i = 0; i <= s.size - size; ++i)
                if (std::memcmp(s.begin + i, value, size) == 0) result.push_back(s.begin + i);
        }
        return result;
    }

    // MSVC x64 RTTI: TypeDescriptor -> CompleteObjectLocator -> primary vftable.
    // The number and order of virtual methods can change; the recreate method is
    // located separately by its diagnostic string, not by a hard-coded slot.
    void** vtable(const char* name) const {
        std::set<void**> candidates;
        for (auto* text : strings(name)) {
            if (!contains(text - 16, 16)) continue;
            const auto type_rva = static_cast<DWORD>(text - 16 - base_);
            for (const auto& s : sections_) {
                if (s.flags & IMAGE_SCN_MEM_EXECUTE || s.size < 24) continue;
                for (std::size_t i = 0; i <= s.size - 24; i += 4) {
                    const auto* col = reinterpret_cast<const DWORD*>(s.begin + i);
                    if (col[0] != 1 || col[1] != 0 || col[2] != 0 || col[3] != type_rva ||
                        col[5] != static_cast<DWORD>(s.begin + i - base_)) continue;
                    const auto col_address = reinterpret_cast<std::uintptr_t>(col);
                    for (const auto& ps : sections_) {
                        if (ps.flags & IMAGE_SCN_MEM_EXECUTE || ps.size < 16) continue;
                        for (std::size_t j = 0; j <= ps.size - 16; j += 8) {
                            std::uintptr_t pointer;
                            std::memcpy(&pointer, ps.begin + j, sizeof(pointer));
                            if (pointer != col_address) continue;
                            auto** table = reinterpret_cast<void**>(ps.begin + j + 8);
                            if (executable(table[0])) candidates.insert(table);
                        }
                    }
                }
            }
        }
        if (candidates.size() != 1) throw std::runtime_error("Primary RTTI vtable is missing or ambiguous");
        return *candidates.begin();
    }

    std::vector<Byte*> rip_refs(const void* target) const {
        std::vector<Byte*> result;
        for (const auto& s : sections_) {
            if (!(s.flags & IMAGE_SCN_MEM_EXECUTE) || s.size < 7) continue;
            for (std::size_t i = 0; i <= s.size - 7; ++i) {
                auto* p = s.begin + i;
                if ((p[0] & 0xf0) != 0x40 || (p[1] != 0x8d && p[1] != 0x8b) || (p[2] & 0xc7) != 5) continue;
                std::int32_t displacement;
                std::memcpy(&displacement, p + 3, sizeof(displacement));
                if (p + 7 + displacement == target && function(p)) result.push_back(p);
            }
        }
        return result;
    }

    std::vector<Byte*> call_refs(const void* target) const {
        std::vector<Byte*> result;
        for (const auto& s : sections_) {
            if (!(s.flags & IMAGE_SCN_MEM_EXECUTE) || s.size < 5) continue;
            for (std::size_t i = 0; i <= s.size - 5; ++i) {
                auto* p = s.begin + i;
                if (p[0] != 0xe8) continue;
                std::int32_t displacement;
                std::memcpy(&displacement, p + 1, sizeof(displacement));
                if (p + 5 + displacement == target && function(p)) result.push_back(p);
            }
        }
        return result;
    }

    std::vector<Function> referring_functions(const char* marker) const {
        std::map<Byte*, Function> result;
        for (auto* text : strings(marker))
            for (auto* ref : rip_refs(text)) {
                const auto f = function(ref);
                result.emplace(f.begin, f);
            }
        std::vector<Function> values;
        for (const auto& entry : result) values.push_back(entry.second);
        return values;
    }

    std::size_t vtable_size(void** table) const {
        std::size_t i = 0;
        while (i < 128 && contains(table + i, sizeof(void*)) && executable(table[i])) ++i;
        return i;
    }

private:
    Byte* base_;
    std::size_t size_ = 0;
    std::vector<Section> sections_;
    std::vector<Function> functions_;
};

struct Instruction {
    Byte* pc = nullptr;
    std::size_t length = 0;
    unsigned opcode = 0;
    unsigned rex = 0;
    unsigned width = 4;
    int reg = -1;
    int rm = -1;
    int base = -1;
    int index = -1;
    unsigned scale = 1;
    std::int64_t displacement = 0;
    bool memory = false;
    bool rip = false;
    bool has_immediate = false;
    std::int64_t immediate = 0;
    Byte* target = nullptr;
};

// Detours supplies instruction lengths, including AVX instructions. Only the
// ordinary MOV/LEA/store/call semantics needed for layout discovery are decoded.
Instruction decode(Byte* pc, Byte* end) {
    Instruction d;
    d.pc = pc;
    if (end - pc < 1) return d;
    const auto* next = static_cast<Byte*>(DetourCopyInstruction(nullptr, nullptr, pc, nullptr, nullptr));
    if (!next || next <= pc || next - pc > 15 || next > end) return d;
    d.length = static_cast<std::size_t>(next - pc);
    std::size_t p = 0;
    bool short_operand = false;
    while (p < d.length) {
        const auto b = pc[p];
        if ((b & 0xf0) == 0x40) d.rex = b;
        else if (b == 0x66) short_operand = true;
        else if (b != 0xf0 && b != 0xf2 && b != 0xf3 && b != 0x2e && b != 0x3e && b != 0x67 && b != 0x65 && b != 0x64) break;
        ++p;
    }
    if (p >= d.length) return d;
    d.opcode = pc[p++];
    d.width = (d.rex & 8) ? 8u : (short_operand ? 2u : 4u);
    if (d.opcode == 0x0f && p < d.length) d.opcode = 0x100 | pc[p++];
    auto immediate = [&](std::size_t count) {
        if (p + count > d.length) return;
        std::int64_t value = 0;
        if (count == 1) value = static_cast<signed char>(pc[p]);
        if (count == 2) { std::int16_t v; std::memcpy(&v, pc + p, 2); value = v; }
        if (count == 4) { std::int32_t v; std::memcpy(&v, pc + p, 4); value = v; }
        if (count == 8) std::memcpy(&value, pc + p, 8);
        d.has_immediate = true;
        d.immediate = value;
        p += count;
    };
    if (d.opcode == 0xe8 || d.opcode == 0xe9) {
        immediate(4);
        if (d.has_immediate) d.target = pc + d.length + d.immediate;
        return d;
    }
    if (d.opcode >= 0xb8 && d.opcode <= 0xbf) {
        d.reg = static_cast<int>(d.opcode - 0xb8 + ((d.rex & 1) ? 8 : 0));
        immediate(d.width == 8 ? 8 : d.width);
        return d;
    }
    if (d.opcode >= 0xb0 && d.opcode <= 0xb7) {
        d.width = 1;
        d.reg = static_cast<int>(d.opcode - 0xb0 + ((d.rex & 1) ? 8 : 0));
        immediate(1);
        return d;
    }
    const bool modrm = d.opcode == 0x8d || d.opcode == 0x8b || d.opcode == 0x89 ||
        d.opcode == 0x88 || d.opcode == 0x8a || d.opcode == 0xc6 || d.opcode == 0xc7 ||
        d.opcode == 0x31 || d.opcode == 0x33 || d.opcode == 0x81 || d.opcode == 0x83 ||
        d.opcode == 0xff || d.opcode == 0x85 || d.opcode == 0x84 || d.opcode == 0x39 || d.opcode == 0x3b;
    if (!modrm || p >= d.length) return d;
    const unsigned m = pc[p++];
    const unsigned mode = m >> 6;
    d.reg = static_cast<int>(((m >> 3) & 7) + ((d.rex & 4) ? 8 : 0));
    d.rm = static_cast<int>((m & 7) + ((d.rex & 1) ? 8 : 0));
    d.memory = mode != 3;
    if (d.opcode == 0x88 || d.opcode == 0x8a || d.opcode == 0xc6 || d.opcode == 0x84) d.width = 1;
    if (d.memory) {
        d.base = d.rm;
        if ((m & 7) == 4 && p < d.length) {
            const unsigned sib = pc[p++];
            d.scale = 1u << (sib >> 6);
            d.index = static_cast<int>(((sib >> 3) & 7) + ((d.rex & 2) ? 8 : 0));
            if (d.index == 4) d.index = -1;
            d.base = static_cast<int>((sib & 7) + ((d.rex & 1) ? 8 : 0));
            if (mode == 0 && (sib & 7) == 5) d.base = -1;
        } else if (mode == 0 && (m & 7) == 5) {
            d.rip = true;
            d.base = -1;
        }
        if (mode == 1 && p < d.length) d.displacement = static_cast<signed char>(pc[p++]);
        if (mode == 2 || (mode == 0 && d.base == -1)) {
            if (p + 4 <= d.length) { std::int32_t v; std::memcpy(&v, pc + p, 4); d.displacement = v; p += 4; }
        }
        if (d.rip) d.target = pc + d.length + d.displacement;
    }
    if (d.opcode == 0xc6 || d.opcode == 0xc7 || d.opcode == 0x81 || d.opcode == 0x83)
        immediate(d.opcode == 0xc6 || d.opcode == 0x83 ? 1 : (short_operand ? 2 : 4));
    return d;
}

std::vector<Instruction> instructions(Function f) {
    std::vector<Instruction> result;
    for (auto* p = f.begin; p < f.end;) {
        const auto d = decode(p, f.end);
        if (!d.length) throw std::runtime_error("Cannot decode a native function");
        result.push_back(d);
        p += d.length;
    }
    return result;
}

bool refers_to(const Image& image, Function f, const void* address) {
    for (auto* ref : image.rip_refs(address)) if (ref >= f.begin && ref < f.end) return true;
    return false;
}

Function unique_marker_function(const Image& image, const char* marker) {
    const auto functions = image.referring_functions(marker);
    if (functions.size() != 1) throw std::runtime_error("Diagnostic function is missing or ambiguous");
    return functions.front();
}

struct Value {
    enum Kind { Unknown, This, Index, Address, Constant, Stack, OwnedThis } kind = Unknown;
    std::int64_t value = 0;
};

Value effective_address(const Instruction& d, const std::array<Value, 16>& r) {
    if (d.rip) return {Value::Address, reinterpret_cast<std::int64_t>(d.target)};
    if (d.base < 0) return {};
    auto v = r[static_cast<std::size_t>(d.base)];
    if (d.index >= 0) {
        const auto index = r[static_cast<std::size_t>(d.index)];
        if (index.kind != Value::Constant) return {};
        v.value += index.value * d.scale;
    }
    if (v.kind == Value::This || v.kind == Value::Address || v.kind == Value::Constant || v.kind == Value::Stack || v.kind == Value::OwnedThis) v.value += d.displacement;
    else return {};
    return v;
}

void track(const Instruction& d, std::array<Value, 16>& r, std::map<std::int64_t, Value>& stack, bool owned_load = false) {
    const auto source = [&](int reg) { return reg >= 0 ? r[static_cast<std::size_t>(reg)] : Value{}; };
    const auto address = d.memory ? effective_address(d, r) : Value{};
    if (address.kind == Value::Stack && (d.opcode == 0x89 || d.opcode == 0x88 || d.opcode == 0xc6 || d.opcode == 0xc7))
        stack[address.value] = d.has_immediate ? Value{Value::Constant, d.immediate} : source(d.reg);
    if (d.opcode >= 0x50 && d.opcode <= 0x57) r[4].value -= 8;
    else if (d.opcode >= 0x58 && d.opcode <= 0x5f) r[4].value += 8;
    else if (d.opcode == 0x8d && d.reg >= 0) r[static_cast<std::size_t>(d.reg)] = effective_address(d, r);
    else if ((d.opcode == 0x8b || d.opcode == 0x8a) && d.reg >= 0) {
        Value value;
        if (!d.memory) value = source(d.rm);
        else if (owned_load && d.width == 8 && address.kind == Value::This && address.value == 0)
            value = {Value::OwnedThis, 0};
        else if (address.kind == Value::Stack) {
            const auto slot = stack.find(address.value);
            if (slot != stack.end()) value = slot->second;
        }
        r[static_cast<std::size_t>(d.reg)] = value;
    }
    else if ((d.opcode == 0x89 || d.opcode == 0x88) && !d.memory && d.rm >= 0)
        r[static_cast<std::size_t>(d.rm)] = source(d.reg);
    else if (d.opcode >= 0xb0 && d.opcode <= 0xbf && d.has_immediate && d.reg >= 0)
        r[static_cast<std::size_t>(d.reg)] = {Value::Constant, d.immediate};
    else if ((d.opcode == 0xc7 || d.opcode == 0xc6) && !d.memory && d.rm >= 0)
        r[static_cast<std::size_t>(d.rm)] = {Value::Constant, d.immediate};
    else if ((d.opcode == 0x31 || d.opcode == 0x33) && !d.memory && d.reg >= 0 && d.rm >= 0) {
        const int dest = d.opcode == 0x31 ? d.rm : d.reg;
        r[static_cast<std::size_t>(dest)] = d.reg == d.rm ? Value{Value::Constant, 0} : Value{};
    } else if ((d.opcode == 0x81 || d.opcode == 0x83) && !d.memory && d.rm >= 0) {
        auto& v = r[static_cast<std::size_t>(d.rm)];
        if (d.reg == 0) v.value += d.immediate;
        else if (d.reg == 5) v.value -= d.immediate;
        else if (d.reg != 7) v = {};
    } else if (d.opcode == 0xe8 || (d.opcode == 0xff && (d.reg & 7) == 2)) {
        for (const int i : {0, 1, 2, 8, 9, 10, 11}) r[static_cast<std::size_t>(i)] = {};
    }
}

void discover_constructor_fields(Function f, NativeLayout& layout) {
    std::array<Value, 16> r{};
    r[1] = {Value::This, 0};
    r[2] = {Value::Index, 0};
    r[4] = {Value::Stack, 0};
    std::map<std::int64_t, Value> stack;
    std::set<std::size_t> indices, controls;
    for (const auto& d : instructions(f)) {
        if (d.memory && (d.opcode == 0x89 || d.opcode == 0x88 || d.opcode == 0xc6 || d.opcode == 0xc7)) {
            const auto dest = effective_address(d, r);
            const auto src = d.has_immediate ? Value{Value::Constant, d.immediate} : (d.reg >= 0 ? r[static_cast<std::size_t>(d.reg)] : Value{});
            if (dest.kind == Value::This && dest.value > 0 && dest.value < 0x100000) {
                const auto offset = static_cast<std::size_t>(dest.value);
                if (src.kind == Value::Index && d.width == 4) indices.insert(offset);
                if (src.kind == Value::Address && d.width == 8 && src.value == reinterpret_cast<std::int64_t>(layout.control_vtable)) controls.insert(offset);
            }
        }
        track(d, r, stack);
    }
    if (indices.size() != 1 || controls.size() != 1)
        throw std::runtime_error("Constructor fields missing/ambiguous: index=" + std::to_string(indices.size()) +
            " control=" + std::to_string(controls.size()));
    layout.index_offset = *indices.begin();
    layout.control_offset = *controls.begin();
}

std::size_t discover_float_capability(const Image& image) {
    const auto labels = image.wide_strings(L"ウィンドウを分離");
    std::map<Byte*, Function> candidates;
    for (auto* label : labels)
        for (auto* ref : image.rip_refs(label)) {
            const auto f = image.function(ref);
            candidates.emplace(f.begin, f);
        }
    std::set<std::size_t> offsets;
    for (const auto& candidate : candidates) {
        std::array<Value, 16> r{};
        r[1] = {Value::This, 0};
        r[4] = {Value::Stack, 0};
        std::map<std::int64_t, Value> stack;
        std::set<std::size_t> checks;
        for (const auto& d : instructions(candidate.second)) {
            if ((d.opcode == 0x81 || d.opcode == 0x83) && d.reg == 7 && d.memory && d.width == 4 &&
                d.has_immediate && d.immediate == 0) {
                const auto field = effective_address(d, r);
                if (field.kind == Value::This && field.value > 0 && field.value < 0x400)
                    checks.insert(static_cast<std::size_t>(field.value));
            }
            if (d.opcode == 0x8d && std::find(labels.begin(), labels.end(), d.target) != labels.end()) {
                // The menu insertion is guarded by exactly one native field
                // check. Do not confuse WindowMouse's event-routing flags with
                // the WindowClient capability used by the menu builder.
                if (checks.size() == 1) offsets.insert(*checks.begin());
                break;
            }
            track(d, r, stack);
        }
    }
    if (offsets.size() != 1) throw std::runtime_error("Native floating menu capability is missing or ambiguous");
    return *offsets.begin();
}

void* discover_path_context_menu(const Image& image, void** explorer_vtable) {
    // Scope popup interception to this virtual method, not screen coordinates,
    // translated runtime menu text, or an assumed vtable index. The two native
    // labels identify the path-bar menu rather than a shell/file context menu.
    std::set<Byte*> add_functions, remove_functions, matches;
    for (auto* label : image.wide_strings(L"ブックマークに追加"))
        for (auto* ref : image.rip_refs(label)) add_functions.insert(image.function(ref).begin);
    for (auto* label : image.wide_strings(L"ブックマークから削除"))
        for (auto* ref : image.rip_refs(label)) remove_functions.insert(image.function(ref).begin);
    for (std::size_t i = 0; i < image.vtable_size(explorer_vtable); ++i) {
        auto* method = static_cast<Byte*>(explorer_vtable[i]);
        if (add_functions.count(method) && remove_functions.count(method)) matches.insert(method);
    }
    if (matches.size() != 1) throw std::runtime_error("Explorer path-bar menu method is missing or ambiguous");
    return *matches.begin();
}

void discover_destructor_semantics(const Image& image, NativeLayout& layout) {
    std::array<Value, 16> r{};
    r[1] = {Value::This, 0};
    r[4] = {Value::Stack, 0};
    std::map<std::int64_t, Value> stack;
    std::set<bool> kinds;
    std::set<Byte*> deletes;
    for (const auto& d : instructions(image.function(layout.destructor))) {
        if (d.opcode == 0x89 && d.memory && d.width == 8 && d.reg >= 0) {
            const auto dest = effective_address(d, r);
            const auto src = r[static_cast<std::size_t>(d.reg)];
            if (dest.value == 0 && src.kind == Value::Address &&
                src.value == reinterpret_cast<std::int64_t>(layout.explorer_vtable)) {
                if (dest.kind == Value::This) kinds.insert(false);
                if (dest.kind == Value::OwnedThis) kinds.insert(true);
            }
        }
        if (d.opcode == 0xe8 && r[1].kind == Value::OwnedThis && r[1].value == 0 &&
            r[2].kind == Value::Constant && r[2].value == static_cast<std::int64_t>(layout.object_size))
            deletes.insert(d.target);
        track(d, r, stack, true);
    }
    if (kinds.size() != 1) throw std::runtime_error("Destructor calling convention is ambiguous");
    layout.destructor_is_deleter = *kinds.begin();
    if (layout.destructor_is_deleter) {
        if (deletes.size() != 1) throw std::runtime_error("Inlined destructor root delete is ambiguous");
        layout.delete_object = *deletes.begin();
    }
}

std::size_t discover_object_size(const Image& image, Function constructor) {
    std::set<std::size_t> sizes;
    for (auto* call : image.call_refs(constructor.begin)) {
        const auto list = instructions(image.function(call));
        const auto at = std::find_if(list.begin(), list.end(), [&](const Instruction& d) { return d.pc == call; });
        if (at == list.end()) continue;
        const auto position = static_cast<std::size_t>(at - list.begin());
        const auto begin = position > 32 ? position - 32 : 0;
        std::map<std::size_t, unsigned> counts;
        for (std::size_t i = begin; i < position; ++i) {
            const auto& d = list[i];
            if (d.opcode >= 0xb8 && d.opcode <= 0xbf && (d.reg == 1 || d.reg == 2 || d.reg == 8) &&
                d.has_immediate && d.immediate >= 0x400 && d.immediate <= 0x100000)
                ++counts[static_cast<std::size_t>(d.immediate)];
        }
        // Allocation and zero-fill must independently agree on the extent.
        for (const auto& entry : counts) if (entry.second >= 2) sizes.insert(entry.first);
    }
    if (sizes.size() != 1) throw std::runtime_error("Native allocation extent is missing or ambiguous");
    return *sizes.begin();
}

} // namespace

ResolveResult ResolveNativeLayout(HMODULE module) {
    ResolveResult result;
    try {
        const Image image(module);
        auto& l = result.layout;
        l.explorer_vtable = image.vtable(".?AVExplorerComponent@Component@@");
        l.control_vtable = image.vtable(".?AVExplorerControl@Control@@");
        const auto recreates = image.referring_functions("Component::ExplorerComponent::recreateClient");
        if (recreates.empty()) {
            result.native_support = true;
            result.message = L"従来の分離制限が見つかりません。本体の処理を変更せずに使用します。";
            return result;
        }
        if (recreates.size() != 1) throw std::runtime_error("Recreate function is ambiguous");
        const auto recreate = recreates.front();
        if (!refers_to(image, recreate, image.strings("not support floating window").at(0)))
            throw std::runtime_error("The recreate function is no longer the unsupported stub");
        l.recreate = recreate.begin;
        std::set<std::size_t> slots;
        for (std::size_t i = 0; i < image.vtable_size(l.explorer_vtable); ++i)
            if (l.explorer_vtable[i] == l.recreate) slots.insert(i);
        if (slots.size() != 1 || *slots.begin() < 2) throw std::runtime_error("Recreate vtable slot is ambiguous");
        l.recreate_slot = *slots.begin();
        l.show_slot = l.recreate_slot - 1;
        std::vector<Function> constructors;
        for (const auto f : image.referring_functions("Window.explorer"))
            if (refers_to(image, f, l.explorer_vtable)) constructors.push_back(f);
        if (constructors.size() != 1) throw std::runtime_error("Explorer constructor is missing or ambiguous");
        l.constructor = constructors.front().begin;
        const auto control_destructor = unique_marker_function(image, "Control::ExplorerControl::~ExplorerControl");
        std::set<Byte*> destructors;
        for (auto* ref : image.rip_refs(l.explorer_vtable)) {
            const auto f = image.function(ref);
            if (f.begin == l.constructor) continue;
            for (const auto& d : instructions(f))
                if (d.opcode == 0xe8 && d.target == control_destructor.begin) destructors.insert(f.begin);
        }
        if (destructors.size() != 1) throw std::runtime_error("Explorer destructor is missing or ambiguous");
        l.destructor = *destructors.begin();
        l.initialize_browser = unique_marker_function(image, "Control::ExplorerControl::initialize").begin;
        l.path_context_menu = discover_path_context_menu(image, l.explorer_vtable);
        discover_constructor_fields(constructors.front(), l);
        l.float_capability_offset = discover_float_capability(image);
        l.object_size = discover_object_size(image, constructors.front());
        discover_destructor_semantics(image, l);
        if (l.index_offset + sizeof(int) > l.object_size || l.control_offset + sizeof(void*) > l.object_size ||
            l.control_offset <= l.index_offset || l.float_capability_offset + sizeof(int) > l.index_offset)
            throw std::runtime_error("Discovered object fields are inconsistent");

        // Locate the native floating switch through its indirect recreate call.
        // This is also independently checked by the in-process smoke tests.
        std::set<Byte*> floating_switches;
        // Check the predecessor slot before using it for visibility changes.
        const auto show = l.explorer_vtable[l.show_slot];
        auto show_function = image.function(show);
        if (!show_function || show_function.begin != show) {
            // Leaf/tail-call methods may have no x64 unwind entry.
            auto* begin = static_cast<Byte*>(show);
            if (!image.contains(begin, 128)) throw std::runtime_error("Invalid visibility method extent");
            for (auto* pc = begin; pc < begin + 128;) {
                const auto d = decode(pc, begin + 128);
                if (!d.length) break;
                pc += d.length;
                if (d.opcode == 0xc3 || d.opcode == 0xe9 || (d.opcode == 0xff && (d.reg & 7) == 4)) {
                    show_function = {begin, pc};
                    break;
                }
            }
        }
        bool valid_show = false;
        for (const auto& d : instructions(show_function))
            if (d.opcode == 0x89 && d.memory && d.base == 1 && d.displacement > 0 && d.width == 4) valid_show = true;
        if (!valid_show) throw std::runtime_error("Native visibility method has changed its semantics");
        // The switch does not directly call the recreate stub; it uses the
        // dynamically found slot. Search executable functions reached by the
        // show implementation's internal layout routine, in tests only below.
        const auto slot_displacement = static_cast<std::int64_t>(l.recreate_slot * sizeof(void*));
        // A floating switch contains the slot call and ClientToScreen, unlike
        // layout restoration. Use the import thunk reference as a stable anchor.
        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(module);
        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(reinterpret_cast<Byte*>(module) + dos->e_lfanew);
        const auto& idir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        auto* imports = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(reinterpret_cast<Byte*>(module) + idir.VirtualAddress);
        for (; idir.VirtualAddress && imports->Name; ++imports) {
            if (!imports->OriginalFirstThunk) continue;
            auto* names = reinterpret_cast<const IMAGE_THUNK_DATA64*>(reinterpret_cast<Byte*>(module) + imports->OriginalFirstThunk);
            auto* iat = reinterpret_cast<const IMAGE_THUNK_DATA64*>(reinterpret_cast<Byte*>(module) + imports->FirstThunk);
            for (std::size_t i = 0; names[i].u1.AddressOfData; ++i) {
                if (IMAGE_SNAP_BY_ORDINAL64(names[i].u1.Ordinal)) continue;
                const auto* name = reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(reinterpret_cast<Byte*>(module) + names[i].u1.AddressOfData);
                if (std::strcmp(reinterpret_cast<const char*>(name->Name), "ClientToScreen") != 0) continue;
                // CALL [RIP+iat] has no REX byte, so inspect .pdata functions via
                // byte references, then validate instruction boundaries.
                const auto* sh = IMAGE_FIRST_SECTION(nt);
                for (unsigned si = 0; si < nt->FileHeader.NumberOfSections; ++si) {
                    if (!(sh[si].Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
                    auto* section = reinterpret_cast<Byte*>(module) + sh[si].VirtualAddress;
                    for (std::size_t p = 0; p + 6 <= sh[si].Misc.VirtualSize; ++p) {
                        if (section[p] != 0xff || section[p + 1] != 0x15) continue;
                        std::int32_t rel; std::memcpy(&rel, section + p + 2, 4);
                        if (section + p + 6 + rel != reinterpret_cast<const Byte*>(iat + i)) continue;
                        const auto f = image.function(section + p);
                        if (!f) continue;
                        for (const auto& d : instructions(f))
                            if (d.opcode == 0xff && (d.reg & 7) == 2 && d.memory && !d.rip &&
                                d.displacement == slot_displacement) floating_switches.insert(f.begin);
                    }
                }
            }
        }
        if (floating_switches.size() == 1) l.change_floating = *floating_switches.begin();
        result.success = true;
        result.message = L"メディアエクスプローラーの標準ウィンドウ分離とフォルダーパス欄の追加メニューを有効にしました。";
    } catch (const std::exception& e) {
        const auto* s = e.what();
        result.message = L"本体の構造を特定できなかったため変更を行いません: ";
        while (*s) result.message += static_cast<unsigned char>(*s++);
    }
    return result;
}

} // namespace media_dock
