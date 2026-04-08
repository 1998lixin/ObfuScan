#include <iostream>
#include <vector>
#include <string>
#include <string_view>
#include <map>
#include <set>
#include <unordered_set>
#include <unordered_map>
#include <algorithm>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <cctype>

#include "miniz.h"
#include "disasm_arm64.h"

#ifdef _WIN32
#include <windows.h>
#endif

// =========================
// 轻量 ELF64 定义（避免依赖 elf.h，方便跨平台）
// =========================

static constexpr uint8_t ELFCLASS64_VAL = 2;
static constexpr uint8_t ELFDATA2LSB_VAL = 1;
static constexpr uint16_t EM_AARCH64_VAL = 183;

static constexpr uint32_t PT_LOAD_VAL = 1;
static constexpr uint32_t PF_X_VAL = 0x1;
static constexpr uint32_t PF_W_VAL = 0x2;
static constexpr uint32_t PF_R_VAL = 0x4;

static constexpr uint32_t SHT_SYMTAB_VAL = 2;
static constexpr uint32_t SHT_DYNSYM_VAL = 11;

static constexpr uint64_t SHN_UNDEF_VAL = 0;

#pragma pack(push, 1)
struct Elf64_Ehdr_L {
    unsigned char e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
};

struct Elf64_Phdr_L {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
};

struct Elf64_Shdr_L {
    uint32_t sh_name;
    uint32_t sh_type;
    uint64_t sh_flags;
    uint64_t sh_addr;
    uint64_t sh_offset;
    uint64_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint64_t sh_addralign;
    uint64_t sh_entsize;
};

struct Elf64_Sym_L {
    uint32_t st_name;
    unsigned char st_info;
    unsigned char st_other;
    uint16_t st_shndx;
    uint64_t st_value;
    uint64_t st_size;
};
#pragma pack(pop)

// =========================
// 工具函数
// =========================

static void init_console_utf8() {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif
}

static std::string json_escape(const std::string &s) {
    std::ostringstream oss;
    for (unsigned char c : s) {
        switch (c) {
            case '\"': oss << "\\\""; break;
            case '\\': oss << "\\\\"; break;
            case '\b': oss << "\\b"; break;
            case '\f': oss << "\\f"; break;
            case '\n': oss << "\\n"; break;
            case '\r': oss << "\\r"; break;
            case '\t': oss << "\\t"; break;
            default:
                if (c < 0x20) {
                    oss << "\\u"
                        << std::hex << std::setw(4) << std::setfill('0')
                        << (int)c << std::dec;
                } else {
                    oss << c;
                }
        }
    }
    return oss.str();
}

static bool starts_with(const std::string &s, const std::string &prefix) {
    return s.size() >= prefix.size() &&
           std::equal(prefix.begin(), prefix.end(), s.begin());
}

static bool ends_with(const std::string &s, const std::string &suffix) {
    return s.size() >= suffix.size() &&
           std::equal(suffix.rbegin(), suffix.rend(), s.rbegin());
}

static double clamp01(double x) {
    if (x < 0.0) return 0.0;
    if (x > 1.0) return 1.0;
    return x;
}

static double shannon_entropy(const uint8_t *data, size_t size) {
    if (!data || size == 0) return 0.0;
    uint64_t freq[256] = {0};
    for (size_t i = 0; i < size; ++i) freq[data[i]]++;
    double ent = 0.0;
    for (uint64_t f : freq) {
        if (!f) continue;
        double p = (double)f / (double)size;
        ent -= p * std::log2(p);
    }
    return ent;
}

static size_t count_printable_strings(const std::vector<uint8_t> &buf, size_t min_len = 4) {
    size_t count = 0;
    size_t i = 0;
    while (i < buf.size()) {
        size_t j = i;
        while (j < buf.size()) {
            unsigned char c = buf[j];
            if (c >= 0x20 && c <= 0x7e) ++j;
            else break;
        }
        if (j - i >= min_len) count++;
        i = (j == i) ? (i + 1) : (j + 1);
    }
    return count;
}

static std::vector<std::string> extract_printable_strings(const std::vector<uint8_t> &buf,
                                                          size_t min_len = 4,
                                                          size_t max_count = 5000) {
    std::vector<std::string> out;
    size_t i = 0;
    while (i < buf.size() && out.size() < max_count) {
        size_t j = i;
        while (j < buf.size()) {
            unsigned char c = buf[j];
            if (c >= 0x20 && c <= 0x7e) ++j;
            else break;
        }
        if (j - i >= min_len) {
            out.emplace_back(reinterpret_cast<const char *>(&buf[i]), j - i);
        }
        i = (j == i) ? (i + 1) : (j + 1);
    }
    return out;
}

template<typename T>
static bool read_struct(const std::vector<uint8_t> &buf, size_t offset, T &out) {
    if (offset + sizeof(T) > buf.size()) return false;
    std::memcpy(&out, buf.data() + offset, sizeof(T));
    return true;
}

static std::string get_cstr_from_table(const std::vector<uint8_t> &table, uint32_t off) {
    if (off >= table.size()) return "";
    const char *p = reinterpret_cast<const char*>(table.data() + off);
    size_t maxlen = table.size() - off;
    size_t n = 0;
    while (n < maxlen && p[n] != '\0') n++;
    return std::string(p, n);
}

static std::string hex_dump_prefix(const std::vector<uint8_t>& buf, size_t n = 32) {
    std::ostringstream oss;
    size_t m = std::min(n, buf.size());
    for (size_t i = 0; i < m; ++i) {
        if (i) oss << " ";
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)buf[i];
    }
    return oss.str();
}

static bool contains_any_icase(const std::vector<std::string> &hay, const std::vector<std::string> &needles) {
    for (const auto &s : hay) {
        std::string ls = s;
        std::transform(ls.begin(), ls.end(), ls.begin(), [](unsigned char c){ return (char)std::tolower(c); });
        for (const auto &n : needles) {
            if (ls.find(n) != std::string::npos) return true;
        }
    }
    return false;
}

static bool contains_string_icase(const std::vector<std::string> &hay, const std::string &needle) {
    std::string n = needle;
    std::transform(n.begin(), n.end(), n.begin(), [](unsigned char c){ return (char)std::tolower(c); });

    for (const auto &s : hay) {
        std::string ls = s;
        std::transform(ls.begin(), ls.end(), ls.begin(), [](unsigned char c){ return (char)std::tolower(c); });
        if (ls.find(n) != std::string::npos) return true;
    }
    return false;
}

static bool is_zip_magic(const std::vector<uint8_t>& buf) {
    return buf.size() >= 4 &&
           buf[0] == 0x50 &&
           buf[1] == 0x4b &&
           buf[2] == 0x03 &&
           buf[3] == 0x04;
}

static bool is_elf_magic(const std::vector<uint8_t>& buf) {
    return buf.size() >= 4 &&
           buf[0] == 0x7f &&
           buf[1] == 'E' &&
           buf[2] == 'L' &&
           buf[3] == 'F';
}

static bool extract_first_elf_from_zip_buffer(const std::vector<uint8_t>& zip_buf,
                                              std::vector<uint8_t>& out_elf,
                                              std::string& inner_name) {
    mz_zip_archive zip{};
    memset(&zip, 0, sizeof(zip));

    if (!mz_zip_reader_init_mem(&zip, zip_buf.data(), zip_buf.size(), 0)) {
        return false;
    }

    mz_uint file_count = mz_zip_reader_get_num_files(&zip);
    for (mz_uint i = 0; i < file_count; ++i) {
        mz_zip_archive_file_stat st{};
        if (!mz_zip_reader_file_stat(&zip, i, &st)) continue;
        if (st.m_is_directory) continue;

        size_t out_size = 0;
        void* p = mz_zip_reader_extract_to_heap(&zip, i, &out_size, 0);
        if (!p || out_size < 4) {
            if (p) mz_free(p);
            continue;
        }

        std::vector<uint8_t> tmp(out_size);
        memcpy(tmp.data(), p, out_size);
        mz_free(p);

        if (is_elf_magic(tmp)) {
            out_elf = std::move(tmp);
            inner_name = st.m_filename ? st.m_filename : "";
            mz_zip_reader_end(&zip);
            return true;
        }
    }

    mz_zip_reader_end(&zip);
    return false;
}

// =========================
// ELF 分析
// =========================

struct SectionInfo {
    std::string name;
    uint32_t type = 0;
    uint64_t offset = 0;
    uint64_t size = 0;
    uint64_t flags = 0;
    double entropy = 0.0;
};

struct SegmentInfo {
    uint32_t type = 0;
    uint32_t flags = 0;
    uint64_t offset = 0;
    uint64_t vaddr = 0;
    uint64_t filesz = 0;
    uint64_t memsz = 0;
};

struct EntryPreview {
    std::string name;
    uint64_t va = 0;
    uint64_t file_offset = 0;
    std::vector<DisasmLine> lines;
};

struct VmpDeepResult {
    bool analyzed = false;
    bool possible = false;
    double score = 0.0;
    std::vector<std::string> signals;
};

struct AnalysisResult {
    std::string so_name;
    uint64_t file_size = 0;           // 外层条目大小
    uint64_t analyzed_file_size = 0;  // 实际分析对象大小（内层ELF或原始ELF）

    bool valid_elf = false;
    bool is_64 = false;
    bool is_aarch64 = false;
    bool little_endian = false;
    bool stripped = false;
    bool has_symtab = false;
    bool has_dynsym = false;
    bool has_init_array = false;
    bool has_jni_onload_string = false;
    bool rwx_segment = false;

    bool is_zip_container = false;
    bool inner_elf_found = false;
    std::string format_note;

    uint16_t section_count = 0;
    uint16_t ph_count = 0;

    uint64_t text_size = 0;
    uint64_t rodata_size = 0;
    uint64_t data_size = 0;
    uint64_t init_array_offset = 0;
    uint64_t init_array_size = 0;

    double file_entropy = 0.0;
    double max_section_entropy = 0.0;
    double avg_exec_entropy = 0.0;

    size_t printable_string_count = 0;
    size_t import_count = 0;
    size_t exported_dynsym_count = 0;

    std::vector<std::string> imports;
    std::vector<SectionInfo> sections;
    std::vector<SegmentInfo> segments;
    A64StatsEx a64;
    std::vector<DisasmLine> preview_lines;
    std::vector<EntryPreview> entry_previews;
    VmpDeepResult vmp;

    double packer_score = 0.0;
    double ollvm_score = 0.0;
    double strong_obf_score = 0.0;
    std::string final_label;
    std::vector<std::string> reasons;
};

static bool va_to_file_offset(uint64_t va,
                              const std::vector<SegmentInfo>& segments,
                              uint64_t& out_off) {
    for (const auto& seg : segments) {
        if (seg.type != PT_LOAD_VAL) continue;
        uint64_t begin = seg.vaddr;
        uint64_t end = seg.vaddr + seg.filesz;
        if (va >= begin && va < end) {
            out_off = seg.offset + (va - begin);
            return true;
        }
    }
    return false;
}

static void add_entry_preview(AnalysisResult& r,
                              Arm64DisasmEngine& engine,
                              const std::vector<uint8_t>& work_buf,
                              const std::string& name,
                              uint64_t va,
                              size_t max_insn = 12) {
    uint64_t file_off = 0;
    if (!va_to_file_offset(va, r.segments, file_off)) return;
    if (file_off >= work_buf.size()) return;

    size_t remain = work_buf.size() - static_cast<size_t>(file_off);
    size_t preview_size = std::min<size_t>(remain, 96);

    EntryPreview ep;
    ep.name = name;
    ep.va = va;
    ep.file_offset = file_off;
    ep.lines = engine.disasm_preview(work_buf.data() + file_off, preview_size, va, max_insn);

    if (!ep.lines.empty()) {
        r.entry_previews.push_back(std::move(ep));
    }
}





static bool is_high_risk_result(const AnalysisResult& r) {
    return r.packer_score >= 0.70 || r.strong_obf_score >= 0.72;
}

static std::string to_lower_copy(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return (char)std::tolower(c); });
    return s;
}

static std::string trim_copy(const std::string& s) {
    size_t l = 0;
    while (l < s.size() && std::isspace((unsigned char)s[l])) l++;
    size_t r = s.size();
    while (r > l && std::isspace((unsigned char)s[r - 1])) r--;
    return s.substr(l, r - l);
}

static std::string normalize_reg(std::string s) {
    s = trim_copy(to_lower_copy(s));
    while (!s.empty() && (s.back() == ',' || s.back() == ']' || s.back() == '!')) s.pop_back();
    while (!s.empty() && std::isspace((unsigned char)s.back())) s.pop_back();

    if (s == "sp") return s;
    if (s.size() >= 2 && (s[0] == 'x' || s[0] == 'w')) {
        bool ok = true;
        for (size_t i = 1; i < s.size(); ++i) {
            if (!std::isdigit((unsigned char)s[i])) {
                ok = false;
                break;
            }
        }
        if (ok) {
            if (s[0] == 'w') s[0] = 'x';
            return s;
        }
    }
    return "";
}

static std::string extract_operand_reg_at(const std::string& op_str, int index) {
    std::string s = to_lower_copy(op_str);
    int cur = 0;
    size_t i = 0;

    while (i < s.size()) {
        while (i < s.size() && (std::isspace((unsigned char)s[i]) || s[i] == ',')) i++;
        if (i >= s.size()) break;

        size_t j = i;
        int bracket_depth = 0;
        while (j < s.size()) {
            if (s[j] == '[') bracket_depth++;
            else if (s[j] == ']') bracket_depth--;
            else if (s[j] == ',' && bracket_depth == 0) break;
            j++;
        }

        if (cur == index) {
            std::string token = trim_copy(s.substr(i, j - i));
            size_t p = 0;
            while (p < token.size() && token[p] == '[') p++;
            size_t q = p;
            while (q < token.size() && !std::isspace((unsigned char)token[q]) && token[q] != ',' && token[q] != ']') q++;
            return normalize_reg(token.substr(p, q - p));
        }

        cur++;
        i = j + 1;
    }

    return "";
}

static std::string extract_first_operand_reg(const std::string& op_str) {
    return extract_operand_reg_at(op_str, 0);
}

static std::string extract_second_operand_reg(const std::string& op_str) {
    return extract_operand_reg_at(op_str, 1);
}

static std::string extract_branch_target_reg(const std::string& op_str) {
    return extract_first_operand_reg(op_str);
}

static std::string extract_mem_base_reg(const std::string& op_str) {
    std::string s = to_lower_copy(op_str);
    size_t p = s.find('[');
    if (p == std::string::npos) return "";

    p++;
    while (p < s.size() && std::isspace((unsigned char)s[p])) p++;
    if (p >= s.size()) return "";

    if (p + 1 < s.size() && s[p] == 's' && s[p + 1] == 'p') {
        return "sp";
    }

    if (s[p] == 'x' || s[p] == 'w') {
        size_t q = p + 1;
        while (q < s.size() && std::isdigit((unsigned char)s[q])) q++;
        return normalize_reg(s.substr(p, q - p));
    }

    return "";
}

static bool has_post_index_advance(const std::string& op_str, const std::string& base_reg) {
    std::string s = to_lower_copy(op_str);
    std::string needle1 = "[" + base_reg + "], #";
    std::string needle2 = "[" + base_reg + "],#";
    return s.find(needle1) != std::string::npos ||
           s.find(needle2) != std::string::npos;
}

static bool is_add_sub_same_reg(const DisasmInsn& ins, const std::string& reg) {
    if (!(ins.mnemonic == "add" || ins.mnemonic == "sub")) return false;
    std::string d = extract_first_operand_reg(ins.op_str);
    std::string s1 = extract_second_operand_reg(ins.op_str);
    return !reg.empty() && d == reg && s1 == reg;
}

static bool is_small_load_mnemonic(const std::string& m) {
    return m == "ldrb" || m == "ldrh" || m == "ldrsb" || m == "ldrsh";
}

static bool is_load_mnemonic(const std::string& m) {
    return starts_with(m, "ldr") || m == "ldp" || m == "ldur";
}

static bool is_logic_shift_mnemonic(const std::string& m) {
    return m == "add" || m == "sub" || m == "subs" ||
           m == "eor" || m == "and" || m == "ands" || m == "orr" ||
           m == "lsl" || m == "lsr" || m == "asr" ||
           m == "ubfx" || m == "sbfx" || m == "extr" ||
           m == "cmp" || m == "cmn" || m == "tst";
}

static bool is_adr_base_mnemonic(const std::string& m) {
    return m == "adr" || m == "adrp";
}

static bool has_large_entropy_blob_for_vmp(const AnalysisResult& r) {
    for (const auto& sec : r.sections) {
        if (sec.size >= 32 * 1024 &&
            sec.entropy >= 7.2 &&
            sec.name != ".text" &&
            sec.name != ".plt") {
            return true;
        }
    }
    return false;
}

struct VmWindowMatch {
    bool strict = false;
    bool medium = false;
    std::string vip_reg;
    std::string br_reg;
};

static VmWindowMatch match_vm_window_strict(const std::vector<DisasmInsn>& insns,
                                            size_t begin,
                                            size_t len) {
    VmWindowMatch wm{};
    if (begin + len > insns.size()) return wm;

    bool has_fetch = false;
    bool has_advance = false;
    bool has_br = false;
    int logic_count = 0;
    size_t br_pos = (size_t)-1;

    std::string vip_reg;
    std::string br_reg;

    for (size_t i = begin; i < begin + len; ++i) {
        const auto& ins = insns[i];
        const std::string& m = ins.mnemonic;

        if (is_small_load_mnemonic(m)) {
            std::string base = extract_mem_base_reg(ins.op_str);
            if (!base.empty()) {
                has_fetch = true;
                if (vip_reg.empty()) vip_reg = base;
                if (has_post_index_advance(ins.op_str, base)) {
                    has_advance = true;
                }
            }
        }

        if (!vip_reg.empty() && is_add_sub_same_reg(ins, vip_reg)) {
            has_advance = true;
        }

        if (m == "br") {
            has_br = true;
            br_pos = i - begin;
            br_reg = extract_branch_target_reg(ins.op_str);
        }

        if (is_logic_shift_mnemonic(m)) {
            logic_count++;
        }
    }

    bool br_at_tail = (br_pos != (size_t)-1 && br_pos >= len - 4);

    wm.medium = has_fetch && has_br && logic_count >= 1 && !vip_reg.empty() && !br_reg.empty();
    wm.strict = has_fetch && has_advance && has_br && logic_count >= 2 &&
                br_at_tail && !vip_reg.empty() && !br_reg.empty();
    wm.vip_reg = vip_reg;
    wm.br_reg = br_reg;
    return wm;
}

static VmpDeepResult analyze_vmp_deep(const AnalysisResult& base,
                                      const std::vector<uint8_t>& work_buf,
                                      const uint8_t* text_ptr,
                                      size_t text_size,
                                      uint64_t text_base_addr) {
    VmpDeepResult vr;
    vr.analyzed = true;

    if (!text_ptr || text_size < 128) {
        return vr;
    }

    Arm64DisasmEngine engine;
    if (!engine.init()) {
        vr.signals.push_back("Capstone深度反汇编初始化失败");
        return vr;
    }

    size_t scan_bytes = std::min<size_t>(text_size, 256 * 1024);
    auto insns = engine.disasm_all(text_ptr, scan_bytes, text_base_addr, 0);
    if (insns.size() < 96) {
        return vr;
    }

    size_t br_count = 0;
    size_t blr_count = 0;
    size_t small_load_count = 0;
    size_t logic_shift_count = 0;

    std::unordered_map<std::string, int> br_reg_freq;
    std::unordered_map<std::string, int> strict_vip_freq;
    std::unordered_map<std::string, int> strict_br_freq;

    for (const auto& ins : insns) {
        const std::string& m = ins.mnemonic;
        if (m == "br") {
            br_count++;
            std::string r = extract_branch_target_reg(ins.op_str);
            if (!r.empty()) br_reg_freq[r]++;
        } else if (m == "blr") {
            blr_count++;
        }

        if (is_small_load_mnemonic(m)) small_load_count++;
        if (is_logic_shift_mnemonic(m)) logic_shift_count++;
    }

    int strict_windows = 0;
    int medium_windows = 0;

    const size_t W = 12;
    for (size_t i = 0; i + W <= insns.size(); ++i) {
        VmWindowMatch wm = match_vm_window_strict(insns, i, W);
        if (wm.medium) medium_windows++;
        if (wm.strict) {
            strict_windows++;
            strict_vip_freq[wm.vip_reg]++;
            strict_br_freq[wm.br_reg]++;
        }
    }

    int max_same_vip = 0;
    for (const auto& kv : strict_vip_freq) {
        if (kv.second > max_same_vip) max_same_vip = kv.second;
    }

    int max_same_br = 0;
    for (const auto& kv : strict_br_freq) {
        if (kv.second > max_same_br) max_same_br = kv.second;
    }

    double br_density = insns.empty() ? 0.0 : double(br_count) / double(insns.size());
    double blr_density = insns.empty() ? 0.0 : double(blr_count) / double(insns.size());
    double small_load_ratio = insns.empty() ? 0.0 : double(small_load_count) / double(insns.size());
    double logic_ratio = insns.empty() ? 0.0 : double(logic_shift_count) / double(insns.size());

    double score = 0.0;

    if (strict_windows >= 5) {
        score += 0.40;
        vr.signals.push_back("重复出现高置信度取字节码-推进VIP-br分发窗口");
    } else if (strict_windows >= 3) {
        score += 0.25;
        vr.signals.push_back("出现多处高置信度取字节码-br分发窗口");
    }

    if (max_same_vip >= 4) {
        score += 0.18;
        vr.signals.push_back("同一VIP寄存器重复出现");
    } else if (max_same_vip >= 3) {
        score += 0.10;
        vr.signals.push_back("疑似VIP寄存器重复出现");
    }

    if (max_same_br >= 4) {
        score += 0.16;
        vr.signals.push_back("同一br目标寄存器重复作为分发出口");
    } else if (max_same_br >= 3) {
        score += 0.10;
        vr.signals.push_back("疑似固定分发寄存器");
    }

    if (br_count >= 8 && br_density >= 0.004) {
        score += 0.10;
        vr.signals.push_back("br分发指令数量偏高");
    } else if (br_count >= 5 && br_density >= 0.0025) {
        score += 0.05;
        vr.signals.push_back("存在一定数量的br分发指令");
    }

    if (medium_windows >= 10) {
        score += 0.08;
        vr.signals.push_back("中等置信度解释器窗口较多");
    }

    if (has_large_entropy_blob_for_vmp(base)) {
        score += 0.05;
        vr.signals.push_back("存在较大高熵疑似字节码/handler数据区");
    }

    if (small_load_ratio >= 0.03) {
        score += 0.04;
        vr.signals.push_back("字节/半字读取比例偏高");
    }

    if (logic_ratio >= 0.10) {
        score += 0.04;
        vr.signals.push_back("位运算/比较密度偏高");
    }

    if (base.import_count <= 8 && base.has_init_array) {
        score += 0.03;
        vr.signals.push_back("导入较少且存在早期初始化入口");
    }

    // 强力反误报：如果 blr 明显多于 br，更像虚表/函数指针调用，不像 dispatcher
    if (blr_count > br_count * 2 && br_count < 8) {
        score -= 0.20;
        vr.signals.push_back("blr占优，更像虚表/函数指针调用");
    }

    // 另一个反误报：没有 strict window 基本不认 VMP
    if (strict_windows == 0) {
        score -= 0.20;
    }

    vr.score = clamp01(score);

    vr.possible =
        (vr.score >= 0.72) &&
        (strict_windows >= 3) &&
        (max_same_vip >= 3) &&
        (max_same_br >= 3) &&
        (br_count >= 5);

    return vr;
}



static AnalysisResult analyze_so(const std::string &name, const std::vector<uint8_t> &input_buf) {
    AnalysisResult r;
    r.so_name = name;
    r.file_size = input_buf.size();

    std::vector<uint8_t> work_buf = input_buf;

    if (is_zip_magic(work_buf)) {
        r.is_zip_container = true;
        r.format_note = "ZIP伪装SO";

        std::vector<uint8_t> inner_elf;
        std::string inner_name;
        if (extract_first_elf_from_zip_buffer(work_buf, inner_elf, inner_name)) {
            r.inner_elf_found = true;
            r.format_note = "ZIP伪装SO，已提取内层ELF";
            r.reasons.push_back("so entry is actually a zip container");
            work_buf = std::move(inner_elf);
        } else {
            r.final_label = "ZIP_SO_CONTAINER";
            r.reasons.push_back("so entry is actually a zip container");
            return r;
        }
    }

    r.analyzed_file_size = work_buf.size();
    r.file_entropy = shannon_entropy(work_buf.data(), work_buf.size());
    r.printable_string_count = count_printable_strings(work_buf, 4);

    auto all_strings = extract_printable_strings(work_buf, 4, 6000);
    r.has_jni_onload_string = contains_string_icase(all_strings, "JNI_OnLoad");

    if (work_buf.size() < sizeof(Elf64_Ehdr_L)) {
        r.final_label = "INVALID_ELF";
        return r;
    }

    Elf64_Ehdr_L eh{};
    if (!read_struct(work_buf, 0, eh)) {
        r.final_label = "INVALID_ELF";
        return r;
    }

    if (!(eh.e_ident[0] == 0x7f &&
          eh.e_ident[1] == 'E' &&
          eh.e_ident[2] == 'L' &&
          eh.e_ident[3] == 'F')) {
        std::cerr << "[INVALID_ELF] " << name
                  << " size=" << work_buf.size()
                  << " prefix=" << hex_dump_prefix(work_buf, 32)
                  << "\n";
        r.final_label = "INVALID_ELF";
        return r;
    }

    r.valid_elf = true;
    r.is_64 = (eh.e_ident[4] == ELFCLASS64_VAL);
    r.little_endian = (eh.e_ident[5] == ELFDATA2LSB_VAL);
    r.is_aarch64 = (eh.e_machine == EM_AARCH64_VAL);
    r.section_count = eh.e_shnum;
    r.ph_count = eh.e_phnum;

    if (!r.is_64 || !r.little_endian || !r.is_aarch64) {
        r.final_label = "UNSUPPORTED_OR_NOT_AARCH64";
        return r;
    }

    std::vector<Elf64_Shdr_L> shdrs;
    shdrs.reserve(eh.e_shnum);

    for (uint16_t i = 0; i < eh.e_shnum; ++i) {
        Elf64_Shdr_L sh{};
        size_t off = static_cast<size_t>(eh.e_shoff) + static_cast<size_t>(i) * eh.e_shentsize;
        if (!read_struct(work_buf, off, sh)) break;
        shdrs.push_back(sh);
    }

    std::vector<uint8_t> shstrtab;
    if (eh.e_shstrndx < shdrs.size()) {
        const auto &shstr = shdrs[eh.e_shstrndx];
        if (shstr.sh_offset + shstr.sh_size <= work_buf.size()) {
            shstrtab.assign(work_buf.begin() + shstr.sh_offset,
                            work_buf.begin() + shstr.sh_offset + shstr.sh_size);
        }
    }

    std::vector<std::string> section_names;
    section_names.reserve(shdrs.size());

    for (const auto &sh : shdrs) {
        SectionInfo si;
        si.name = get_cstr_from_table(shstrtab, sh.sh_name);
        si.type = sh.sh_type;
        si.offset = sh.sh_offset;
        si.size = sh.sh_size;
        si.flags = sh.sh_flags;

        if (si.offset + si.size <= work_buf.size() && si.size > 0) {
            si.entropy = shannon_entropy(work_buf.data() + si.offset, static_cast<size_t>(si.size));
            r.max_section_entropy = std::max(r.max_section_entropy, si.entropy);
        }

        section_names.push_back(si.name);
        r.sections.push_back(si);

        if (si.name == ".text") r.text_size = si.size;
        else if (si.name == ".rodata") r.rodata_size = si.size;
        else if (si.name == ".data") r.data_size = si.size;

        if (sh.sh_type == SHT_SYMTAB_VAL) r.has_symtab = true;
        if (sh.sh_type == SHT_DYNSYM_VAL) r.has_dynsym = true;
        if (si.name == ".init_array") {
            r.has_init_array = true;
            r.init_array_offset = si.offset;
            r.init_array_size = si.size;
        }
    }

    r.stripped = !r.has_symtab;

    uint64_t exec_entropy_count = 0;
    double exec_entropy_sum = 0.0;

    for (uint16_t i = 0; i < eh.e_phnum; ++i) {
        Elf64_Phdr_L ph{};
        size_t off = static_cast<size_t>(eh.e_phoff) + static_cast<size_t>(i) * eh.e_phentsize;
        if (!read_struct(work_buf, off, ph)) break;

        SegmentInfo sg;
        sg.type = ph.p_type;
        sg.flags = ph.p_flags;
        sg.offset = ph.p_offset;
        sg.vaddr = ph.p_vaddr;
        sg.filesz = ph.p_filesz;
        sg.memsz = ph.p_memsz;
        r.segments.push_back(sg);

        if (ph.p_type == PT_LOAD_VAL &&
            (ph.p_flags & (PF_R_VAL | PF_W_VAL | PF_X_VAL)) == (PF_R_VAL | PF_W_VAL | PF_X_VAL)) {
            r.rwx_segment = true;
        }

        if (ph.p_type == PT_LOAD_VAL &&
            (ph.p_flags & PF_X_VAL) &&
            ph.p_offset + ph.p_filesz <= work_buf.size() &&
            ph.p_filesz > 0) {
            double e = shannon_entropy(work_buf.data() + ph.p_offset, static_cast<size_t>(ph.p_filesz));
            exec_entropy_sum += e;
            exec_entropy_count++;
        }
    }

    if (exec_entropy_count > 0) {
        r.avg_exec_entropy = exec_entropy_sum / double(exec_entropy_count);
    }

    std::vector<uint8_t> dynstr;
    std::vector<Elf64_Sym_L> dynsyms;
    std::vector<std::pair<std::string, uint64_t>> exported_funcs;

    for (size_t i = 0; i < shdrs.size(); ++i) {
        const auto &sh = shdrs[i];
        std::string sec_name = (i < r.sections.size() ? r.sections[i].name : "");

        if (sec_name == ".dynstr" && sh.sh_offset + sh.sh_size <= work_buf.size()) {
            dynstr.assign(work_buf.begin() + sh.sh_offset,
                          work_buf.begin() + sh.sh_offset + sh.sh_size);
        }

        if (sh.sh_type == SHT_DYNSYM_VAL &&
            sh.sh_entsize == sizeof(Elf64_Sym_L) &&
            sh.sh_offset + sh.sh_size <= work_buf.size()) {
            size_t cnt = static_cast<size_t>(sh.sh_size / sh.sh_entsize);
            dynsyms.resize(cnt);
            std::memcpy(dynsyms.data(),
                        work_buf.data() + sh.sh_offset,
                        cnt * sizeof(Elf64_Sym_L));
        }
    }

    for (const auto &sym : dynsyms) {
        std::string sname = get_cstr_from_table(dynstr, sym.st_name);
        if (sname.empty()) continue;

        if (sym.st_shndx == SHN_UNDEF_VAL) {
            r.imports.push_back(sname);
        } else {
            r.exported_dynsym_count++;

            if (sym.st_value != 0) {
                if (sname == "JNI_OnLoad" ||
                    sname.rfind("Java_", 0) == 0 ||
                    sname.find("init") != std::string::npos ||
                    sname.find("Init") != std::string::npos ||
                    sname.find("load") != std::string::npos ||
                    sname.find("Load") != std::string::npos ||
                    sname.find("register") != std::string::npos ||
                    sname.find("Register") != std::string::npos) {
                    exported_funcs.push_back({sname, sym.st_value});
                }
            }
        }
    }
    r.import_count = r.imports.size();

    const uint8_t *text_ptr = nullptr;
    size_t text_size = 0;
    uint64_t text_base_addr = 0;

    for (const auto &sec : r.sections) {
        if (sec.name == ".text" &&
            sec.offset + sec.size <= work_buf.size() &&
            sec.size >= 4) {
            text_ptr = work_buf.data() + sec.offset;
            text_size = static_cast<size_t>(sec.size);
            text_base_addr = 0;
            break;
        }
    }

    if (!text_ptr) {
        for (const auto &seg : r.segments) {
            if (seg.type == PT_LOAD_VAL &&
                (seg.flags & PF_X_VAL) &&
                seg.offset + seg.filesz <= work_buf.size() &&
                seg.filesz >= 4) {
                text_ptr = work_buf.data() + seg.offset;
                text_size = static_cast<size_t>(seg.filesz);
                text_base_addr = seg.vaddr;
                break;
            }
        }
    }

    if (text_ptr && text_size >= 4) {
        Arm64DisasmEngine engine;
        if (engine.init()) {
            r.a64 = engine.analyze_text(text_ptr, text_size, text_base_addr);
            r.preview_lines = engine.disasm_preview(text_ptr, text_size, text_base_addr, 16);

            if (eh.e_entry != 0) {
                add_entry_preview(r, engine, work_buf, "ELF入口", eh.e_entry, 12);
            }

            if (r.has_init_array &&
                r.init_array_offset < work_buf.size() &&
                r.init_array_size >= 8 &&
                r.init_array_offset + r.init_array_size <= work_buf.size()) {

                size_t cnt = static_cast<size_t>(r.init_array_size / 8);
                size_t limit = std::min<size_t>(cnt, 8);

                for (size_t i = 0; i < limit; ++i) {
                    uint64_t fn_va = 0;
                    std::memcpy(&fn_va, work_buf.data() + r.init_array_offset + i * 8, 8);
                    if (fn_va != 0) {
                        add_entry_preview(r, engine, work_buf,
                                          ".init_array[" + std::to_string(i) + "]",
                                          fn_va, 12);
                    }
                }
            }

            size_t export_limit = std::min<size_t>(exported_funcs.size(), 8);
            for (size_t i = 0; i < export_limit; ++i) {
                add_entry_preview(r, engine, work_buf,
                                  exported_funcs[i].first,
                                  exported_funcs[i].second,
                                  12);
            }
        } else {
            r.reasons.push_back("capstone init failed");
        }
    }

    static const std::unordered_set<std::string> suspicious_loader_imports = {
        "dlopen", "android_dlopen_ext", "dlsym",
        "mmap", "mprotect", "munmap",
        "memcpy", "memmove", "memset",
        "pthread_create", "ptrace",
        "open", "openat", "read", "pread64", "fstat", "lseek",
        "syscall", "__system_property_get", "sigaction", "sigprocmask"
    };

    size_t loader_hit = 0;
    for (const auto &imp : r.imports) {
        if (suspicious_loader_imports.count(imp)) loader_hit++;
    }

    double low_string_density = 0.0;
    if (!work_buf.empty()) {
        double density = double(r.printable_string_count) /
                         double(std::max<size_t>(1, work_buf.size() / 1024));
        if (density < 1.5) low_string_density = 1.0;
        else if (density < 3.0) low_string_density = 0.5;
    }

    double huge_entropy_blob = 0.0;
    for (const auto &sec : r.sections) {
        if (sec.size >= 64 * 1024 &&
            sec.entropy >= 7.4 &&
            sec.name != ".text" &&
            sec.name != ".plt") {
            huge_entropy_blob = 1.0;
            break;
        }
    }

    double abnormal_sections = 0.0;
    if (r.section_count <= 6) abnormal_sections += 0.5;
    if (!r.has_symtab) abnormal_sections += 0.3;
    if (!r.has_dynsym) abnormal_sections += 0.4;

    double tiny_text_big_file = 0.0;
    if (r.text_size > 0 && r.analyzed_file_size > 256 * 1024 && r.text_size < 32 * 1024) {
        tiny_text_big_file = 1.0;
    }

    double suspicious_section_name = 0.0;
    static const std::vector<std::string> sec_needles = {
        "ollvm", "obf", "vmp", "vm", "protect", "guard", "shell", "stub"
    };
    if (contains_any_icase(section_names, sec_needles)) suspicious_section_name = 1.0;

    r.packer_score =
        std::min(0.45, loader_hit * 0.08) +
        (r.rwx_segment ? 0.20 : 0.0) +
        (r.has_init_array ? 0.08 : 0.0) +
        (r.has_jni_onload_string ? 0.05 : 0.0) +
        (huge_entropy_blob * 0.22) +
        (tiny_text_big_file * 0.18) +
        (low_string_density * 0.08);

    r.packer_score = clamp01(r.packer_score);

    double branch_ratio = r.a64.branch_ratio();
    double indirect_branch_ratio = r.a64.indirect_branch_ratio();
    double obf_arith_ratio = r.a64.obf_arith_ratio();

    double branch_suspicion = 0.0;
    if (branch_ratio > 0.18) branch_suspicion += 0.20;
    else if (branch_ratio > 0.12) branch_suspicion += 0.10;

    if (indirect_branch_ratio > 0.015) branch_suspicion += 0.20;
    else if (indirect_branch_ratio > 0.008) branch_suspicion += 0.10;

    double arith_suspicion = 0.0;
    if (obf_arith_ratio > 0.28) arith_suspicion += 0.20;
    else if (obf_arith_ratio > 0.20) arith_suspicion += 0.10;

    r.ollvm_score =
        branch_suspicion +
        arith_suspicion +
        (low_string_density * 0.10) +
        (r.stripped ? 0.10 : 0.0) +
        (suspicious_section_name * 0.15) +
        ((r.avg_exec_entropy > 6.8) ? 0.12 : 0.0);

    r.ollvm_score = clamp01(r.ollvm_score);

    r.strong_obf_score =
        clamp01(
            r.packer_score * 0.55 +
            r.ollvm_score * 0.65 +
            abnormal_sections * 0.20 +
            ((r.max_section_entropy > 7.5) ? 0.10 : 0.0)
        );

    if (r.stripped) r.reasons.push_back("missing .symtab / stripped");
    if (r.rwx_segment) r.reasons.push_back("found RWX PT_LOAD segment");
    if (loader_hit > 0) r.reasons.push_back("suspicious loader imports hit=" + std::to_string(loader_hit));
    if (huge_entropy_blob > 0.5) r.reasons.push_back("large high-entropy blob detected");
    if (tiny_text_big_file > 0.5) r.reasons.push_back("tiny .text but large file");
    if (low_string_density > 0.5) r.reasons.push_back("very low printable string density");
    if (r.avg_exec_entropy > 6.8) r.reasons.push_back("high executable segment entropy");
    if (branch_ratio > 0.18) r.reasons.push_back("high branch density in AArch64 text");
    if (indirect_branch_ratio > 0.015) r.reasons.push_back("high indirect branch density");
    if (obf_arith_ratio > 0.28) r.reasons.push_back("high arithmetic/logical opcode density");

    if (r.packer_score >= 0.70) {
        r.final_label = "POSSIBLE_PACKER";
    } else if (r.strong_obf_score >= 0.72 && r.ollvm_score >= 0.55) {
        r.final_label = "POSSIBLE_OLLVM_OR_STRONG_OBF";
    } else if (r.strong_obf_score >= 0.70) {
        r.final_label = "STRONG_OBFUSCATION";
    } else if (r.ollvm_score >= 0.60) {
        r.final_label = "POSSIBLE_OLLVM";
    } else {
        r.final_label = "NORMAL_OR_LIGHT_OBF";
    }
    if (is_high_risk_result(r) && text_ptr && text_size >= 128) {
        r.vmp = analyze_vmp_deep(r, work_buf, text_ptr, text_size, text_base_addr);
        if (r.vmp.possible) {
            r.reasons.push_back("possible vmp dispatcher/handler loop");
        }
    }
    return r;
}

// =========================
// APK 读取
// =========================

struct ApkSoEntry {
    std::string name_in_apk;
    std::vector<uint8_t> data;
};

static std::vector<ApkSoEntry> load_arm64_sos_from_apk(const std::string &apk_path) {
    std::vector<ApkSoEntry> out;

    mz_zip_archive zip{};
    if (!mz_zip_reader_init_file(&zip, apk_path.c_str(), 0)) {
        std::cerr << "[-] open apk failed: " << apk_path << "\n";
        return out;
    }

    mz_uint file_count = mz_zip_reader_get_num_files(&zip);
    for (mz_uint i = 0; i < file_count; ++i) {
        mz_zip_archive_file_stat st{};
        if (!mz_zip_reader_file_stat(&zip, i, &st)) continue;
        if (st.m_is_directory) continue;

        std::string name = st.m_filename ? st.m_filename : "";
        if (!starts_with(name, "lib/arm64-v8a/")) continue;
        if (!ends_with(name, ".so")) continue;

        size_t out_size = 0;
        void *p = mz_zip_reader_extract_to_heap(&zip, i, &out_size, 0);
        if (!p || out_size == 0) continue;

        ApkSoEntry e;
        e.name_in_apk = name;
        e.data.resize(out_size);
        std::memcpy(e.data.data(), p, out_size);
        mz_free(p);

        out.emplace_back(std::move(e));
    }

    mz_zip_reader_end(&zip);
    return out;
}

// =========================
// 输出
// =========================

static void print_usage(const char *prog) {
    std::cout << "用法:\n";
    std::cout << "  " << prog << " <apk_path>\n\n";
    std::cout << "示例:\n";
    std::cout << "  " << prog << " demo.apk\n";
}

static std::string label_to_zh(const std::string &label) {
    if (label == "POSSIBLE_PACKER") return "疑似加壳";
    if (label == "POSSIBLE_OLLVM_OR_STRONG_OBF") return "疑似强混淆/OLLVM";
    if (label == "STRONG_OBFUSCATION") return "疑似强混淆";
    if (label == "POSSIBLE_OLLVM") return "疑似 OLLVM";
    if (label == "NORMAL_OR_LIGHT_OBF") return "正常或轻度混淆";
    if (label == "INVALID_ELF") return "文件头不是标准ELF";
    if (label == "UNSUPPORTED_OR_NOT_AARCH64") return "不是 64 位 ARM so";
    if (label == "ZIP_SO_CONTAINER") return "SO容器文件";
    return "未知";
}

static std::string risk_level_zh(const AnalysisResult &r) {
    if (r.packer_score >= 0.70 || r.strong_obf_score >= 0.72) return "高";
    if (r.ollvm_score >= 0.50 || r.strong_obf_score >= 0.50) return "中";
    return "低";
}

static std::string reason_to_zh(const std::string &reason) {
    if (reason == "missing .symtab / stripped") return "已裁剪符号表";
    if (reason == "found RWX PT_LOAD segment") return "发现可读可写可执行段";
    if (reason == "large high-entropy blob detected") return "存在大块高熵数据";
    if (reason == "tiny .text but large file") return "代码段很小但文件较大";
    if (reason == "very low printable string density") return "可见字符串很少";
    if (reason == "high executable segment entropy") return "可执行段熵较高";
    if (reason == "high branch density in AArch64 text") return "分支跳转密度高";
    if (reason == "high indirect branch density") return "间接跳转偏多";
    if (reason == "high arithmetic/logical opcode density") return "算术逻辑指令密度高";
    if (reason == "so entry is actually a zip container") return "该SO条目实际是ZIP容器";
    if (reason == "capstone init failed") return "Capstone 初始化失败";

    if (reason.rfind("suspicious loader imports hit=", 0) == 0) {
        return "存在较多可疑加载器导入函数";
    }
    if (reason == "possible vmp dispatcher/handler loop") return "存在疑似VMP分发器/handler循环";
    return reason;
}

static std::string build_summary_zh(const AnalysisResult &r) {
    if (r.final_label == "ZIP_SO_CONTAINER") {
        return "该 so 文件在 APK 中并不是裸 ELF，而是一个 ZIP 容器，真实的 native 库可能位于其内层或运行时再释放。";
    }
    if (r.is_zip_container && r.inner_elf_found && r.final_label == "NORMAL_OR_LIGHT_OBF") {
        return "该 so 在 APK 中是 ZIP 容器，已自动提取内层 ELF 进行分析，当前看更像正常发布版本或轻度混淆。";
    }
    if (r.is_zip_container && r.inner_elf_found) {
        return "该 so 在 APK 中是 ZIP 容器，已自动提取内层 ELF 进行分析，内层样本存在明显保护或混淆特征。";
    }
    if (r.final_label == "POSSIBLE_PACKER") {
        return "该 so 存在较明显的壳或加载器特征，静态上看像是经过了解密装载或入口保护处理。";
    }
    if (r.final_label == "POSSIBLE_OLLVM_OR_STRONG_OBF") {
        return "该 so 存在较明显的强混淆特征，可能使用了 OLLVM、控制流平坦化或其他高强度保护。";
    }
    if (r.final_label == "STRONG_OBFUSCATION") {
        return "该 so 存在明显混淆痕迹，但暂时无法仅凭静态特征确认具体保护类型。";
    }
    if (r.final_label == "POSSIBLE_OLLVM") {
        return "该 so 的控制流和指令分布存在一定异常，疑似使用了 OLLVM 类混淆。";
    }
    if (r.final_label == "NORMAL_OR_LIGHT_OBF") {
        return "该 so 整体看更像正常发布版本或仅做了轻度混淆，暂未发现特别强的壳或重度保护迹象。";
    }
    if (r.final_label == "INVALID_ELF") {
        return "当前读取到的文件头不是标准 ELF。";
    }
    if (r.final_label == "UNSUPPORTED_OR_NOT_AARCH64") {
        return "该文件不是目标 64 位 ARM so。";
    }
    return "该 so 已完成静态特征分析。";
}

static std::string build_advice_zh(const AnalysisResult &r) {
    if (r.vmp.possible) {
        return "建议重点查看入口函数、dispatcher循环、handler表、字节码数据区及间接跳转链路。";
    }
    if (r.final_label == "POSSIBLE_PACKER") {
        return "建议人工重点查看 init_array、JNI_OnLoad、mprotect/mmap/dlopen 相关逻辑。";
    }
    if (r.final_label == "POSSIBLE_OLLVM_OR_STRONG_OBF" || r.final_label == "POSSIBLE_OLLVM") {
        return "建议结合反汇编和 CFG 进一步确认是否存在控制流平坦化、不透明谓词或指令替换。";
    }
    if (r.final_label == "STRONG_OBFUSCATION") {
        return "建议进一步查看入口函数、关键导出函数和可疑高熵区域。";
    }
    if (r.final_label == "ZIP_SO_CONTAINER") {
        return "建议继续分析内层资源或运行时释放出来的真实 so。";
    }
    return "可暂不作为高优先级样本，必要时再人工复查。";
}

static std::string join_preview_lines(const std::vector<DisasmLine>& lines, size_t max_lines = 3) {
    std::ostringstream oss;
    size_t n = std::min(lines.size(), max_lines);
    for (size_t i = 0; i < n; ++i) {
        if (i) oss << " | ";
        oss << lines[i].mnemonic;
        if (!lines[i].op_str.empty()) {
            oss << " " << lines[i].op_str;
        }
    }
    return oss.str();
}

struct SummaryStats {
    int total = 0;
    int high = 0;
    int medium = 0;
    int low = 0;
    int zip_so_container = 0;
    int inner_elf_extracted = 0;
};

static SummaryStats build_summary_stats(const std::vector<AnalysisResult> &results) {
    SummaryStats s;
    s.total = static_cast<int>(results.size());

    for (const auto &r : results) {
        std::string level = risk_level_zh(r);
        if (level == "高") s.high++;
        else if (level == "中") s.medium++;
        else s.low++;

        if (r.is_zip_container) s.zip_so_container++;
        if (r.inner_elf_found) s.inner_elf_extracted++;
    }
    return s;
}

static void print_all_results_json_cn(const std::vector<AnalysisResult> &results, bool pretty = true) {
    const char *indent1 = pretty ? "  " : "";
    const char *indent2 = pretty ? "    " : "";
    const char *indent3 = pretty ? "      " : "";
    const char *nl = pretty ? "\n" : "";

    SummaryStats stats = build_summary_stats(results);

    std::cout << "{" << nl;

    std::cout << indent1 << "\"汇总\": {" << nl;
    std::cout << indent2 << "\"总so数量\": " << stats.total << "," << nl;
    std::cout << indent2 << "\"高风险\": " << stats.high << "," << nl;
    std::cout << indent2 << "\"中风险\": " << stats.medium << "," << nl;
    std::cout << indent2 << "\"低风险\": " << stats.low << "," << nl;
    std::cout << indent2 << "\"容器SO数量\": " << stats.zip_so_container << "," << nl;
    std::cout << indent2 << "\"内层ELF成功提取数量\": " << stats.inner_elf_extracted << nl;
    std::cout << indent1 << "}," << nl;

    std::cout << indent1 << "\"结果\": [" << nl;
    for (size_t i = 0; i < results.size(); ++i) {
        const auto &r = results[i];
        std::vector<std::string> zh_reasons;
        for (const auto &reason : r.reasons) {
            zh_reasons.push_back(reason_to_zh(reason));
        }

        std::cout << indent2 << "{" << nl;
        std::cout << indent3 << "\"so文件\": \"" << json_escape(r.so_name) << "\"," << nl;
        std::cout << indent3 << "\"检测结果\": \"" << json_escape(label_to_zh(r.final_label)) << "\"," << nl;
        std::cout << indent3 << "\"风险等级\": \"" << json_escape(risk_level_zh(r)) << "\"," << nl;
        std::cout << indent3 << "\"说明\": \"" << json_escape(build_summary_zh(r)) << "\"," << nl;

        if (r.is_zip_container) {
            std::cout << indent3 << "\"容器特征\": \"" << json_escape(r.format_note) << "\"," << nl;
        }

        std::cout << indent3 << "\"可疑点\": [" << nl;
        for (size_t j = 0; j < zh_reasons.size(); ++j) {
            std::cout << indent3 << "  \"" << json_escape(zh_reasons[j]) << "\"";
            if (j + 1 != zh_reasons.size()) std::cout << ",";
            std::cout << nl;
        }
        std::cout << indent3 << "]," << nl;

        if (!r.entry_previews.empty() && risk_level_zh(r) == "高") {
            std::cout << indent3 << "\"入口预览\": [" << nl;
            size_t limit = std::min<size_t>(r.entry_previews.size(), 4);
            for (size_t k = 0; k < limit; ++k) {
                const auto& ep = r.entry_previews[k];
                std::cout << indent3 << "  {" << nl;
                std::cout << indent3 << "    \"名称\": \"" << json_escape(ep.name) << "\"," << nl;
                std::cout << indent3 << "    \"地址\": \"0x" << std::hex << ep.va << std::dec << "\"," << nl;
                std::cout << indent3 << "    \"预览\": \"" << json_escape(join_preview_lines(ep.lines, 3)) << "\"" << nl;
                std::cout << indent3 << "  }";
                if (k + 1 != limit) std::cout << ",";
                std::cout << nl;
            }
            std::cout << indent3 << "]," << nl;
        }

        if (r.vmp.analyzed && risk_level_zh(r) == "高") {
            std::cout << indent3 << "\"VMP判断\": \""
                      << json_escape(r.vmp.possible ? "疑似VMP保护" : "未见明显VMP特征")
                      << "\"," << nl;

            std::cout << indent3 << "\"VMP分数\": "
                      << std::fixed << std::setprecision(4) << r.vmp.score << "," << nl;

            if (r.vmp.possible) {
                std::cout << indent3 << "\"VMP特征\": [" << nl;
                for (size_t t = 0; t < r.vmp.signals.size(); ++t) {
                    std::cout << indent3 << "  \"" << json_escape(r.vmp.signals[t]) << "\"";
                    if (t + 1 != r.vmp.signals.size()) std::cout << ",";
                    std::cout << nl;
                }
                std::cout << indent3 << "]," << nl;
            }
        }

        std::cout << indent3 << "\"建议\": \"" << json_escape(build_advice_zh(r)) << "\"" << nl;
        std::cout << indent2 << "}";

        if (i + 1 != results.size()) std::cout << ",";
        std::cout << nl;
    }
    std::cout << indent1 << "]" << nl;
    std::cout << "}" << nl;
}

// =========================
// 排序
// =========================

static int risk_rank(const AnalysisResult& r) {
    std::string level = risk_level_zh(r);
    if (level == "高") return 3;
    if (level == "中") return 2;
    return 1;
}

static double combined_score(const AnalysisResult& r) {
    return r.packer_score * 1.2 +
           r.strong_obf_score * 1.0 +
           r.ollvm_score * 0.9 +
           r.vmp.score * 0.35 +
           (r.vmp.possible ? 0.12 : 0.0);
}

static void sort_results_by_risk(std::vector<AnalysisResult>& results) {
    std::stable_sort(results.begin(), results.end(),
        [](const AnalysisResult& a, const AnalysisResult& b) {
            int ra = risk_rank(a);
            int rb = risk_rank(b);
            if (ra != rb) return ra > rb;

            double sa = combined_score(a);
            double sb = combined_score(b);
            if (sa != sb) return sa > sb;

            return a.so_name < b.so_name;
        });
}

// =========================
// main
// =========================

int main(int argc, char *argv[]) {
    init_console_utf8();

    std::string apk_path;
    if (argc >= 2) {
        apk_path = argv[1];
    } else {

     //     apk_path = "D:\\QQ.apk";
     //    apk_path ="D:\\dyjs.apk";
    //      apk_path ="D:\\tb.apk";


    }

    auto sos = load_arm64_sos_from_apk(apk_path);
    if (sos.empty()) {
        std::cerr << "[-] 没找到 lib/arm64-v8a/*.so\n";
        return 2;
    }

    std::vector<AnalysisResult> results;
    results.reserve(sos.size());

    for (size_t i = 0; i < sos.size(); ++i) {
        results.push_back(analyze_so(sos[i].name_in_apk, sos[i].data));
    }

    sort_results_by_risk(results);
    print_all_results_json_cn(results, true);
    return 0;
}