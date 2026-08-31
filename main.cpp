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
#include <limits>
#include <sstream>
#include <fstream>
#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <cctype>
#include <filesystem>
#include <new>
#include <utility>

#include "miniz.h"
#include "apk_scan_limits.h"
#include "custom_linker_detector.h"
#include "disasm_arm64.h"
#include "elf_dynamic.h"
#include "vmp_detector.h"
#include "vmp_linkage.h"

#ifdef _WIN32
#include <windows.h>
#include <shellapi.h>
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
static constexpr uint64_t SHF_EXECINSTR_VAL = 0x4;

static constexpr uint64_t SHN_UNDEF_VAL = 0;
static constexpr uint8_t STT_FUNC_VAL = 2;

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

template<typename T>
static bool read_struct(const std::vector<uint8_t> &buf, size_t offset, T &out) {
    if (offset > buf.size() || sizeof(T) > buf.size() - offset) return false;
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

static bool valid_file_range(uint64_t offset, uint64_t size, size_t file_size) {
    return offset <= file_size && size <= static_cast<uint64_t>(file_size) - offset;
}

struct ScanDiagnostic {
    std::string severity;
    std::string code;
    std::string entry;
    std::string detail;
    uint64_t entry_index = 0;
    uint64_t compressed_bytes = 0;
    uint64_t uncompressed_bytes = 0;
    bool has_entry_index = false;
};

static void record_scan_diagnostic(std::vector<ScanDiagnostic>& diagnostics,
                                   uint64_t& suppressed_count,
                                   ScanDiagnostic diagnostic) {
    if (diagnostics.size() < obfuscan::ApkScanLimits::kMaxRecordedDiagnostics) {
        diagnostics.push_back(std::move(diagnostic));
    } else {
        ++suppressed_count;
    }
}

struct MinizAllocationBudget {
    size_t limit_bytes = 0;
    size_t current_bytes = 0;
    size_t peak_bytes = 0;
    bool limit_hit = false;
};

struct alignas(std::max_align_t) BoundedAllocationHeader {
    size_t payload_bytes = 0;
};

static bool checked_allocation_size(size_t items, size_t size, size_t& out) {
    if (items != 0 && size > std::numeric_limits<size_t>::max() / items) return false;
    out = items * size;
    if (out == 0) out = 1;
    return out <= std::numeric_limits<size_t>::max() - sizeof(BoundedAllocationHeader);
}

static void* bounded_miniz_alloc(void* opaque, size_t items, size_t size) {
    auto* budget = static_cast<MinizAllocationBudget*>(opaque);
    size_t requested = 0;
    if (!budget || !checked_allocation_size(items, size, requested) ||
        requested > budget->limit_bytes - std::min(budget->current_bytes, budget->limit_bytes)) {
        if (budget) budget->limit_hit = true;
        return nullptr;
    }

    auto* header = static_cast<BoundedAllocationHeader*>(
        std::malloc(sizeof(BoundedAllocationHeader) + requested));
    if (!header) return nullptr;
    header->payload_bytes = requested;
    budget->current_bytes += requested;
    budget->peak_bytes = std::max(budget->peak_bytes, budget->current_bytes);
    return header + 1;
}

static void bounded_miniz_free(void* opaque, void* address) {
    if (!address) return;
    auto* budget = static_cast<MinizAllocationBudget*>(opaque);
    auto* header = static_cast<BoundedAllocationHeader*>(address) - 1;
    if (budget) {
        budget->current_bytes = header->payload_bytes <= budget->current_bytes
            ? budget->current_bytes - header->payload_bytes
            : 0;
    }
    std::free(header);
}

static void* bounded_miniz_realloc(void* opaque, void* address,
                                   size_t items, size_t size) {
    if (!address) return bounded_miniz_alloc(opaque, items, size);

    auto* budget = static_cast<MinizAllocationBudget*>(opaque);
    auto* old_header = static_cast<BoundedAllocationHeader*>(address) - 1;
    const size_t old_size = old_header->payload_bytes;
    size_t requested = 0;
    if (!budget || !checked_allocation_size(items, size, requested)) {
        if (budget) budget->limit_hit = true;
        return nullptr;
    }

    const size_t base = old_size <= budget->current_bytes
        ? budget->current_bytes - old_size
        : 0;
    if (requested > budget->limit_bytes - std::min(base, budget->limit_bytes)) {
        budget->limit_hit = true;
        return nullptr;
    }

    auto* new_header = static_cast<BoundedAllocationHeader*>(
        std::realloc(old_header, sizeof(BoundedAllocationHeader) + requested));
    if (!new_header) return nullptr;
    new_header->payload_bytes = requested;
    budget->current_bytes = base + requested;
    budget->peak_bytes = std::max(budget->peak_bytes, budget->current_bytes);
    return new_header + 1;
}

static void configure_bounded_miniz_allocator(mz_zip_archive& zip,
                                              MinizAllocationBudget& budget) {
    zip.m_pAlloc = bounded_miniz_alloc;
    zip.m_pFree = bounded_miniz_free;
    zip.m_pRealloc = bounded_miniz_realloc;
    zip.m_pAlloc_opaque = &budget;
}

struct ZipReaderScope {
    mz_zip_archive* zip = nullptr;
    MZ_FILE* external_file = nullptr;
    bool initialized = false;

    ~ZipReaderScope() {
        if (initialized && zip) mz_zip_reader_end(zip);
        if (external_file) std::fclose(external_file);
    }
};

static std::string miniz_error_detail(mz_zip_archive& zip) {
    const char* text = mz_zip_get_error_string(mz_zip_get_last_error(&zip));
    return text ? text : "unknown miniz error";
}

static bool table_entry_offset(uint64_t table_offset,
                               uint64_t index,
                               uint64_t entry_size,
                               size_t required_size,
                               size_t file_size,
                               size_t& out) {
    if (entry_size < required_size) return false;
    if (index != 0 && entry_size >
        (std::numeric_limits<uint64_t>::max() - table_offset) / index) {
        return false;
    }
    const uint64_t offset = table_offset + index * entry_size;
    if (!valid_file_range(offset, required_size, file_size)) return false;
    out = static_cast<size_t>(offset);
    return true;
}

static size_t count_buffer_needles_icase(const std::vector<uint8_t>& hay,
                                         const std::vector<std::string>& needles) {
    auto ascii_lower = [](unsigned char c) -> unsigned char {
        return (c >= 'A' && c <= 'Z') ? static_cast<unsigned char>(c + ('a' - 'A')) : c;
    };
    size_t count = 0;
    for (const auto& needle : needles) {
        if (needle.empty() || needle.size() > hay.size()) continue;
        auto found = std::search(hay.begin(), hay.end(), needle.begin(), needle.end(),
            [&](uint8_t lhs, char rhs) {
                return ascii_lower(lhs) == ascii_lower(static_cast<unsigned char>(rhs));
            });
        if (found != hay.end()) count++;
    }
    return count;
}

static size_t count_import_name_hits(const std::vector<std::string> &imports,
                                     const std::vector<std::string> &names) {
    std::unordered_set<std::string> wanted;
    for (auto name : names) {
        std::transform(name.begin(), name.end(), name.begin(),
                       [](unsigned char c){ return (char)std::tolower(c); });
        wanted.insert(std::move(name));
    }

    size_t count = 0;
    for (auto imp : imports) {
        std::transform(imp.begin(), imp.end(), imp.begin(),
                       [](unsigned char c){ return (char)std::tolower(c); });
        size_t version_pos = imp.find('@');
        if (version_pos != std::string::npos) {
            imp = imp.substr(0, version_pos);
        }
        if (wanted.count(imp)) count++;
    }
    return count;
}

static bool is_zip_magic(const std::vector<uint8_t>& buf) {
    return buf.size() >= 4 &&
           buf[0] == 0x50 &&
           buf[1] == 0x4b &&
           buf[2] == 0x03 &&
           buf[3] == 0x04;
}

static bool is_aarch64_elf64_little(const std::vector<uint8_t>& buf) {
    Elf64_Ehdr_L eh{};
    if (!read_struct(buf, 0, eh)) return false;
    return eh.e_ident[0] == 0x7f &&
           eh.e_ident[1] == 'E' &&
           eh.e_ident[2] == 'L' &&
           eh.e_ident[3] == 'F' &&
           eh.e_ident[4] == ELFCLASS64_VAL &&
           eh.e_ident[5] == ELFDATA2LSB_VAL &&
           eh.e_machine == EM_AARCH64_VAL;
}

static bool extract_first_elf_from_zip_buffer(
        const std::vector<uint8_t>& zip_buf,
        std::vector<uint8_t>& out_elf,
        std::string& inner_name,
        const std::string& outer_entry_name,
        std::vector<ScanDiagnostic>* diagnostics,
        uint64_t* suppressed_diagnostics,
        std::string& failure_code) {
    MinizAllocationBudget allocation_budget{
        static_cast<size_t>(obfuscan::ApkScanLimits::kMaxInnerZipMetadataBytes)};
    mz_zip_archive zip{};
    memset(&zip, 0, sizeof(zip));
    configure_bounded_miniz_allocator(zip, allocation_budget);
    ZipReaderScope scope{&zip, nullptr, false};

    auto report_inner = [&](const std::string& code,
                            const std::string& inner_entry,
                            uint64_t entry_index,
                            uint64_t compressed_bytes,
                            uint64_t uncompressed_bytes,
                            const std::string& detail = std::string()) {
        if (failure_code.empty()) failure_code = code;
        if (!diagnostics || !suppressed_diagnostics) return;
        const std::string qualified_name = inner_entry.empty()
            ? outer_entry_name
            : outer_entry_name + "!" + inner_entry;
        record_scan_diagnostic(
            *diagnostics, *suppressed_diagnostics,
            ScanDiagnostic{"warning", code, qualified_name, detail, entry_index,
                           compressed_bytes, uncompressed_bytes, true});
    };

    if (!mz_zip_reader_init_mem(&zip, zip_buf.data(), zip_buf.size(),
                                MZ_ZIP_FLAG_DO_NOT_SORT_CENTRAL_DIRECTORY)) {
        report_inner(allocation_budget.limit_hit ? "INNER_ZIP_METADATA_LIMIT"
                                                 : "INNER_ZIP_OPEN_FAILED",
                     "", 0, 0, 0, miniz_error_detail(zip));
        return false;
    }
    scope.initialized = true;

    mz_uint file_count = mz_zip_reader_get_num_files(&zip);
    if (file_count > obfuscan::ApkScanLimits::kMaxInnerZipEntries) {
        report_inner("INNER_ZIP_ENTRY_LIMIT", "", 0, 0, file_count);
        return false;
    }

    bool found = false;
    uint64_t best_rank = 0;
    uint64_t accepted_uncompressed_bytes = 0;
    const obfuscan::ZipPayloadPolicy policy{
        obfuscan::ApkScanLimits::kMaxSingleInnerEntryBytes,
        obfuscan::ApkScanLimits::kMaxCompressionRatio,
        obfuscan::ApkScanLimits::kCompressionRatioFloorBytes,
    };

    for (mz_uint i = 0; i < file_count; ++i) {
        mz_zip_archive_file_stat st{};
        if (!mz_zip_reader_file_stat(&zip, i, &st)) {
            report_inner("INNER_ZIP_ENTRY_STAT_FAILED", "", i, 0, 0,
                         miniz_error_detail(zip));
            continue;
        }
        if (st.m_is_directory) continue;

        const obfuscan::ZipPayloadDecision decision = obfuscan::evaluate_zip_payload(
            {st.m_comp_size, st.m_uncomp_size,
             st.m_is_encrypted != 0, st.m_is_supported != 0},
            policy);
        if (decision == obfuscan::ZipPayloadDecision::kEmpty) continue;
        if (decision != obfuscan::ZipPayloadDecision::kAllow) {
            report_inner("INNER_ZIP_" +
                             std::string(obfuscan::zip_payload_decision_code(decision)),
                         st.m_filename, i, st.m_comp_size, st.m_uncomp_size);
            continue;
        }

        if (!obfuscan::fits_cumulative_budget(
                accepted_uncompressed_bytes, st.m_uncomp_size,
                obfuscan::ApkScanLimits::kMaxTotalInnerEntryBytes)) {
            report_inner("INNER_ZIP_TOTAL_UNCOMPRESSED_LIMIT", st.m_filename, i,
                         st.m_comp_size, st.m_uncomp_size);
            continue;
        }
        accepted_uncompressed_bytes += st.m_uncomp_size;

        std::vector<uint8_t> tmp;
        try {
            tmp.resize(static_cast<size_t>(st.m_uncomp_size));
        } catch (const std::bad_alloc&) {
            report_inner("INNER_ZIP_ALLOCATION_FAILED", st.m_filename, i,
                         st.m_comp_size, st.m_uncomp_size);
            continue;
        }

        if (!mz_zip_reader_extract_to_mem(&zip, i, tmp.data(), tmp.size(), 0)) {
            report_inner("INNER_ZIP_EXTRACT_FAILED", st.m_filename, i,
                         st.m_comp_size, st.m_uncomp_size, miniz_error_detail(zip));
            continue;
        }

        const bool elf_magic = tmp.size() >= 4 && tmp[0] == 0x7f && tmp[1] == 'E' &&
                               tmp[2] == 'L' && tmp[3] == 'F';
        if (elf_magic) {
            uint64_t rank = static_cast<uint64_t>(tmp.size());
            if (is_aarch64_elf64_little(tmp)) {
                rank += (1ULL << 62);
            }

            if (!found || rank > best_rank) {
                found = true;
                best_rank = rank;
                out_elf = std::move(tmp);
                inner_name = st.m_filename;
            }
        }
    }

    return found;
}

// =========================
// ELF 分析
// =========================

struct SectionInfo {
    std::string name;
    uint32_t type = 0;
    uint64_t address = 0;
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

struct DefinedFunctionRange {
    std::string name;
    uint64_t address = 0;
    uint64_t size = 0;
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
    bool entry_in_writable_segment = false;

    bool is_zip_container = false;
    bool inner_elf_found = false;
    bool known_hook_framework = false;
    bool known_runtime_framework = false;
    bool known_vm_runtime = false;
    bool embedded_cxxabi_runtime = false;
    uint8_t runtime_evidence_classes = 0;
    size_t runtime_raw_identity_hits = 0;
    size_t runtime_import_api_hits = 0;
    bool possible_custom_linker = false;
    obfuscan::custom_linker::Result custom_linker;
    std::string format_note;
    std::string known_framework_name;
    std::string known_runtime_name;

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
    std::vector<std::string> needed_libraries;
    std::vector<std::string> defined_exports;
    std::vector<DefinedFunctionRange> defined_function_ranges;
    std::vector<SectionInfo> sections;
    std::vector<SegmentInfo> segments;
    A64StatsEx a64;
    std::vector<DisasmLine> preview_lines;
    std::vector<EntryPreview> entry_previews;
    VmpDeepResult vmp;

    double packer_score = 0.0;
    double ollvm_score = 0.0;
    double strong_obf_score = 0.0;
    bool vmp_protected_client = false;
    std::string vmp_provider_so;
    std::string vmp_needed_library;
    std::vector<std::string> vmp_shared_symbols;
    std::string final_label;
    std::vector<std::string> reasons;
};

static bool va_to_file_offset(uint64_t va,
                              const std::vector<SegmentInfo>& segments,
                              uint64_t& out_off) {
    for (const auto& seg : segments) {
        if (seg.type != PT_LOAD_VAL) continue;
        if (va >= seg.vaddr && va - seg.vaddr < seg.filesz) {
            const uint64_t delta = va - seg.vaddr;
            if (delta > std::numeric_limits<uint64_t>::max() - seg.offset) continue;
            out_off = seg.offset + delta;
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

static std::vector<AddressRange> find_dynamic_plt_branch_ranges(
        const std::vector<ExecutableRegionView>& regions,
        const std::vector<uint64_t>& jump_slot_vas);





static bool is_high_risk_result(const AnalysisResult& r) {
    return r.vmp_protected_client ||
           r.possible_custom_linker ||
           r.packer_score >= 0.68 ||
           r.strong_obf_score >= 0.70 ||
           r.vmp.possible ||
           (r.packer_score >= 0.62 && r.strong_obf_score >= 0.58) ||
           (r.ollvm_score >= 0.65 && r.strong_obf_score >= 0.60);
}

static bool is_medium_risk_result(const AnalysisResult& r) {
    return r.known_hook_framework ||
           r.custom_linker.loader_component() ||
           r.packer_score >= 0.45 ||
           r.ollvm_score >= 0.50 ||
           r.strong_obf_score >= 0.50 ||
           r.vmp.score >= 0.50;
}

static std::string path_basename_lower(const std::string& path) {
    size_t pos = path.find_last_of("/\\");
    std::string base = (pos == std::string::npos) ? path : path.substr(pos + 1);
    std::transform(base.begin(), base.end(), base.begin(),
                   [](unsigned char c) { return (char)std::tolower(c); });
    return base;
}

static bool is_known_runtime_library_name(const std::string& base, std::string& family) {
    struct KnownName {
        const char* needle;
        const char* family;
    };

    static const KnownName names[] = {
        {"libreact", "React Native"},
        {"librn", "React Native"},
        {"libhermes", "Hermes/React Native"},
        {"libjsi", "React Native JSI"},
        {"libjsc", "JavaScriptCore/React Native"},
        {"libturbomodule", "React Native TurboModule"},
        {"libuimanager", "React Native UIManager"},
        {"libmapbuffer", "React Native MapBuffer"},
        {"libyoga", "Yoga layout"},
        {"libfbjni", "fbjni"},
        {"libglog", "glog"},
        {"libsentry", "Sentry native"},
        {"libgifimage", "image codec"},
        {"libglide-webp", "image codec"},
        {"libnative-imagetranscoder", "image codec"},
        {"libreanimated", "React Native Reanimated"},
        {"libvisioncamera", "React Native VisionCamera"},
        {"libjscexecutor", "React Native JS executor"},
        {"libjserrorhandler", "React Native JS error handler"},
        {"libjsinspector", "React Native JS inspector"},
        {"libjsijniprofiler", "React Native JSI profiler"},
        {"libnative-filters", "image filter"},
        {"libmetis", "Metis/native graph library"},
        {"liblogger", "native logging"},
        {"libtt_ugen_layout", "layout engine"}
    };

    for (const auto& item : names) {
        if (base.find(item.needle) != std::string::npos) {
            family = item.family;
            return true;
        }
    }
    return false;
}

struct RuntimeEvidence {
    std::string family;
    bool basename_hit = false;
    bool raw_identity_hit = false;
    bool import_api_hit = false;
    size_t raw_hits = 0;
    size_t import_hits = 0;

    uint8_t evidence_classes() const {
        return static_cast<uint8_t>(basename_hit) +
               static_cast<uint8_t>(raw_identity_hit) +
               static_cast<uint8_t>(import_api_hit);
    }
    bool present() const { return evidence_classes() != 0; }
    bool confirmed() const { return evidence_classes() >= 2; }
};

static RuntimeEvidence detect_known_vm_or_branch_runtime(
        const std::string& basename,
        const std::vector<uint8_t>& image,
        const std::vector<std::string>& imports) {
    RuntimeEvidence best;
    auto consider = [&](const char* family,
                        bool basename_hit,
                        const std::vector<std::string>& identity_needles,
                        const std::vector<std::string>& api_names) {
        RuntimeEvidence candidate;
        candidate.family = family;
        candidate.basename_hit = basename_hit;
        candidate.raw_hits = count_buffer_needles_icase(image, identity_needles);
        candidate.import_hits = count_import_name_hits(imports, api_names);
        candidate.raw_identity_hit = candidate.raw_hits >= 2;
        candidate.import_api_hit = candidate.import_hits >= 2;
        if (!candidate.present()) return;
        const auto rank = [](const RuntimeEvidence& item) {
            return std::make_pair(item.evidence_classes(), item.raw_hits + item.import_hits);
        };
        if (!best.present() || rank(candidate) > rank(best)) best = std::move(candidate);
    };

    const bool libcxx_name = basename == "libc++_shared.so" ||
                             basename == "libc++_shared_64.so" ||
                             basename == "libstlport_shared.so" ||
                             basename == "libgnustl_shared.so";
    // C++ ABI symbols occur in almost every native library, so they are only
    // an SO-wide alternative when the SONAME itself is the shared C++ runtime.
    if (libcxx_name) {
        consider("C++ runtime callback/virtual dispatch", true,
                 {"std::__ndk1", "LLVM libc++", "__cxa_demangle", "__gxx_personality_v0",
                  "__vmi_class_type_info", "__cxxabi"},
                 {"__cxa_throw", "__cxa_begin_catch", "__cxa_end_catch", "__gxx_personality_v0"});
    }
    consider("Nano Compose expression/layout runtime",
             basename.find("nano_compose") != std::string::npos,
             {"ComposeFunc", "ExprIDValue", "OpGroupValue", "LayoutNode"}, {});
    consider("QuickJS bytecode runtime",
             basename.find("quickjs") != std::string::npos,
             {"QuickJS", "JS_EvalInternal", "JS_CallInternal", "JS_ExecutePendingJob"},
             {"JS_NewRuntime", "JS_NewContext", "JS_Eval", "JS_ExecutePendingJob"});
    const bool ffmpeg_name = basename.find("ffmpeg") != std::string::npos ||
        basename == "libavcodec.so" || basename == "libavutil.so" ||
        basename == "libavfilter.so" || basename == "libavformat.so" ||
        basename == "libswscale.so" || basename == "libavdevice.so" ||
        basename == "libijkplayer.so";
    // A basename is deliberately only one evidence class.  At least one
    // independent identity-string or imported-API class is still required by
    // RuntimeEvidence::confirmed() before this can override a VMP verdict.
    consider("FFmpeg/media codec runtime", ffmpeg_name,
              {"FFmpeg version", "Lavc", "Lavf", "Lavu", "Lavfi", "Sws",
               "ff_h264_", "libavcodec", "libavutil", "libavformat",
               "libavfilter", "libswscale", "ijkplayer"},
              {"avcodec_send_packet", "avcodec_receive_frame", "avformat_open_input",
               "av_read_frame", "av_malloc", "av_free", "av_log", "av_frame_alloc",
               "sws_scale", "avfilter_graph_alloc"});
    consider("SQLite VDBE runtime",
             basename.find("sqlite") != std::string::npos,
             {"SQLite format 3", "sqlite3VdbeExec", "database disk image is malformed",
              "malformed database schema", "sqlite_master", "sqlite_sequence"},
             {"sqlite3_prepare_v2", "sqlite3_step", "sqlite3_finalize", "sqlite3_open_v2"});
    consider("Unicorn/Flutter UI runtime",
             basename == "libunicorn.so" || basename.rfind("libunicorn_", 0) == 0,
             {"Unicorn Engine", "unicorn_render_engine", "FlutterJNI",
              "FlutterMutatorsStack", "unicorn_library_loader"}, {});
    consider("CPU emulation runtime",
             basename.find("unicorn") != std::string::npos ||
                 basename.find("qemu") != std::string::npos,
             {"unicorn engine", "qemu-system", "cpu_exec", "uc_version"},
             {"uc_open", "uc_emu_start", "uc_hook_add", "uc_close"});
    consider("Hermes JavaScript runtime",
             basename.find("hermes") != std::string::npos,
             {"facebook::hermes", "HermesRuntime", "Hermes bytecode", "HermesVM"},
             {"hermes_create_runtime", "hermes_get_runtime_properties"});
    const bool lua_name = basename.rfind("liblua", 0) == 0 ||
                          basename.rfind("lua", 0) == 0;
    consider("Lua bytecode runtime", lua_name,
             {"Lua 5.", "luaV_execute", "luaD_precall", "luaG_runerror"},
             {"lua_pcall", "lua_pcallk", "lua_newstate", "luaL_newstate"});
    const bool jsc_name = basename.rfind("libjsc", 0) == 0 ||
                          basename.find("javascriptcore") != std::string::npos;
    consider("JavaScriptCore runtime", jsc_name,
             {"JavaScriptCore", "JSC::VM", "WTF::", "JSGlobalObject"},
             {"JSEvaluateScript", "JSGlobalContextCreate", "JSContextGroupCreate"});
    const bool wasm_name = basename.rfind("libwasm", 0) == 0 ||
                           basename.find("webassembly") != std::string::npos;
    consider("WebAssembly runtime", wasm_name,
             {"WebAssembly", "wasm interpreter", "wasm_runtime", "WASM bytecode"},
             {"wasm_runtime_init", "wasm_runtime_load", "wasm_runtime_instantiate"});
    const bool regex_name = basename.rfind("libpcre", 0) == 0 ||
                            basename.rfind("libre2", 0) == 0 ||
                            basename.rfind("libregex", 0) == 0;
    consider("regular-expression runtime", regex_name,
             {"PCRE2", "pcre2_match", "regex bytecode", "RE2::"},
             {"pcre_exec", "pcre2_match", "regexec"});
    return best;
}

static bool is_known_non_vm_candidate_function(const std::string& symbol) {
    std::string lower = symbol;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return symbol.find("_M_open") != std::string::npos ||
           symbol.find("cJSON_PrintBuffered") != std::string::npos ||
           symbol.find("__do_find_public_src") != std::string::npos ||
           symbol.find("av_sscanf") != std::string::npos ||
           symbol.find("__cxa_demangle") != std::string::npos ||
           lower.find("demangler") != std::string::npos;
}

static bool is_cxxabi_runtime_anchor_function(const std::string& symbol) {
    return symbol.rfind("__cxa_", 0) == 0 ||
           symbol == "__gxx_personality_v0" ||
           symbol == "__dynamic_cast" ||
           symbol.find("__cxxabi") != std::string::npos;
}

static AnalysisResult analyze_so(const std::string &name,
                                 const std::vector<uint8_t> &input_buf,
                                 std::vector<ScanDiagnostic>* diagnostics = nullptr,
                                 uint64_t* suppressed_diagnostics = nullptr) {
    AnalysisResult r;
    r.so_name = name;
    r.file_size = input_buf.size();


    bool loaded_from_assets = (name.find("assets/") != std::string::npos);
    if (loaded_from_assets) {
        r.reasons.push_back("loaded from assets path");
    }
    std::string so_basename = path_basename_lower(name);
    if (is_known_runtime_library_name(so_basename, r.known_runtime_name)) {
        r.known_runtime_framework = true;
    }
    const bool pine_basename_hint =
        so_basename == "libpine.so" || so_basename == "libpinehook.so";

    std::vector<uint8_t> inner_work_buf;
    const std::vector<uint8_t>* work_buf_ptr = &input_buf;

    if (is_zip_magic(input_buf)) {
        r.is_zip_container = true;
        r.format_note = "ZIP伪装SO";

        std::string inner_name;
        std::string inner_failure_code;
        if (extract_first_elf_from_zip_buffer(
                input_buf, inner_work_buf, inner_name, name,
                diagnostics, suppressed_diagnostics, inner_failure_code)) {
            r.inner_elf_found = true;
            r.format_note = "ZIP伪装SO，已提取内层ELF";
            r.reasons.push_back("so entry is actually a zip container");
            work_buf_ptr = &inner_work_buf;
        } else {
            r.final_label = "ZIP_SO_CONTAINER";
            r.reasons.push_back("so entry is actually a zip container");
            r.packer_score = 0.78;
            r.strong_obf_score = 0.68;
            if (!inner_failure_code.empty()) {
                r.reasons.push_back("inner ZIP scan stopped: " + inner_failure_code);
                r.vmp.outcome = "PARTIAL_ANALYSIS";
                r.vmp.limitation = "Inner ZIP analysis stopped safely: " +
                                   inner_failure_code;
            } else {
                r.vmp.outcome = "INCONCLUSIVE_PACKED";
                r.vmp.limitation = "No observable inner ELF was found in the container";
            }
            r.vmp.confidence = "UNKNOWN";
            return r;
        }
    }

    const std::vector<uint8_t>& work_buf = *work_buf_ptr;

    r.analyzed_file_size = work_buf.size();
    r.file_entropy = shannon_entropy(work_buf.data(), work_buf.size());
    r.printable_string_count = count_printable_strings(work_buf, 4);

    r.has_jni_onload_string =
        count_buffer_needles_icase(work_buf, {"JNI_OnLoad"}) != 0;

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
        size_t off = 0;
        if (!table_entry_offset(eh.e_shoff, i, eh.e_shentsize,
                                sizeof(sh), work_buf.size(), off)) break;
        if (!read_struct(work_buf, off, sh)) break;
        shdrs.push_back(sh);
    }

    std::vector<uint8_t> shstrtab;
    if (eh.e_shstrndx < shdrs.size()) {
        const auto &shstr = shdrs[eh.e_shstrndx];
        if (valid_file_range(shstr.sh_offset, shstr.sh_size, work_buf.size())) {
            const size_t begin = static_cast<size_t>(shstr.sh_offset);
            const size_t end = begin + static_cast<size_t>(shstr.sh_size);
            shstrtab.assign(work_buf.begin() + begin, work_buf.begin() + end);
        }
    }

    std::vector<std::string> section_names;
    section_names.reserve(shdrs.size());

    for (const auto &sh : shdrs) {
        SectionInfo si;
        si.name = get_cstr_from_table(shstrtab, sh.sh_name);
        si.type = sh.sh_type;
        si.address = sh.sh_addr;
        si.offset = sh.sh_offset;
        si.size = sh.sh_size;
        si.flags = sh.sh_flags;

        if (valid_file_range(si.offset, si.size, work_buf.size()) && si.size > 0) {
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
    std::vector<ExecutableRegionView> executable_regions;

    for (uint16_t i = 0; i < eh.e_phnum; ++i) {
        Elf64_Phdr_L ph{};
        size_t off = 0;
        if (!table_entry_offset(eh.e_phoff, i, eh.e_phentsize,
                                sizeof(ph), work_buf.size(), off)) break;
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

        if (eh.e_entry != 0 &&
            ph.p_type == PT_LOAD_VAL &&
            (ph.p_flags & PF_W_VAL) &&
            eh.e_entry >= ph.p_vaddr &&
            eh.e_entry - ph.p_vaddr < ph.p_memsz) {
            r.entry_in_writable_segment = true;
        }

        if (ph.p_type == PT_LOAD_VAL &&
            (ph.p_flags & PF_X_VAL) &&
            valid_file_range(ph.p_offset, ph.p_filesz, work_buf.size()) &&
            ph.p_vaddr <= UINT64_MAX - ph.p_filesz &&
            ph.p_filesz > 0) {
            double e = shannon_entropy(work_buf.data() + ph.p_offset, static_cast<size_t>(ph.p_filesz));
            exec_entropy_sum += e;
            exec_entropy_count++;

            ExecutableRegionView region;
            region.data = work_buf.data() + static_cast<size_t>(ph.p_offset);
            region.size = static_cast<size_t>(ph.p_filesz);
            region.virtual_address = ph.p_vaddr;
            region.name = "PT_LOAD[" + std::to_string(i) + "]";
            executable_regions.push_back(std::move(region));
        }
    }

    if (exec_entropy_count > 0) {
        r.avg_exec_entropy = exec_entropy_sum / double(exec_entropy_count);
    }
    if (r.text_size == 0) {
        for (const auto& region : executable_regions) {
            if (r.text_size > UINT64_MAX - region.size) {
                r.text_size = UINT64_MAX;
                break;
            }
            r.text_size += region.size;
        }
    }

    std::vector<obfuscan::elf_dynamic::Segment> dynamic_segments;
    dynamic_segments.reserve(r.segments.size());
    for (const auto& seg : r.segments) {
        dynamic_segments.push_back({seg.type, seg.flags, seg.offset, seg.vaddr,
                                    seg.filesz, seg.memsz});
    }
    const obfuscan::elf_dynamic::ParseResult dynamic_info =
        obfuscan::elf_dynamic::parse(work_buf, dynamic_segments);
    if (dynamic_info.valid) {
        r.has_dynsym = r.has_dynsym || dynamic_info.has_symbol_table;
        if (dynamic_info.has_init_array) {
            r.has_init_array = true;
            r.init_array_offset = dynamic_info.init_array_file_offset;
            r.init_array_size = dynamic_info.init_array_size;
        }
    }

    std::vector<uint8_t> dynstr;
    std::vector<Elf64_Sym_L> dynsyms;
    std::vector<std::pair<std::string, uint64_t>> exported_funcs;
    std::vector<DefinedFunctionRange> cxxabi_runtime_anchors;
    std::unordered_set<std::string> defined_export_seen;
    auto record_defined_symbol = [&](const std::string& symbol,
                                     uint64_t value,
                                     uint64_t size,
                                     uint8_t info) {
        if (symbol.empty()) return;
        if (defined_export_seen.insert(symbol).second) {
            r.defined_exports.push_back(symbol);
        }
        if ((info & 0x0fU) == STT_FUNC_VAL && size > 0 &&
            value <= UINT64_MAX - size) {
            if (is_known_non_vm_candidate_function(symbol)) {
                r.defined_function_ranges.push_back({symbol, value, size});
            }
            if (is_cxxabi_runtime_anchor_function(symbol)) {
                cxxabi_runtime_anchors.push_back({symbol, value, size});
            }
        }
    };

    for (size_t i = 0; i < shdrs.size(); ++i) {
        const auto &sh = shdrs[i];
        if (sh.sh_type != SHT_DYNSYM_VAL ||
            sh.sh_entsize != sizeof(Elf64_Sym_L) ||
            !valid_file_range(sh.sh_offset, sh.sh_size, work_buf.size())) {
            continue;
        }
        size_t cnt = static_cast<size_t>(sh.sh_size / sh.sh_entsize);
        dynsyms.resize(cnt);
        std::memcpy(dynsyms.data(),
                    work_buf.data() + sh.sh_offset,
                    cnt * sizeof(Elf64_Sym_L));

        // ELF defines the matching string table through sh_link.  Section
        // names are optional and frequently removed by protectors.
        if (sh.sh_link < shdrs.size()) {
            const auto& linked = shdrs[sh.sh_link];
            if (valid_file_range(linked.sh_offset, linked.sh_size, work_buf.size())) {
                const size_t begin = static_cast<size_t>(linked.sh_offset);
                const size_t end = begin + static_cast<size_t>(linked.sh_size);
                dynstr.assign(work_buf.begin() + begin, work_buf.begin() + end);
            }
        }
        if (dynstr.empty()) {
            for (size_t string_index = 0; string_index < shdrs.size(); ++string_index) {
                if (string_index >= r.sections.size() ||
                    r.sections[string_index].name != ".dynstr") continue;
                const auto& fallback = shdrs[string_index];
                if (!valid_file_range(fallback.sh_offset, fallback.sh_size,
                                      work_buf.size())) continue;
                const size_t begin = static_cast<size_t>(fallback.sh_offset);
                const size_t end = begin + static_cast<size_t>(fallback.sh_size);
                dynstr.assign(work_buf.begin() + begin, work_buf.begin() + end);
                break;
            }
        }
        break;
    }

    for (const auto &sym : dynsyms) {
        std::string sname = get_cstr_from_table(dynstr, sym.st_name);
        if (sname.empty()) continue;

        if (sym.st_shndx == SHN_UNDEF_VAL) {
            r.imports.push_back(sname);
        } else {
            r.exported_dynsym_count++;
            record_defined_symbol(sname, sym.st_value, sym.st_size, sym.st_info);

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

    std::unordered_set<std::string> import_seen;
    std::vector<std::string> merged_imports;
    merged_imports.reserve(r.imports.size() + dynamic_info.imports.size());
    auto merge_import = [&](const std::string& symbol) {
        if (!symbol.empty() && import_seen.insert(symbol).second) {
            merged_imports.push_back(symbol);
        }
    };
    for (const auto& symbol : r.imports) merge_import(symbol);
    if (dynamic_info.valid) {
        r.needed_libraries = dynamic_info.needed_libraries;
        for (const auto& symbol : dynamic_info.imports) merge_import(symbol);
        r.exported_dynsym_count = std::max(r.exported_dynsym_count,
                                           dynamic_info.exported_symbol_count);
        std::set<std::pair<std::string, uint64_t>> exported_seen(
            exported_funcs.begin(), exported_funcs.end());
        for (const auto& symbol : dynamic_info.symbols) {
            if (symbol.undefined() || symbol.value == 0 || symbol.name.empty()) continue;
            const std::string& sname = symbol.name;
            record_defined_symbol(sname, symbol.value, symbol.size, symbol.info);
            const bool interesting = sname == "JNI_OnLoad" ||
                sname.rfind("Java_", 0) == 0 ||
                sname.find("init") != std::string::npos ||
                sname.find("Init") != std::string::npos ||
                sname.find("load") != std::string::npos ||
                sname.find("Load") != std::string::npos ||
                sname.find("register") != std::string::npos ||
                sname.find("Register") != std::string::npos;
            if (interesting && exported_seen.insert({sname, symbol.value}).second) {
                exported_funcs.push_back({sname, symbol.value});
            }
        }
    }
    r.imports = std::move(merged_imports);
    std::sort(r.needed_libraries.begin(), r.needed_libraries.end());
    r.needed_libraries.erase(
        std::unique(r.needed_libraries.begin(), r.needed_libraries.end()),
        r.needed_libraries.end());
    std::sort(r.defined_exports.begin(), r.defined_exports.end());
    if (cxxabi_runtime_anchors.size() >= 8) {
        uint64_t runtime_begin = UINT64_MAX;
        uint64_t runtime_end = 0;
        for (const auto& anchor : cxxabi_runtime_anchors) {
            runtime_begin = std::min(runtime_begin, anchor.address);
            runtime_end = std::max(runtime_end, anchor.address + anchor.size);
        }
        constexpr uint64_t kMaxEmbeddedRuntimeSpan = 512ULL * 1024ULL;
        if (runtime_begin < runtime_end &&
            runtime_end - runtime_begin <= kMaxEmbeddedRuntimeSpan) {
            r.embedded_cxxabi_runtime = true;
            r.defined_function_ranges.push_back({
                "embedded C++ ABI/demangler runtime",
                runtime_begin,
                runtime_end - runtime_begin
            });
            r.reasons.push_back(
                "embedded C++ ABI runtime range excluded from VMP candidates");
        }
    }
    std::sort(r.defined_function_ranges.begin(), r.defined_function_ranges.end(),
        [](const DefinedFunctionRange& lhs, const DefinedFunctionRange& rhs) {
            if (lhs.address != rhs.address) return lhs.address < rhs.address;
            if (lhs.size != rhs.size) return lhs.size < rhs.size;
            return lhs.name < rhs.name;
        });
    r.defined_function_ranges.erase(
        std::unique(r.defined_function_ranges.begin(), r.defined_function_ranges.end(),
            [](const DefinedFunctionRange& lhs, const DefinedFunctionRange& rhs) {
                return lhs.address == rhs.address && lhs.size == rhs.size &&
                       lhs.name == rhs.name;
            }),
        r.defined_function_ranges.end());
    r.import_count = r.imports.size();

    RuntimeEvidence semantic_runtime =
        detect_known_vm_or_branch_runtime(so_basename, work_buf, r.imports);
    if (semantic_runtime.present()) {
        r.known_runtime_framework = true;
        r.known_vm_runtime = semantic_runtime.confirmed();
        r.known_runtime_name = semantic_runtime.family;
        r.runtime_evidence_classes = semantic_runtime.evidence_classes();
        r.runtime_raw_identity_hits = semantic_runtime.raw_hits;
        r.runtime_import_api_hits = semantic_runtime.import_hits;
    }

    const uint8_t *text_ptr = nullptr;
    size_t text_size = 0;
    uint64_t text_base_addr = 0;

    for (const auto &sec : r.sections) {
        if (sec.name == ".text" &&
            valid_file_range(sec.offset, sec.size, work_buf.size()) &&
            sec.size >= 4) {
            text_ptr = work_buf.data() + sec.offset;
            text_size = static_cast<size_t>(sec.size);
            text_base_addr = sec.address;
            break;
        }
    }

    if (!text_ptr) {
        for (const auto &seg : r.segments) {
            if (seg.type == PT_LOAD_VAL &&
                (seg.flags & PF_X_VAL) &&
                valid_file_range(seg.offset, seg.filesz, work_buf.size()) &&
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

            if (dynamic_info.valid && dynamic_info.has_init &&
                dynamic_info.init_va != 0) {
                add_entry_preview(r, engine, work_buf, "DT_INIT",
                                  dynamic_info.init_va, 12);
            }

            if (r.has_init_array &&
                r.init_array_size >= 8 &&
                valid_file_range(r.init_array_offset, r.init_array_size,
                                 work_buf.size())) {

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

    // These are uncommon enough to support a generic packer suspicion. Common
    // libc, mmap/mprotect, file-I/O and dlopen/dlsym imports are capabilities,
    // not evidence that a library implements a private linker.
    static const std::unordered_set<std::string> suspicious_loader_imports = {
        "android_dlopen_ext", "mremap", "memfd_create", "ptrace",
        "process_vm_readv", "process_vm_writev", "dl_iterate_phdr"
    };

    size_t loader_hit = 0;
    for (const auto &imp : r.imports) {
        if (suspicious_loader_imports.count(imp)) loader_hit++;
    }

    size_t pine_name_hits = count_buffer_needles_icase(work_buf, {
        "_ZN4pine", "top.canyie.pine", "top/canyie/pine",
        "PineNativeInlineHook", "pine::", "PineEnhances", "PineConfig"
    });
    size_t pine_art_hits = count_buffer_needles_icase(work_buf, {
        "ElfImage", "ArtMethod", "Jit", "RegisterNatives", "trampoline", "entrypoint"
    });
    size_t vmp_metadata_hits = count_buffer_needles_icase(work_buf, {
        "Target VMP2 metadata", "VMP2 metadata", "VMP metadata"
    });
    const bool protection_interpreter_marker =
        count_buffer_needles_icase(work_buf, {"JavaVMP"}) >= 1 &&
        count_buffer_needles_icase(work_buf, {"interpreter_wrap_"}) >= 1;
    if (protection_interpreter_marker) {
        ++vmp_metadata_hits;
        r.reasons.push_back("protection VM interpreter marker cluster");
    }
    const bool pine_identity_confirmed =
        (pine_basename_hint && pine_name_hits >= 1 && pine_art_hits >= 1) ||
        (pine_name_hits >= 2 && pine_art_hits >= 2);
    if (pine_identity_confirmed) {
        r.known_hook_framework = true;
        r.known_framework_name = "Pine";
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
    if (r.sections.empty()) {
        for (const auto& seg : r.segments) {
            if (seg.type != PT_LOAD_VAL || (seg.flags & PF_X_VAL) != 0 ||
                seg.filesz < 64 * 1024 ||
                !valid_file_range(seg.offset, seg.filesz, work_buf.size())) {
                continue;
            }
            const double entropy = shannon_entropy(
                work_buf.data() + static_cast<size_t>(seg.offset),
                static_cast<size_t>(seg.filesz));
            r.max_section_entropy = std::max(r.max_section_entropy, entropy);
            if (entropy >= 7.4) huge_entropy_blob = 1.0;
        }
    }

    size_t init_array_entry_count = static_cast<size_t>(r.init_array_size / 8);
    double heavy_init_array = 0.0;
    if (init_array_entry_count >= 20) heavy_init_array = 1.0;
    else if (init_array_entry_count >= 8) heavy_init_array = 0.5;

    double zip_container_suspicion = r.is_zip_container ? 1.0 : 0.0;
    double asset_path_suspicion = loaded_from_assets ? 1.0 : 0.0;

    double suspicious_section_name = 0.0;
    static const std::vector<std::string> sec_needles = {
        "ollvm", "obf", "vmp", "vm", "protect", "guard", "shell", "stub"
    };
    if (contains_any_icase(section_names, sec_needles)) suspicious_section_name = 1.0;

    obfuscan::custom_linker::Context custom_linker_context;
    custom_linker_context.basename = so_basename;
    custom_linker_context.known_hook_framework = r.known_hook_framework;
    custom_linker_context.known_runtime_framework = r.known_runtime_framework;
    custom_linker_context.sectionless = r.sections.empty();
    custom_linker_context.code_obscured_by_packing =
        (tiny_text_big_file > 0.5 && huge_entropy_blob > 0.5) ||
        executable_regions.empty();
    custom_linker_context.high_entropy_payload = huge_entropy_blob > 0.5;
    custom_linker_context.packed_container = r.is_zip_container;
    custom_linker_context.loaded_from_assets = loaded_from_assets;

    r.custom_linker = obfuscan::custom_linker::analyze(
        work_buf, r.imports, custom_linker_context);
    r.possible_custom_linker = r.custom_linker.likely_protection();
    if (r.custom_linker.hook_alternative &&
        r.custom_linker.outcome ==
            obfuscan::custom_linker::Outcome::ELF_INSPECTION_OR_HOOK) {
        r.known_hook_framework = true;
        if (r.known_framework_name.empty()) {
            r.known_framework_name = pine_basename_hint ? "Pine" : "Hook/Trampoline";
        }
    }

    r.packer_score =
        std::min(0.50, loader_hit * 0.08) +
        (r.rwx_segment ? 0.22 : 0.0) +
        (r.entry_in_writable_segment ? 0.18 : 0.0) +
        (r.has_init_array ? 0.05 : 0.0) +
        (heavy_init_array * 0.12) +
        (r.has_jni_onload_string ? 0.05 : 0.0) +
        (huge_entropy_blob * 0.22) +
        (tiny_text_big_file * 0.18) +
        (low_string_density * 0.08) +
        (zip_container_suspicion * 0.15) +
        (asset_path_suspicion * 0.12);

    r.packer_score = clamp01(r.packer_score);
    if (r.possible_custom_linker) {
        r.packer_score = std::max(r.packer_score, 0.72);
    }

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

    VmpAnalysisContext vmp_context;
    vmp_context.import_count = r.import_count;
    vmp_context.has_init_array = r.has_init_array;
    vmp_context.has_large_entropy_blob = huge_entropy_blob > 0.5;
    vmp_context.code_obscured_by_packing =
        (tiny_text_big_file > 0.5 && huge_entropy_blob > 0.5) ||
        executable_regions.empty();
    // Only semantic VM/interpreter runtimes are a VMP alternative. Generic
    // libraries such as logging, image or layout frameworks must not veto a
    // genuine dispatcher merely because their filename is familiar.
    vmp_context.known_runtime = r.known_vm_runtime;
    vmp_context.known_non_vm_framework =
        (r.known_runtime_framework && !r.known_vm_runtime) ||
        r.known_hook_framework;
    vmp_context.runtime_evidence_classes = r.runtime_evidence_classes;
    vmp_context.known_runtime_name = r.known_runtime_name;
    vmp_context.vmp_metadata_marker = vmp_metadata_hits >= 1;
    // VMP must not inherit intent from raw "linker" strings or generic
    // loader APIs.  Only the independently gated protection verdict may act
    // as supporting context, and it is counted once through the likely flag.
    vmp_context.custom_linker_marker = false;
    vmp_context.custom_linker_likely = r.possible_custom_linker;
    vmp_context.control_flow_obfuscation_likely =
        obf_arith_ratio > 0.28 && r.avg_exec_entropy > 6.8 &&
        (r.packer_score >= 0.55 || r.ollvm_score >= 0.40 ||
         r.strong_obf_score >= 0.55);

    for (const auto& sec : r.sections) {
        if ((sec.flags & SHF_EXECINSTR_VAL) == 0 || sec.size == 0) continue;
        if (sec.name == ".plt" || sec.name == ".plt.got" ||
            sec.name == ".iplt" || sec.name == ".init" || sec.name == ".fini") {
            if (sec.address <= UINT64_MAX - sec.size) {
                vmp_context.excluded_thunk_ranges.push_back(
                    AddressRange{sec.address, sec.address + sec.size});
            }
        }
    }
    for (const auto& function : r.defined_function_ranges) {
        const uint64_t end = function.address + function.size;
        const bool within_executable_region = std::any_of(
            executable_regions.begin(), executable_regions.end(),
            [&](const ExecutableRegionView& region) {
                if (region.virtual_address > UINT64_MAX - region.size) return false;
                const uint64_t region_end = region.virtual_address + region.size;
                return function.address >= region.virtual_address && end <= region_end;
            });
        if (within_executable_region) {
            vmp_context.excluded_thunk_ranges.push_back(
                AddressRange{function.address, end});
        }
    }
    if (dynamic_info.valid && !dynamic_info.jump_slot_vas.empty()) {
        auto dynamic_plt_ranges = find_dynamic_plt_branch_ranges(
            executable_regions, dynamic_info.jump_slot_vas);
        vmp_context.excluded_thunk_ranges.insert(
            vmp_context.excluded_thunk_ranges.end(),
            dynamic_plt_ranges.begin(), dynamic_plt_ranges.end());
    }

    r.vmp = analyze_vmp_regions(executable_regions, vmp_context);
    if (r.vmp.possible) {
        r.reasons.push_back("possible vmp dispatcher/handler loop");
    } else if (r.vmp.outcome == "VM_LIKE_INTERPRETER") {
        r.reasons.push_back("vmp-like branches explained by known runtime framework");
    } else if (r.vmp.outcome == "INCONCLUSIVE_PACKED") {
        r.reasons.push_back("vmp observability blocked by packing");
    } else if (r.vmp.outcome == "SUSPICIOUS_VM_STRUCTURE") {
        r.reasons.push_back("vmp-like dispatch signals");
    }

    r.strong_obf_score = clamp01(
        r.strong_obf_score +
        (r.vmp.possible ? 0.14 : r.vmp.structure_score * 0.06)
    );
    bool plain_known_runtime =
        r.known_runtime_framework &&
        r.vmp.outcome == "VM_LIKE_INTERPRETER" &&
        r.vmp.protection_intent_score < 0.50 &&
        !r.vmp.possible &&
        !r.possible_custom_linker &&
        !r.is_zip_container &&
        !r.rwx_segment &&
        !r.entry_in_writable_segment &&
        huge_entropy_blob <= 0.5 &&
        tiny_text_big_file <= 0.5;
    bool plain_known_hook =
        r.known_hook_framework &&
        !r.vmp.possible &&
        !r.possible_custom_linker &&
        !r.is_zip_container &&
        !r.rwx_segment &&
        !r.entry_in_writable_segment &&
        huge_entropy_blob <= 0.5 &&
        tiny_text_big_file <= 0.5;
    if (plain_known_runtime) {
        r.packer_score = std::min(r.packer_score, 0.44);
        r.ollvm_score = std::min(r.ollvm_score, 0.49);
        r.strong_obf_score = std::min(r.strong_obf_score, 0.49);
    }
    if (plain_known_hook) {
        r.packer_score = std::min(r.packer_score, 0.44);
        r.ollvm_score = std::min(r.ollvm_score, 0.49);
        r.strong_obf_score = std::min(r.strong_obf_score, 0.49);
    }

    if (r.known_hook_framework) {
        r.reasons.push_back("known hook framework: " + r.known_framework_name);
    }
    if (r.known_runtime_framework) {
        r.reasons.push_back("known runtime framework: " + r.known_runtime_name);
    }
    if (r.custom_linker.likely_protection()) {
        r.reasons.push_back("custom linker protection chain confirmed");
        r.reasons.push_back("independent ELF loader stages confirmed");
        r.reasons.push_back("protection-specific payload or identity evidence");
    } else if (r.custom_linker.loader_component()) {
        r.reasons.push_back("custom ELF loader component without protection proof");
        r.reasons.push_back("independent ELF loader stages confirmed");
    } else if (r.custom_linker.outcome ==
                   obfuscan::custom_linker::Outcome::ELF_INSPECTION_OR_HOOK &&
               r.custom_linker.hook_alternative) {
        r.reasons.push_back("ELF inspection and memory patching explained by hook framework");
    } else if (r.custom_linker.outcome ==
               obfuscan::custom_linker::Outcome::INCONCLUSIVE_PACKED) {
        r.reasons.push_back("custom linker analysis inconclusive because packing obscures code");
    }
    if (r.stripped) r.reasons.push_back("missing .symtab / stripped");
    if (r.rwx_segment) r.reasons.push_back("found RWX PT_LOAD segment");
    if (r.entry_in_writable_segment) r.reasons.push_back("entry point in writable segment");
    if (loader_hit > 0) r.reasons.push_back("runtime-sensitive imports hit=" + std::to_string(loader_hit));
    if (huge_entropy_blob > 0.5) r.reasons.push_back("large high-entropy blob detected");
    if (tiny_text_big_file > 0.5) r.reasons.push_back("tiny .text but large file");
    if (heavy_init_array > 0.5) r.reasons.push_back("large init_array entry count");
    if (low_string_density > 0.5) r.reasons.push_back("very low printable string density");
    if (r.avg_exec_entropy > 6.8) r.reasons.push_back("high executable segment entropy");
    if (branch_ratio > 0.18) r.reasons.push_back("high branch density in AArch64 text");
    if (indirect_branch_ratio > 0.015) r.reasons.push_back("high indirect branch density");
    if (obf_arith_ratio > 0.28) r.reasons.push_back("high arithmetic/logical opcode density");

    if (r.possible_custom_linker && r.vmp.possible) {
        r.final_label = "POSSIBLE_CUSTOM_LINKER_VMP";
    } else if (r.possible_custom_linker) {
        r.final_label = "POSSIBLE_CUSTOM_LINKER";
    } else if (plain_known_hook) {
        r.final_label = "KNOWN_HOOK_FRAMEWORK";
    } else if (r.custom_linker.loader_component()) {
        r.final_label = "CUSTOM_LOADER_COMPONENT";
    } else if (r.packer_score >= 0.68 ||
        (r.packer_score >= 0.62 && r.strong_obf_score >= 0.58)) {
        r.final_label = "POSSIBLE_PACKER";
    } else if (r.vmp.possible) {
        r.final_label = "POSSIBLE_VMP_OR_STRONG_OBF";
    } else if (r.strong_obf_score >= 0.70 && r.ollvm_score >= 0.52) {
        r.final_label = "POSSIBLE_OLLVM_OR_STRONG_OBF";
    } else if (r.strong_obf_score >= 0.68) {
        r.final_label = "STRONG_OBFUSCATION";
    } else if (r.ollvm_score >= 0.60) {
        r.final_label = "POSSIBLE_OLLVM";
    } else {
        r.final_label = "NORMAL_OR_LIGHT_OBF";
    }
    return r;
}

static void link_vmp_protected_clients(std::vector<AnalysisResult>& results) {
    std::vector<obfuscan::vmp_linkage::ProviderView> providers;
    providers.reserve(results.size());
    for (const auto& result : results) {
        providers.push_back({
            result.so_name,
            result.defined_exports,
            result.vmp.outcome == "LIKELY_VMP" && result.vmp.confidence == "HIGH",
            is_high_risk_result(result)
        });
    }

    for (auto& client : results) {
        // A library with its own high-confidence dispatcher remains a provider;
        // dependency evidence must not replace stronger local evidence.
        if (client.vmp.outcome == "LIKELY_VMP") continue;
        const auto evidence = obfuscan::vmp_linkage::find_protected_provider(
            client.needed_libraries, client.imports, providers);
        if (!evidence.matched()) continue;

        client.vmp_protected_client = true;
        client.vmp_provider_so = evidence.provider_so;
        client.vmp_needed_library = evidence.needed_library;
        client.vmp_shared_symbols = evidence.shared_symbols;
        client.final_label = "VMP_PROTECTED_CLIENT";

        // This is a dependency relationship, not proof that the client itself
        // owns a dispatcher.  Replace local heuristic candidates with a clean
        // relationship outcome and expose the graph evidence separately.
        VmpDeepResult linked;
        linked.analyzed = true;
        linked.observable = client.vmp.observable;
        linked.coverage = client.vmp.coverage;
        linked.outcome = "VMP_PROTECTED_CLIENT";
        linked.confidence = "HIGH";
        linked.profile = "DEPENDENCY_LINKED";
        client.vmp = std::move(linked);

        client.reasons.erase(
            std::remove_if(client.reasons.begin(), client.reasons.end(),
                [](const std::string& reason) {
                    return reason == "possible vmp dispatcher/handler loop" ||
                           reason == "vmp-like dispatch signals";
                }),
            client.reasons.end());
        client.reasons.push_back("imports protected VMP provider symbols");
    }
}

// =========================
// APK 读取
// =========================

struct ApkInputPath {
    std::string utf8;
#ifdef _WIN32
    std::wstring native;
#endif
};

struct ApkScanReport {
    std::vector<AnalysisResult> results;
    std::vector<ScanDiagnostic> diagnostics;
    std::string status = "OK";
    uint64_t apk_file_bytes = 0;
    uint64_t archive_entry_count = 0;
    uint64_t relevant_so_count = 0;
    uint64_t analyzed_so_count = 0;
    uint64_t skipped_so_count = 0;
    uint64_t declared_relevant_uncompressed_bytes = 0;
    uint64_t accepted_relevant_uncompressed_bytes = 0;
    uint64_t zip_metadata_peak_bytes = 0;
    uint64_t suppressed_diagnostic_count = 0;
};

struct ApkSoCandidate {
    mz_uint zip_index = 0;
    std::string name;
    uint64_t compressed_bytes = 0;
    uint64_t uncompressed_bytes = 0;
    bool encrypted = false;
    bool supported = false;
};

static void add_report_diagnostic(ApkScanReport& report,
                                  const std::string& severity,
                                  const std::string& code,
                                  const std::string& entry = std::string(),
                                  const std::string& detail = std::string(),
                                  uint64_t entry_index = 0,
                                  uint64_t compressed_bytes = 0,
                                  uint64_t uncompressed_bytes = 0,
                                  bool has_entry_index = false) {
    record_scan_diagnostic(
        report.diagnostics, report.suppressed_diagnostic_count,
        ScanDiagnostic{severity, code, entry, detail, entry_index,
                       compressed_bytes, uncompressed_bytes, has_entry_index});
}

static ApkScanReport analyze_arm64_sos_from_apk(const ApkInputPath &apk_path) {
    ApkScanReport report;

    std::error_code file_size_error;
#ifdef _WIN32
    const std::filesystem::path filesystem_path(apk_path.native);
#else
    const std::filesystem::path filesystem_path(apk_path.utf8);
#endif
    const std::uintmax_t file_size = std::filesystem::file_size(
        filesystem_path, file_size_error);
    if (!file_size_error) {
        report.apk_file_bytes = static_cast<uint64_t>(
            std::min<std::uintmax_t>(file_size, std::numeric_limits<uint64_t>::max()));
        if (file_size > obfuscan::ApkScanLimits::kMaxApkBytes) {
            report.status = "REJECTED";
            add_report_diagnostic(report, "error", "APK_FILE_SIZE_LIMIT", apk_path.utf8,
                                  std::to_string(file_size));
            return report;
        }
    }

    MinizAllocationBudget allocation_budget{
        static_cast<size_t>(obfuscan::ApkScanLimits::kMaxZipMetadataBytes)};
    mz_zip_archive zip{};
    configure_bounded_miniz_allocator(zip, allocation_budget);
    ZipReaderScope scope{&zip, nullptr, false};
#ifdef _WIN32
    MZ_FILE *apk_file = _wfopen(apk_path.native.c_str(), L"rb");
    scope.external_file = apk_file;
    const bool input_file_opened = apk_file != nullptr;
    const bool zip_opened = apk_file && mz_zip_reader_init_cfile(
        &zip, apk_file, 0, MZ_ZIP_FLAG_DO_NOT_SORT_CENTRAL_DIRECTORY);
#else
    const bool input_file_opened = true;
    const bool zip_opened = mz_zip_reader_init_file(
        &zip, apk_path.utf8.c_str(), MZ_ZIP_FLAG_DO_NOT_SORT_CENTRAL_DIRECTORY);
#endif
    if (!zip_opened) {
        report.status = allocation_budget.limit_hit ? "REJECTED" : "ERROR";
        add_report_diagnostic(
            report, "error",
            allocation_budget.limit_hit ? "APK_ZIP_METADATA_LIMIT" : "APK_OPEN_FAILED",
            apk_path.utf8,
            input_file_opened ? miniz_error_detail(zip) : "unable to open input file");
        report.zip_metadata_peak_bytes = allocation_budget.peak_bytes;
        return report;
    }
    scope.initialized = true;

    mz_uint file_count = mz_zip_reader_get_num_files(&zip);
    report.archive_entry_count = file_count;
    if (file_count > obfuscan::ApkScanLimits::kMaxZipEntries) {
        report.status = "REJECTED";
        add_report_diagnostic(report, "error", "APK_ENTRY_LIMIT", apk_path.utf8,
                              std::to_string(file_count));
        report.zip_metadata_peak_bytes = allocation_budget.peak_bytes;
        return report;
    }

    std::vector<ApkSoCandidate> candidates;
    candidates.reserve(static_cast<size_t>(
        obfuscan::ApkScanLimits::kMaxCandidateSoEntries));
    for (mz_uint i = 0; i < file_count; ++i) {
        mz_zip_archive_file_stat st{};
        if (!mz_zip_reader_file_stat(&zip, i, &st)) {
            add_report_diagnostic(report, "warning", "ZIP_ENTRY_STAT_FAILED", "",
                                  miniz_error_detail(zip), i, 0, 0, true);
            continue;
        }
        if (st.m_is_directory) continue;

        std::string name = st.m_filename;
        const bool is_apk_so_path = starts_with(name, "lib/arm64-v8a/");
        const bool is_hap_so_path = starts_with(name, "libs/arm64-v8a/");
        if (!is_apk_so_path && !is_hap_so_path && !starts_with(name, "assets/")) continue;
        if (!ends_with(name, ".so")) continue;

        ++report.relevant_so_count;
        report.declared_relevant_uncompressed_bytes = obfuscan::saturating_add_u64(
            report.declared_relevant_uncompressed_bytes, st.m_uncomp_size);
        if (candidates.size() < obfuscan::ApkScanLimits::kMaxCandidateSoEntries) {
            candidates.push_back({i, std::move(name), st.m_comp_size, st.m_uncomp_size,
                                  st.m_is_encrypted != 0, st.m_is_supported != 0});
        }
    }

    if (report.relevant_so_count > obfuscan::ApkScanLimits::kMaxCandidateSoEntries) {
        report.status = "REJECTED";
        report.skipped_so_count = report.relevant_so_count;
        add_report_diagnostic(report, "error", "SO_CANDIDATE_LIMIT", apk_path.utf8,
                              std::to_string(report.relevant_so_count));
        report.zip_metadata_peak_bytes = allocation_budget.peak_bytes;
        return report;
    }

    const obfuscan::ZipPayloadPolicy policy{
        obfuscan::ApkScanLimits::kMaxSingleSoBytes,
        obfuscan::ApkScanLimits::kMaxCompressionRatio,
        obfuscan::ApkScanLimits::kCompressionRatioFloorBytes,
    };

    for (const auto& candidate : candidates) {
        const obfuscan::ZipPayloadDecision decision = obfuscan::evaluate_zip_payload(
            {candidate.compressed_bytes, candidate.uncompressed_bytes,
             candidate.encrypted, candidate.supported},
            policy);
        if (decision != obfuscan::ZipPayloadDecision::kAllow) {
            ++report.skipped_so_count;
            add_report_diagnostic(
                report, "warning",
                "SO_" + std::string(obfuscan::zip_payload_decision_code(decision)),
                candidate.name, "", candidate.zip_index, candidate.compressed_bytes,
                candidate.uncompressed_bytes, true);
            continue;
        }

        if (!obfuscan::fits_cumulative_budget(
                report.accepted_relevant_uncompressed_bytes,
                candidate.uncompressed_bytes,
                obfuscan::ApkScanLimits::kMaxTotalRelevantSoBytes)) {
            ++report.skipped_so_count;
            add_report_diagnostic(report, "warning", "SO_TOTAL_UNCOMPRESSED_LIMIT",
                                  candidate.name, "", candidate.zip_index,
                                  candidate.compressed_bytes,
                                  candidate.uncompressed_bytes, true);
            continue;
        }
        report.accepted_relevant_uncompressed_bytes += candidate.uncompressed_bytes;

        std::vector<uint8_t> data;
        try {
            data.resize(static_cast<size_t>(candidate.uncompressed_bytes));
        } catch (const std::bad_alloc&) {
            ++report.skipped_so_count;
            add_report_diagnostic(report, "warning", "SO_ALLOCATION_FAILED",
                                  candidate.name, "", candidate.zip_index,
                                  candidate.compressed_bytes,
                                  candidate.uncompressed_bytes, true);
            continue;
        }

        if (!mz_zip_reader_extract_to_mem(&zip, candidate.zip_index,
                                          data.data(), data.size(), 0)) {
            ++report.skipped_so_count;
            add_report_diagnostic(report, "warning", "SO_EXTRACT_FAILED",
                                  candidate.name, miniz_error_detail(zip),
                                  candidate.zip_index, candidate.compressed_bytes,
                                  candidate.uncompressed_bytes, true);
            continue;
        }

        try {
            report.results.emplace_back(analyze_so(
                candidate.name, data, &report.diagnostics,
                &report.suppressed_diagnostic_count));
        } catch (const std::bad_alloc&) {
            ++report.skipped_so_count;
            add_report_diagnostic(report, "warning", "SO_ANALYSIS_ALLOCATION_FAILED",
                                  candidate.name, "", candidate.zip_index,
                                  candidate.compressed_bytes,
                                  candidate.uncompressed_bytes, true);
        } catch (const std::exception& error) {
            ++report.skipped_so_count;
            add_report_diagnostic(report, "warning", "SO_ANALYSIS_FAILED",
                                  candidate.name, error.what(), candidate.zip_index,
                                  candidate.compressed_bytes,
                                  candidate.uncompressed_bytes, true);
        } catch (...) {
            ++report.skipped_so_count;
            add_report_diagnostic(report, "warning", "SO_ANALYSIS_FAILED",
                                  candidate.name, "unknown exception", candidate.zip_index,
                                  candidate.compressed_bytes,
                                  candidate.uncompressed_bytes, true);
        }
    }

    report.analyzed_so_count = report.results.size();
    link_vmp_protected_clients(report.results);
    report.zip_metadata_peak_bytes = allocation_budget.peak_bytes;
    if (!report.diagnostics.empty() || report.suppressed_diagnostic_count != 0) {
        report.status = "PARTIAL";
    }
    return report;
}

// =========================
// 输出
// =========================

static void print_usage(const char *prog) {
    std::cout << "Usage:\n";
    std::cout << "  " << prog << " <apk_or_hap_path> [--en]\n\n";
    std::cout << "Options:\n";
    std::cout << "  --en    Output in English\n\n";
    std::cout << "Examples:\n";
    std::cout << "  " << prog << " demo.apk\n";
    std::cout << "  " << prog << " demo.hap --en\n";
}

static std::string label_to_zh(const std::string &label) {
    if (label == "VMP_PROTECTED_CLIENT") return "VMP保护库关联客户端";
    if (label == "POSSIBLE_CUSTOM_LINKER_VMP") return "疑似自定义Linker+VMP加固";
    if (label == "POSSIBLE_CUSTOM_LINKER") return "疑似自定义Linker加固";
    if (label == "KNOWN_HOOK_FRAMEWORK") return "Hook/Trampoline框架";
    if (label == "CUSTOM_LOADER_COMPONENT") return "自定义ELF Loader组件（未证实加固）";
    if (label == "POSSIBLE_PACKER") return "疑似加壳";
    if (label == "POSSIBLE_VMP_OR_STRONG_OBF") return "疑似 VMP/强混淆";
    if (label == "POSSIBLE_OLLVM_OR_STRONG_OBF") return "疑似强混淆/OLLVM";
    if (label == "STRONG_OBFUSCATION") return "疑似强混淆";
    if (label == "POSSIBLE_OLLVM") return "疑似 OLLVM";
    if (label == "NORMAL_OR_LIGHT_OBF") return "正常或轻度混淆";
    if (label == "INVALID_ELF") return "文件头不是标准ELF";
    if (label == "UNSUPPORTED_OR_NOT_AARCH64") return "不是 64 位 ARM so";
    if (label == "ZIP_SO_CONTAINER") return "SO容器文件";
    return "未知";
}

static std::string label_to_en(const std::string &label) {
    if (label == "VMP_PROTECTED_CLIENT") return "VMP-Protected Client";
    if (label == "POSSIBLE_CUSTOM_LINKER_VMP") return "Likely Custom Linker + VMP Protection";
    if (label == "POSSIBLE_CUSTOM_LINKER") return "Likely Custom Linker Protection";
    if (label == "KNOWN_HOOK_FRAMEWORK") return "Hook/Trampoline Framework";
    if (label == "CUSTOM_LOADER_COMPONENT") return "Custom ELF Loader Component (Protection Not Established)";
    if (label == "POSSIBLE_PACKER") return "Possible Packer";
    if (label == "POSSIBLE_VMP_OR_STRONG_OBF") return "Possible VMP/Strong Obfuscation";
    if (label == "POSSIBLE_OLLVM_OR_STRONG_OBF") return "Possible OLLVM/Strong Obfuscation";
    if (label == "STRONG_OBFUSCATION") return "Strong Obfuscation";
    if (label == "POSSIBLE_OLLVM") return "Possible OLLVM";
    if (label == "NORMAL_OR_LIGHT_OBF") return "Normal or Light Obfuscation";
    if (label == "INVALID_ELF") return "Invalid ELF Header";
    if (label == "UNSUPPORTED_OR_NOT_AARCH64") return "Not a 64-bit ARM SO";
    if (label == "ZIP_SO_CONTAINER") return "ZIP Container";
    return "Unknown";
}

static std::string risk_level_zh(const AnalysisResult &r) {
    if (is_high_risk_result(r)) return "高";
    if (is_medium_risk_result(r)) return "中";
    return "低";
}

static std::string risk_level_en(const AnalysisResult &r) {
    if (is_high_risk_result(r)) return "High";
    if (is_medium_risk_result(r)) return "Medium";
    return "Low";
}

static std::string reason_to_zh(const std::string &reason) {
    if (reason == "embedded C++ ABI runtime range excluded from VMP candidates") return "已识别并排除内嵌 C++ ABI/反修饰运行时代码区，避免把语法跳表误判为VMP";
    if (reason == "protection VM interpreter marker cluster") return "同时发现JavaVMP与解释器包装器标记，作为保护型VM辅助证据";
    if (reason == "imports protected VMP provider symbols") return "通过DT_NEEDED及共享符号确认调用VMP保护库";
    if (reason == "loaded from assets path") return "位于 assets 路径，可能是运行时释放或加载的库";
    if (reason == "missing .symtab / stripped") return "已裁剪符号表";
    if (reason == "found RWX PT_LOAD segment") return "发现可读可写可执行段";
    if (reason == "entry point in writable segment") return "ELF入口落在可写段";
    if (reason == "large high-entropy blob detected") return "存在大块高熵数据";
    if (reason == "tiny .text but large file") return "代码段很小但文件较大";
    if (reason == "large init_array entry count") return ".init_array 初始化入口较多";
    if (reason.rfind("known hook framework:", 0) == 0) return "识别到Hook/Trampoline框架";
    if (reason.rfind("known runtime framework:", 0) == 0) return "识别到常见三方运行时/框架";
    if (reason == "vmp-like branches explained by hook framework") return "VMP相似跳转由Hook/Trampoline框架解释，不按VMP处理";
    if (reason == "vmp-like branches explained by known runtime framework") return "VMP相似跳转由常见运行时/框架解释，不按VMP处理";
    if (reason == "vmp metadata marker present") return "存在VMP元数据标记";
    if (reason == "custom linker with vmp-like dispatcher") return "自定义Linker样本中存在VMP分发相似窗口";
    if (reason == "custom linker protection chain confirmed") return "自定义Linker装载链与加固证据均已通过门控";
    if (reason == "custom ELF loader component without protection proof") return "检测到自定义ELF Loader组件，但没有足够的加固证据";
    if (reason == "independent ELF loader stages confirmed") return "已确认ELF解析、重定位、依赖/符号解析等独立装载阶段";
    if (reason == "protection-specific payload or identity evidence") return "存在加固专用payload或精确身份标记";
    if (reason == "ELF inspection and memory patching explained by hook framework") return "ELF检查与内存修改行为可由Hook框架解释，不作为自定义Linker加固";
    if (reason == "custom linker analysis inconclusive because packing obscures code") return "代码被打包隐藏，暂时无法确认自定义Linker";
    if (reason == "very low printable string density") return "可见字符串很少";
    if (reason == "high executable segment entropy") return "可执行段熵较高";
    if (reason == "high branch density in AArch64 text") return "分支跳转密度高";
    if (reason == "high indirect branch density") return "间接跳转偏多";
    if (reason == "high arithmetic/logical opcode density") return "算术逻辑指令密度高";
    if (reason == "so entry is actually a zip container") return "该SO条目实际是ZIP容器";
    if (reason == "capstone init failed") return "Capstone 初始化失败";

    if (reason.rfind("runtime-sensitive imports hit=", 0) == 0) {
        return "存在运行时敏感导入函数";
    }
    if (reason == "vmp-like dispatch signals") return "存在一定 VMP 分发器相似特征";
    if (reason == "possible vmp dispatcher/handler loop") return "存在疑似VMP分发器/handler循环";
    return reason;
}

static std::string reason_to_en(const std::string &reason) {
    if (reason == "embedded C++ ABI runtime range excluded from VMP candidates") return "Embedded C++ ABI/demangler runtime range excluded from VMP candidates";
    if (reason == "protection VM interpreter marker cluster") return "JavaVMP and interpreter-wrapper markers provide protection-VM evidence";
    if (reason == "imports protected VMP provider symbols") return "Confirmed client of a VMP provider through DT_NEEDED and shared symbols";
    if (reason == "loaded from assets path") return "Located under assets path, possibly released or loaded at runtime";
    if (reason == "missing .symtab / stripped") return "Symbol table stripped";
    if (reason == "found RWX PT_LOAD segment") return "Found RWX PT_LOAD segment";
    if (reason == "entry point in writable segment") return "ELF entry point is in a writable segment";
    if (reason == "large high-entropy blob detected") return "Large high-entropy blob detected";
    if (reason == "tiny .text but large file") return "Small .text but large file";
    if (reason == "large init_array entry count") return "Large .init_array entry count";
    if (reason.rfind("known hook framework:", 0) == 0) return "Known Hook/Trampoline framework detected";
    if (reason.rfind("known runtime framework:", 0) == 0) return "Known third-party runtime/framework detected";
    if (reason == "vmp-like branches explained by hook framework") return "VMP-like branches explained by Hook/Trampoline framework; not treated as VMP";
    if (reason == "vmp-like branches explained by known runtime framework") return "VMP-like branches explained by known runtime/framework; not treated as VMP";
    if (reason == "vmp metadata marker present") return "VMP metadata marker present";
    if (reason == "custom linker with vmp-like dispatcher") return "Custom Linker sample contains VMP-like dispatcher windows";
    if (reason == "custom linker protection chain confirmed") return "Custom Linker loader chain and protection evidence passed the gate";
    if (reason == "custom ELF loader component without protection proof") return "Custom ELF loader component detected without sufficient protection evidence";
    if (reason == "independent ELF loader stages confirmed") return "Independent ELF parsing, relocation, and dependency/symbol-resolution stages confirmed";
    if (reason == "protection-specific payload or identity evidence") return "Protection-specific payload or precise identity evidence present";
    if (reason == "ELF inspection and memory patching explained by hook framework") return "ELF inspection and memory patching are explained by the Hook framework, not Custom Linker protection";
    if (reason == "custom linker analysis inconclusive because packing obscures code") return "Packing obscures the code; Custom Linker analysis is inconclusive";
    if (reason == "very low printable string density") return "Very low printable string density";
    if (reason == "high executable segment entropy") return "High executable segment entropy";
    if (reason == "high branch density in AArch64 text") return "High branch density";
    if (reason == "high indirect branch density") return "High indirect branch density";
    if (reason == "high arithmetic/logical opcode density") return "High arithmetic/logical opcode density";
    if (reason == "so entry is actually a zip container") return "SO entry is actually a ZIP container";
    if (reason == "capstone init failed") return "Capstone initialization failed";

    if (reason.rfind("runtime-sensitive imports hit=", 0) == 0) {
        return "Runtime-sensitive imports";
    }
    if (reason == "vmp-like dispatch signals") return "VMP-like dispatch signals";
    if (reason == "possible vmp dispatcher/handler loop") return "Possible VMP dispatcher/handler loop";
    return reason;
}

static std::string build_summary_zh(const AnalysisResult &r) {
    if (r.final_label == "VMP_PROTECTED_CLIENT") {
        return "该 so 自身未被判定含 VMP dispatcher；但其 DT_NEEDED 明确依赖高置信 VMP 保护库，且导入符号与该保护库的定义导出相交，因此判定为受该 VMP 保护链路服务的客户端。";
    }
    if (r.final_label == "ZIP_SO_CONTAINER") {
        return "该 so 文件在 APK 中并不是裸 ELF，而是一个 ZIP 容器，真实的 native 库可能位于其内层或运行时再释放。";
    }
    if (r.is_zip_container && r.inner_elf_found && r.final_label == "NORMAL_OR_LIGHT_OBF") {
        return "该 so 在 APK 中是 ZIP 容器，已自动提取内层 ELF 进行分析，当前看更像正常发布版本或轻度混淆。";
    }
    if (r.is_zip_container && r.inner_elf_found) {
        return "该 so 在 APK 中是 ZIP 容器，已自动提取内层 ELF 进行分析，内层样本存在明显保护或混淆特征。";
    }
    if (r.final_label == "POSSIBLE_CUSTOM_LINKER_VMP") {
        return "该 so 同时存在自定义 Linker/Loader 加固和 VMP 元数据/分发特征，静态上看属于组合式 native 保护。";
    }
    if (r.final_label == "POSSIBLE_CUSTOM_LINKER") {
        return "该 so 存在较明显的自定义 Linker/Loader 加固特征，可能包含手动 ELF 映射、重定位、解密装载或绕过系统 linker 的逻辑。";
    }
    if (r.final_label == "KNOWN_HOOK_FRAMEWORK") {
        return "该 so 更像 Hook/Trampoline 框架或运行时修改组件，存在可疑跳转但当前不按 VMP 或加壳处理。";
    }
    if (r.final_label == "CUSTOM_LOADER_COMPONENT") {
        return "该 so 实现了较完整的自定义 ELF 装载链，包括解析、重定位及依赖/符号处理；但尚未发现足以证明加固的受保护 payload 或专用身份，因此只判为 Loader 组件。";
    }
    if (r.final_label == "POSSIBLE_PACKER") {
        return "该 so 存在较明显的壳或加载器特征，静态上看像是经过了解密装载或入口保护处理。";
    }
    if (r.final_label == "POSSIBLE_VMP_OR_STRONG_OBF") {
        return "该 so 存在较明显的 VMP 或解释器式分发特征，建议作为高优先级样本进一步确认。";
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

static std::string build_summary_en(const AnalysisResult &r) {
    if (r.final_label == "VMP_PROTECTED_CLIENT") {
        return "This SO is not claimed to contain its own VMP dispatcher. Its DT_NEEDED entry points to a high-confidence VMP provider and its imports overlap that provider's defined exports, so it is classified as a client of the protected execution path.";
    }
    if (r.final_label == "ZIP_SO_CONTAINER") {
        return "This SO entry is not a raw ELF but a ZIP container. The actual native library may be inside or released at runtime.";
    }
    if (r.is_zip_container && r.inner_elf_found && r.final_label == "NORMAL_OR_LIGHT_OBF") {
        return "This SO is a ZIP container in APK. Inner ELF extracted and analyzed. Appears to be normal or lightly obfuscated.";
    }
    if (r.is_zip_container && r.inner_elf_found) {
        return "This SO is a ZIP container in APK. Inner ELF extracted and analyzed. Inner sample shows significant protection or obfuscation.";
    }
    if (r.final_label == "POSSIBLE_CUSTOM_LINKER_VMP") {
        return "This SO shows both Custom Linker/Loader protection and VMP metadata/dispatch signals, indicating combined native protection.";
    }
    if (r.final_label == "POSSIBLE_CUSTOM_LINKER") {
        return "This SO shows obvious Custom Linker/Loader protection signals, possibly including manual ELF mapping, relocation, decrypt-loading, or bypassing the system linker.";
    }
    if (r.final_label == "KNOWN_HOOK_FRAMEWORK") {
        return "This SO looks like a Hook/Trampoline framework or runtime patching component. Suspicious jumps are present but it is not treated as VMP or packer.";
    }
    if (r.final_label == "CUSTOM_LOADER_COMPONENT") {
        return "This SO implements a substantial custom ELF loading chain, including parsing, relocation, and dependency/symbol handling, but no protected payload or protection-specific identity establishes hardening.";
    }
    if (r.final_label == "POSSIBLE_PACKER") {
        return "This SO shows obvious packer or loader characteristics, likely processed with decryption loading or entry protection.";
    }
    if (r.final_label == "POSSIBLE_VMP_OR_STRONG_OBF") {
        return "This SO shows obvious VMP or interpreter-style dispatch characteristics and should be prioritized for manual confirmation.";
    }
    if (r.final_label == "POSSIBLE_OLLVM_OR_STRONG_OBF") {
        return "This SO shows significant obfuscation characteristics, possibly using OLLVM, control flow flattening or other strong protections.";
    }
    if (r.final_label == "STRONG_OBFUSCATION") {
        return "This SO shows obvious obfuscation traces, but the specific protection type cannot be confirmed by static features alone.";
    }
    if (r.final_label == "POSSIBLE_OLLVM") {
        return "This SO shows anomalies in control flow and instruction distribution, possibly using OLLVM-style obfuscation.";
    }
    if (r.final_label == "NORMAL_OR_LIGHT_OBF") {
        return "This SO appears to be a normal release or lightly obfuscated. No strong packer or heavy protection detected.";
    }
    if (r.final_label == "INVALID_ELF") {
        return "File header is not a valid ELF.";
    }
    if (r.final_label == "UNSUPPORTED_OR_NOT_AARCH64") {
        return "Not a 64-bit ARM SO.";
    }
    return "Static feature analysis completed.";
}

static std::string build_advice_zh(const AnalysisResult &r) {
    if (r.final_label == "VMP_PROTECTED_CLIENT") {
        return "建议从该客户端对共享符号的调用点入手，跨库跟踪到VMP provider；不要在客户端内盲找dispatcher。";
    }
    if (r.possible_custom_linker && r.vmp.possible) {
        return "建议先沿自定义 linker 的映射/解密/重定位流程找到真实代码区，再定位 VMP 元数据、dispatcher、handler 表和间接跳转链路。";
    }
    if (r.final_label == "KNOWN_HOOK_FRAMEWORK") {
        return "建议按 Hook/Trampoline 框架复核导出符号、入口和 inline hook 跳板，不作为 VMP 优先样本。";
    }
    if (r.final_label == "CUSTOM_LOADER_COMPONENT") {
        return "建议沿 ELF 解析、重定位和构造器调用链确认它服务于插件/运行时加载还是保护流程；在找到解密 payload 或明确保护关系前，不应直接按加固处理。";
    }
    if (r.possible_custom_linker) {
        return "建议优先查看 mmap/mprotect/open/read/dlopen/dlsym 调用链、ELF Program Header/Dynamic 段解析、重定位处理和解密后的内存映射。";
    }
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

static std::string build_advice_en(const AnalysisResult &r) {
    if (r.final_label == "VMP_PROTECTED_CLIENT") {
        return "Recommended: start from the client's shared-symbol call sites and follow them into the VMP provider; do not assume a dispatcher exists inside the client.";
    }
    if (r.possible_custom_linker && r.vmp.possible) {
        return "Recommended: follow the custom linker mapping/decryption/relocation flow to the real code region, then locate VMP metadata, dispatcher, handler tables and indirect jumps.";
    }
    if (r.final_label == "KNOWN_HOOK_FRAMEWORK") {
        return "Recommended: review exported symbols, entries and inline-hook trampolines as a Hook/Trampoline framework, not as a VMP-priority sample.";
    }
    if (r.final_label == "CUSTOM_LOADER_COMPONENT") {
        return "Recommended: trace ELF parsing, relocation, and constructor calls to determine whether this serves plugin/runtime loading or protection; do not call it hardening without decrypted payload or a precise protection relationship.";
    }
    if (r.possible_custom_linker) {
        return "Recommended: inspect mmap/mprotect/open/read/dlopen/dlsym call chains, ELF Program Header/Dynamic parsing, relocation handling, and decrypted memory mappings.";
    }
    if (r.vmp.possible) {
        return "Recommended: focus on entry functions, dispatcher loops, handler tables, bytecode data sections and indirect jump chains.";
    }
    if (r.final_label == "POSSIBLE_PACKER") {
        return "Recommended: manually inspect init_array, JNI_OnLoad, and mprotect/mmap/dlopen related logic.";
    }
    if (r.final_label == "POSSIBLE_OLLVM_OR_STRONG_OBF" || r.final_label == "POSSIBLE_OLLVM") {
        return "Recommended: use disassembly and CFG to confirm control flow flattening, opaque predicates or instruction substitution.";
    }
    if (r.final_label == "STRONG_OBFUSCATION") {
        return "Recommended: further inspect entry functions, key exports and suspicious high-entropy regions.";
    }
    if (r.final_label == "ZIP_SO_CONTAINER") {
        return "Recommended: analyze inner resources or the actual SO released at runtime.";
    }
    return "May deprioritize this sample. Manual review if necessary.";
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

static std::string vmp_judgment_zh(const VmpDeepResult& vmp) {
    if (vmp.outcome == "VMP_PROTECTED_CLIENT") return "依赖高置信VMP保护库的客户端（自身未检出dispatcher）";
    if (vmp.outcome == "LIKELY_VMP") return "疑似VMP保护";
    if (vmp.outcome == "VM_LIKE_INTERPRETER") return "存在VM结构，更像合法解释器/运行时";
    if (vmp.outcome == "SUSPICIOUS_VM_STRUCTURE") return "存在可疑VM结构，保护意图证据不足";
    if (vmp.outcome == "INCONCLUSIVE_PACKED") return "打包/加密阻断静态观察，VMP不可判定";
    if (vmp.outcome == "PARTIAL_ANALYSIS") return "扫描不完整，VMP不可判定";
    if (vmp.outcome == "NO_EXECUTABLE_CODE") return "无可观察执行代码，VMP不可判定";
    if (vmp.outcome == "ANALYSIS_ERROR") return "VMP分析失败";
    if (vmp.outcome == "NO_VMP_EVIDENCE") return "覆盖范围内未见结构性VMP证据";
    return "未完成VMP分析";
}

static std::string vmp_judgment_en(const VmpDeepResult& vmp) {
    if (vmp.outcome == "VMP_PROTECTED_CLIENT") return "Client of a high-confidence VMP provider; no local dispatcher is claimed";
    if (vmp.outcome == "LIKELY_VMP") return "Likely VMP protection";
    if (vmp.outcome == "VM_LIKE_INTERPRETER") return "VM structure present; better explained by a legitimate runtime";
    if (vmp.outcome == "SUSPICIOUS_VM_STRUCTURE") return "Suspicious VM structure; insufficient protection-intent evidence";
    if (vmp.outcome == "INCONCLUSIVE_PACKED") return "Packing/encryption blocks observation; VMP is inconclusive";
    if (vmp.outcome == "PARTIAL_ANALYSIS") return "Partial scan; VMP is inconclusive";
    if (vmp.outcome == "NO_EXECUTABLE_CODE") return "No observable executable code; VMP is inconclusive";
    if (vmp.outcome == "ANALYSIS_ERROR") return "VMP analysis failed";
    if (vmp.outcome == "NO_VMP_EVIDENCE") return "No structural VMP evidence in the covered code";
    return "VMP analysis was not completed";
}

static std::string vmp_confidence_zh(const std::string& value) {
    if (value == "HIGH") return "高";
    if (value == "MEDIUM") return "中";
    if (value == "LOW") return "低";
    return "未知";
}

static std::string vmp_profile_zh(const std::string& value) {
    if (value == "DEPENDENCY_LINKED") return "跨SO依赖关联";
    if (value == "REGISTER_DISPATCH") return "寄存器/表分发";
    if (value == "DIRECT_THREADED") return "direct-threaded";
    if (value == "CALL_THREADED") return "call-threaded";
    if (value == "RETURN_THREADED") return "return-threaded";
    if (value == "CONDITIONAL_DISPATCH") return "条件链分发";
    if (value == "THREADED_TRAMPOLINE") return "线程化跳板/调用边";
    if (value == "MIXED") return "混合分发";
    return "未识别";
}

static std::string vmp_profile_en(const std::string& value) {
    if (value == "DEPENDENCY_LINKED") return "Cross-SO dependency link";
    if (value == "REGISTER_DISPATCH") return "Register/table dispatch";
    if (value == "DIRECT_THREADED") return "Direct-threaded";
    if (value == "CALL_THREADED") return "Call-threaded";
    if (value == "RETURN_THREADED") return "Return-threaded";
    if (value == "CONDITIONAL_DISPATCH") return "Conditional-chain dispatch";
    if (value == "THREADED_TRAMPOLINE") return "Threaded trampoline/call edge";
    if (value == "MIXED") return "Mixed dispatch";
    return "Unidentified";
}

static std::string vmp_trait_zh(const std::string& value) {
    if (value == "VPC_FETCH") return "VPC/VIP取指";
    if (value == "VPC_ADVANCE") return "VPC/VIP推进";
    if (value == "OPCODE_TO_TARGET_DATAFLOW") return "opcode到handler目标数据流";
    if (value == "HANDLER_POINTER_FETCH") return "从VPC直接取handler指针";
    if (value == "TARGET_TABLE_LOAD") return "handler目标表读取";
    if (value == "BACK_EDGE") return "控制流回边";
    if (value == "SHARED_VM_CONTEXT") return "共享VM上下文";
    if (value == "COMPARE_CHAIN") return "条件比较链";
    return value;
}

static std::string vmp_signal_to_en(const std::string &signal) {
    if (signal == "重复出现高置信度取字节码-推进VIP-br分发窗口") return "Repeated high-confidence bytecode fetch-advance VIP-br dispatch window";
    if (signal == "出现多处高置信度取字节码-br分发窗口") return "Multiple high-confidence bytecode fetch-br dispatch windows";
    if (signal == "同一VIP寄存器重复出现") return "Same VIP register repeated";
    if (signal == "疑似VIP寄存器重复出现") return "Possible VIP register repeated";
    if (signal == "同一br目标寄存器重复作为分发出口") return "Same br target register repeated as dispatch exit";
    if (signal == "疑似固定分发寄存器") return "Possible fixed dispatch register";
    if (signal == "br分发指令数量偏高") return "High br dispatch instruction count";
    if (signal == "存在一定数量的br分发指令") return "Some br dispatch instructions present";
    if (signal == "中等置信度解释器窗口较多") return "Multiple medium-confidence interpreter windows";
    if (signal == "存在较大高熵疑似字节码/handler数据区") return "Large high-entropy bytecode/handler data section";
    if (signal == "字节/半字读取比例偏高") return "High byte/half-word load ratio";
    if (signal == "位运算/比较密度偏高") return "High bitwise operation/compare density";
    if (signal == "导入较少且存在早期初始化入口") return "Few imports with early initialization entries";
    if (signal == "blr占优，更像虚表/函数指针调用") return "BLR dominant, more like vtable/function pointer calls";
    if (signal == "存在VMP元数据标记") return "VMP metadata marker present";
    if (signal == "自定义Linker样本中存在VMP分发相似窗口") return "Custom Linker sample contains VMP-like dispatcher windows";
    if (starts_with(signal, "发现去重后的强分发数据流候选=")) return "Deduplicated strong dispatch-dataflow candidates=" + signal.substr(signal.find('=') + 1);
    if (starts_with(signal, "opcode到handler目标存在数据依赖候选=")) return "Opcode-to-handler target dataflow candidates=" + signal.substr(signal.find('=') + 1);
    if (starts_with(signal, "多个独立候选共享VPC/VIP寄存器=")) return "Independent candidates sharing a VPC/VIP register=" + signal.substr(signal.find('=') + 1);
    if (starts_with(signal, "候选访问共享VM上下文=")) return "Candidates accessing shared VM context=" + signal.substr(signal.find('=') + 1);
    if (starts_with(signal, "候选控制流存在回边=")) return "Candidates with control-flow back edges=" + signal.substr(signal.find('=') + 1);
    if (starts_with(signal, "识别到call-threaded间接调用候选=")) return "Call-threaded indirect-call candidates=" + signal.substr(signal.find('=') + 1);
    if (starts_with(signal, "识别到return-threaded候选=")) return "Return-threaded candidates=" + signal.substr(signal.find('=') + 1);
    if (starts_with(signal, "识别到条件链分发候选=")) return "Conditional-chain dispatch candidates=" + signal.substr(signal.find('=') + 1);
    if (starts_with(signal, "识别到线程化跳板候选=")) return "Threaded trampoline candidates=" + signal.substr(signal.find('=') + 1);
    if (starts_with(signal, "已隔离普通switch跳表替代解释=")) return "Excluded ordinary switch jump-table explanations=" + signal.substr(signal.find('=') + 1);
    if (starts_with(signal, "已隔离vtable/函数指针调用替代解释=")) return "Excluded vtable/function-pointer explanations=" + signal.substr(signal.find('=') + 1);
    if (starts_with(signal, "存在合法解释器/运行时替代解释: ")) return "Legitimate interpreter/runtime alternative: " + signal.substr(signal.find(':') + 2);
    if (signal == "存在保护型VMP元数据辅助证据") return "Protection-specific VMP metadata is present";
    if (signal == "打包/加密降低静态可观测性") return "Packing/encryption reduces static observability";
    return signal;
}

static void print_vmp_json_cn(const AnalysisResult& r,
                              const char* indent,
                              const char* nl) {
    const auto& v = r.vmp;
    std::cout << indent << "\"VMP判断\": \"" << json_escape(vmp_judgment_zh(v)) << "\"," << nl;
    std::cout << indent << "\"VMP状态码\": \"" << json_escape(v.outcome) << "\"," << nl;
    std::cout << indent << "\"VMP置信度\": \"" << json_escape(vmp_confidence_zh(v.confidence)) << "\"," << nl;
    std::cout << indent << "\"VMP类型\": \"" << json_escape(vmp_profile_zh(v.profile)) << "\"," << nl;
    std::cout << indent << "\"VMP分数\": " << std::fixed << std::setprecision(4) << v.score << "," << nl;
    std::cout << indent << "\"VM结构分数\": " << std::fixed << std::setprecision(4) << v.structure_score << "," << nl;
    std::cout << indent << "\"保护意图分数\": " << std::fixed << std::setprecision(4) << v.protection_intent_score << "," << nl;
    std::cout << indent << "\"替代解释扣分\": " << std::fixed << std::setprecision(4) << v.alternative_penalty << "," << nl;
    std::cout << indent << "\"VMP扫描覆盖率\": " << std::fixed << std::setprecision(4) << v.coverage << "," << nl;
    std::cout << indent << "\"VMP可观测\": " << (v.observable ? "true" : "false") << "," << nl;

    std::cout << indent << "\"VMP扫描指标\": {"
              << "\"可执行字节\":" << v.metrics.executable_bytes << ","
              << "\"扫描字节\":" << v.metrics.scanned_bytes << ","
              << "\"候选反汇编字节\":" << v.metrics.decoded_candidate_bytes << ","
              << "\"原始间接转移\":" << v.metrics.raw_indirect_transfers << ","
              << "\"已排除桩点\":" << v.metrics.excluded_thunk_sites << ","
              << "\"去重候选\":" << v.metrics.unique_candidates << ","
              << "\"强候选\":" << v.metrics.strong_candidates << ","
              << "\"中候选\":" << v.metrics.medium_candidates << ","
              << "\"共享VPC最大候选数\":" << v.metrics.dominant_vip_sites << ","
              << "\"4KB最大聚类数\":" << v.metrics.max_cluster_sites << "}," << nl;

    std::cout << indent << "\"VMP特征\": [";
    for (size_t i = 0; i < v.signals.size(); ++i) {
        if (i) std::cout << ",";
        std::cout << "\"" << json_escape(v.signals[i]) << "\"";
    }
    std::cout << "]," << nl;

    std::cout << indent << "\"VMP候选点\": [" << nl;
    for (size_t i = 0; i < v.candidates.size(); ++i) {
        const auto& candidate = v.candidates[i];
        std::cout << indent << "  {\"地址\":\"0x" << std::hex << candidate.address << std::dec
                  << "\",\"区域\":\"" << json_escape(candidate.region)
                  << "\",\"类型\":\"" << json_escape(candidate.kind)
                  << "\",\"强度\":\"" << json_escape(candidate.strength)
                  << "\",\"VPC寄存器\":\"" << json_escape(candidate.vip_reg)
                  << "\",\"opcode寄存器\":\"" << json_escape(candidate.opcode_reg)
                  << "\",\"target寄存器\":\"" << json_escape(candidate.target_reg)
                  << "\",\"特征\":[";
        for (size_t j = 0; j < candidate.traits.size(); ++j) {
            if (j) std::cout << ",";
            std::cout << "\"" << json_escape(vmp_trait_zh(candidate.traits[j])) << "\"";
        }
        std::cout << "]}";
        if (i + 1 != v.candidates.size()) std::cout << ",";
        std::cout << nl;
    }
    std::cout << indent << "]," << nl;
    if (!v.alternative_explanation.empty()) {
        std::cout << indent << "\"VMP替代解释\": \""
                  << json_escape(v.alternative_explanation) << "\"," << nl;
    }
    if (!v.limitation.empty()) {
        std::cout << indent << "\"VMP分析限制\": \""
                  << json_escape(v.limitation) << "\"," << nl;
    }
}

static std::vector<AddressRange> find_dynamic_plt_branch_ranges(
        const std::vector<ExecutableRegionView>& regions,
        const std::vector<uint64_t>& jump_slot_vas) {
    std::vector<AddressRange> ranges;
    if (jump_slot_vas.empty()) return ranges;

    Arm64DisasmEngine engine;
    if (!engine.init()) return ranges;

    for (const auto& region : regions) {
        if (!region.data || region.size < 16 ||
            region.virtual_address > UINT64_MAX - region.size) continue;
        for (size_t offset = 0; offset + 4 <= region.size; offset += 4) {
            uint32_t word = 0;
            std::memcpy(&word, region.data + offset, sizeof(word));
            if (word != 0xd61f0220U) continue;  // br x17

            const size_t window_begin = offset > 24 ? offset - 24 : 0;
            const size_t window_size = offset + 4 - window_begin;
            auto instructions = engine.disasm_aligned_resilient(
                region.data + window_begin, window_size,
                region.virtual_address + window_begin, 0);
            if (instructions.empty()) continue;

            size_t branch_index = instructions.size();
            for (size_t i = 0; i < instructions.size(); ++i) {
                const auto& ins = instructions[i];
                if (ins.address == region.virtual_address + offset &&
                    ins.mnemonic == "br" && ins.operand_count > 0 &&
                    ins.operands[0].type == DisasmOperandType::Reg &&
                    ins.operands[0].reg == "x17") {
                    branch_index = i;
                    break;
                }
            }
            if (branch_index == instructions.size()) continue;

            const DisasmInsn* pointer_load = nullptr;
            const DisasmInsn* page_base = nullptr;
            bool has_plt_add = false;
            size_t load_index = instructions.size();
            for (size_t i = branch_index; i > 0; --i) {
                const auto& ins = instructions[i - 1];
                if (ins.mnemonic != "ldr" || ins.operand_count < 2 ||
                    ins.operands[0].type != DisasmOperandType::Reg ||
                    ins.operands[0].reg != "x17") continue;
                for (size_t op = 1; op < ins.operand_count; ++op) {
                    if (ins.operands[op].type == DisasmOperandType::Mem &&
                        ins.operands[op].mem_base == "x16") {
                        pointer_load = &ins;
                        load_index = i - 1;
                        break;
                    }
                }
                if (pointer_load) break;
            }
            if (!pointer_load) continue;

            for (size_t i = load_index; i > 0; --i) {
                const auto& ins = instructions[i - 1];
                if (ins.mnemonic == "adrp" && ins.operand_count >= 2 &&
                    ins.operands[0].type == DisasmOperandType::Reg &&
                    ins.operands[0].reg == "x16" &&
                    ins.operands[1].type == DisasmOperandType::Imm) {
                    page_base = &ins;
                    break;
                }
            }
            for (size_t i = load_index + 1; i < branch_index; ++i) {
                const auto& ins = instructions[i];
                if (ins.mnemonic == "add" && ins.operand_count >= 2 &&
                    ins.operands[0].type == DisasmOperandType::Reg &&
                    ins.operands[1].type == DisasmOperandType::Reg &&
                    ins.operands[0].reg == "x16" &&
                    ins.operands[1].reg == "x16") {
                    has_plt_add = true;
                    break;
                }
            }
            if (!page_base || !has_plt_add || page_base->operands[1].imm < 0) continue;

            const DisasmOperand* memory = nullptr;
            for (size_t op = 1; op < pointer_load->operand_count; ++op) {
                if (pointer_load->operands[op].type == DisasmOperandType::Mem) {
                    memory = &pointer_load->operands[op];
                    break;
                }
            }
            if (!memory || memory->mem_disp < 0) continue;
            const uint64_t page = static_cast<uint64_t>(page_base->operands[1].imm);
            const uint64_t displacement = static_cast<uint64_t>(memory->mem_disp);
            if (page > UINT64_MAX - displacement) continue;
            const uint64_t slot_va = page + displacement;
            if (std::binary_search(jump_slot_vas.begin(), jump_slot_vas.end(), slot_va)) {
                const uint64_t branch_va = region.virtual_address + offset;
                ranges.push_back({branch_va, branch_va + 4});
            }
        }
    }

    std::sort(ranges.begin(), ranges.end(), [](const AddressRange& lhs,
                                                const AddressRange& rhs) {
        return lhs.begin < rhs.begin;
    });
    ranges.erase(std::unique(ranges.begin(), ranges.end(),
        [](const AddressRange& lhs, const AddressRange& rhs) {
            return lhs.begin == rhs.begin && lhs.end == rhs.end;
        }), ranges.end());
    return ranges;
}

static void print_vmp_json_en(const AnalysisResult& r,
                              const char* indent,
                              const char* nl) {
    const auto& v = r.vmp;
    std::cout << indent << "\"vmp_judgment\": \"" << json_escape(vmp_judgment_en(v)) << "\"," << nl;
    std::cout << indent << "\"vmp_outcome\": \"" << json_escape(v.outcome) << "\"," << nl;
    std::cout << indent << "\"vmp_confidence\": \"" << json_escape(v.confidence) << "\"," << nl;
    std::cout << indent << "\"vmp_profile\": \"" << json_escape(v.profile) << "\"," << nl;
    std::cout << indent << "\"vmp_profile_label\": \"" << json_escape(vmp_profile_en(v.profile)) << "\"," << nl;
    std::cout << indent << "\"vmp_score\": " << std::fixed << std::setprecision(4) << v.score << "," << nl;
    std::cout << indent << "\"vm_structure_score\": " << std::fixed << std::setprecision(4) << v.structure_score << "," << nl;
    std::cout << indent << "\"protection_intent_score\": " << std::fixed << std::setprecision(4) << v.protection_intent_score << "," << nl;
    std::cout << indent << "\"alternative_penalty\": " << std::fixed << std::setprecision(4) << v.alternative_penalty << "," << nl;
    std::cout << indent << "\"vmp_scan_coverage\": " << std::fixed << std::setprecision(4) << v.coverage << "," << nl;
    std::cout << indent << "\"vmp_observable\": " << (v.observable ? "true" : "false") << "," << nl;

    std::cout << indent << "\"vmp_metrics\": {"
              << "\"executable_bytes\":" << v.metrics.executable_bytes << ","
              << "\"scanned_bytes\":" << v.metrics.scanned_bytes << ","
              << "\"decoded_candidate_bytes\":" << v.metrics.decoded_candidate_bytes << ","
              << "\"raw_indirect_transfers\":" << v.metrics.raw_indirect_transfers << ","
              << "\"excluded_thunk_sites\":" << v.metrics.excluded_thunk_sites << ","
              << "\"unique_candidates\":" << v.metrics.unique_candidates << ","
              << "\"strong_candidates\":" << v.metrics.strong_candidates << ","
              << "\"medium_candidates\":" << v.metrics.medium_candidates << ","
              << "\"dominant_vip_sites\":" << v.metrics.dominant_vip_sites << ","
              << "\"max_cluster_sites_4k\":" << v.metrics.max_cluster_sites << "}," << nl;

    std::cout << indent << "\"vmp_features\": [";
    for (size_t i = 0; i < v.signals.size(); ++i) {
        if (i) std::cout << ",";
        std::cout << "\"" << json_escape(vmp_signal_to_en(v.signals[i])) << "\"";
    }
    std::cout << "]," << nl;

    std::cout << indent << "\"vmp_candidates\": [" << nl;
    for (size_t i = 0; i < v.candidates.size(); ++i) {
        const auto& candidate = v.candidates[i];
        std::cout << indent << "  {\"address\":\"0x" << std::hex << candidate.address << std::dec
                  << "\",\"region\":\"" << json_escape(candidate.region)
                  << "\",\"kind\":\"" << json_escape(candidate.kind)
                  << "\",\"strength\":\"" << json_escape(candidate.strength)
                  << "\",\"vpc_reg\":\"" << json_escape(candidate.vip_reg)
                  << "\",\"opcode_reg\":\"" << json_escape(candidate.opcode_reg)
                  << "\",\"target_reg\":\"" << json_escape(candidate.target_reg)
                  << "\",\"traits\":[";
        for (size_t j = 0; j < candidate.traits.size(); ++j) {
            if (j) std::cout << ",";
            std::cout << "\"" << json_escape(candidate.traits[j]) << "\"";
        }
        std::cout << "]}";
        if (i + 1 != v.candidates.size()) std::cout << ",";
        std::cout << nl;
    }
    std::cout << indent << "]," << nl;
    if (!v.alternative_explanation.empty()) {
        std::cout << indent << "\"vmp_alternative_explanation\": \""
                  << json_escape(v.alternative_explanation) << "\"," << nl;
    }
    if (!v.limitation.empty()) {
        std::cout << indent << "\"vmp_limitation\": \""
                  << json_escape(v.limitation) << "\"," << nl;
    }
}

static SummaryStats build_summary_stats_zh(const std::vector<AnalysisResult> &results) {
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

static SummaryStats build_summary_stats_en(const std::vector<AnalysisResult> &results) {
    SummaryStats s;
    s.total = static_cast<int>(results.size());

    for (const auto &r : results) {
        std::string level = risk_level_en(r);
        if (level == "High") s.high++;
        else if (level == "Medium") s.medium++;
        else s.low++;

        if (r.is_zip_container) s.zip_so_container++;
        if (r.inner_elf_found) s.inner_elf_extracted++;
    }
    return s;
}

static std::string scan_diagnostic_message(const std::string& code, bool chinese) {
    struct MessagePair { const char* en; const char* zh; };
    static const std::map<std::string, MessagePair> messages = {
        {"APK_FILE_SIZE_LIMIT", {"APK exceeds the scanner input-size limit.", "APK 超过扫描器允许的输入大小上限。"}},
        {"APK_ZIP_METADATA_LIMIT", {"ZIP metadata allocation exceeded its hard limit.", "ZIP 元数据内存分配超过硬限制。"}},
        {"APK_OPEN_FAILED", {"Input is not a readable, supported APK/ZIP archive.", "输入文件不是可读取且受支持的 APK/ZIP。"}},
        {"APK_ENTRY_LIMIT", {"APK contains too many ZIP entries; no SO was extracted.", "APK 的 ZIP 总条目数过多，未解压任何 SO。"}},
        {"ZIP_ENTRY_STAT_FAILED", {"A ZIP entry could not be inspected and was skipped.", "某个 ZIP 条目无法读取元数据，已跳过。"}},
        {"SO_CANDIDATE_LIMIT", {"APK contains too many relevant ARM64/assets SO candidates; scan was rejected.", "APK 中待分析的 ARM64/assets SO 候选过多，扫描已拒绝。"}},
        {"SO_EMPTY_ENTRY", {"Empty SO entry was skipped.", "空 SO 条目已跳过。"}},
        {"SO_ENCRYPTED_ENTRY", {"Encrypted SO entry is unsupported and was skipped.", "加密 SO 条目不受支持，已跳过。"}},
        {"SO_UNSUPPORTED_COMPRESSION", {"SO uses an unsupported ZIP compression method and was skipped.", "SO 使用不受支持的 ZIP 压缩方式，已跳过。"}},
        {"SO_ENTRY_TOO_LARGE", {"SO declared size exceeds the per-entry limit and was not extracted.", "SO 声明大小超过单条目上限，未执行解压。"}},
        {"SO_COMPRESSION_RATIO_LIMIT", {"SO has a suspicious compression ratio and was not extracted.", "SO 压缩比异常，疑似解压炸弹，未执行解压。"}},
        {"SO_TOTAL_UNCOMPRESSED_LIMIT", {"Cumulative relevant-SO budget was exhausted; this entry was skipped.", "相关 SO 累计解压预算已耗尽，该条目已跳过。"}},
        {"SO_ALLOCATION_FAILED", {"Memory allocation for the bounded SO buffer failed.", "受限 SO 缓冲区内存分配失败。"}},
        {"SO_EXTRACT_FAILED", {"SO extraction failed validation and the entry was skipped.", "SO 解压或校验失败，该条目已跳过。"}},
        {"SO_ANALYSIS_ALLOCATION_FAILED", {"SO analysis ran out of its available memory and was skipped safely.", "SO 分析内存不足，已安全跳过。"}},
        {"SO_ANALYSIS_FAILED", {"SO analysis failed safely; other entries may still have been analyzed.", "SO 分析安全失败，其他条目仍可继续分析。"}},
        {"SCANNER_MEMORY_LIMIT", {"Scanner memory allocation failed; the request was stopped safely.", "扫描器内存分配失败，请求已安全停止。"}},
        {"SCANNER_INTERNAL_ERROR", {"Scanner hit an internal error and stopped safely.", "扫描器遇到内部错误，已安全停止。"}},
        {"INNER_ZIP_METADATA_LIMIT", {"Nested ZIP metadata exceeded its allocation limit.", "内层 ZIP 元数据超过内存限制。"}},
        {"INNER_ZIP_OPEN_FAILED", {"Nested ZIP container could not be parsed safely.", "内层 ZIP 容器无法安全解析。"}},
        {"INNER_ZIP_ENTRY_LIMIT", {"Nested ZIP contains too many entries.", "内层 ZIP 条目数过多。"}},
        {"INNER_ZIP_ENTRY_STAT_FAILED", {"A nested ZIP entry could not be inspected.", "某个内层 ZIP 条目无法读取元数据。"}},
        {"INNER_ZIP_ENCRYPTED_ENTRY", {"Encrypted nested entry was skipped.", "加密的内层条目已跳过。"}},
        {"INNER_ZIP_UNSUPPORTED_COMPRESSION", {"Nested entry uses unsupported compression and was skipped.", "内层条目使用不支持的压缩方式，已跳过。"}},
        {"INNER_ZIP_ENTRY_TOO_LARGE", {"Nested entry exceeds the per-entry limit.", "内层条目超过单条目大小上限。"}},
        {"INNER_ZIP_COMPRESSION_RATIO_LIMIT", {"Nested entry has a suspicious compression ratio.", "内层条目压缩比异常，疑似解压炸弹。"}},
        {"INNER_ZIP_TOTAL_UNCOMPRESSED_LIMIT", {"Nested ZIP cumulative decompression budget was exhausted.", "内层 ZIP 累计解压预算已耗尽。"}},
        {"INNER_ZIP_ALLOCATION_FAILED", {"Memory allocation for a nested entry failed.", "内层条目内存分配失败。"}},
        {"INNER_ZIP_EXTRACT_FAILED", {"Nested entry extraction failed validation.", "内层条目解压或校验失败。"}},
    };
    const auto it = messages.find(code);
    if (it == messages.end()) {
        return chinese ? "扫描器已安全处理该异常。" : "The scanner handled this condition safely.";
    }
    return chinese ? it->second.zh : it->second.en;
}

static void print_scan_metadata_json(const ApkScanReport& report,
                                     bool chinese,
                                     const char* indent1,
                                     const char* indent2,
                                     const char* indent3,
                                     const char* nl) {
    using Limits = obfuscan::ApkScanLimits;
    std::cout << indent1 << "\"scan_status\": \"" << json_escape(report.status)
              << "\"," << nl;
    std::cout << indent1 << "\"scan_limits\": {" << nl;
    std::cout << indent2 << "\"max_apk_bytes\": " << Limits::kMaxApkBytes << "," << nl;
    std::cout << indent2 << "\"max_zip_metadata_bytes\": " << Limits::kMaxZipMetadataBytes << "," << nl;
    std::cout << indent2 << "\"max_zip_entries\": " << Limits::kMaxZipEntries << "," << nl;
    std::cout << indent2 << "\"max_candidate_so_entries\": " << Limits::kMaxCandidateSoEntries << "," << nl;
    std::cout << indent2 << "\"max_single_so_uncompressed_bytes\": " << Limits::kMaxSingleSoBytes << "," << nl;
    std::cout << indent2 << "\"max_total_relevant_so_uncompressed_bytes\": " << Limits::kMaxTotalRelevantSoBytes << "," << nl;
    std::cout << indent2 << "\"max_compression_ratio\": " << Limits::kMaxCompressionRatio << "," << nl;
    std::cout << indent2 << "\"compression_ratio_floor_bytes\": " << Limits::kCompressionRatioFloorBytes << "," << nl;
    std::cout << indent2 << "\"max_inner_zip_entries\": " << Limits::kMaxInnerZipEntries << "," << nl;
    std::cout << indent2 << "\"max_total_inner_uncompressed_bytes\": " << Limits::kMaxTotalInnerEntryBytes << "," << nl;
    std::cout << indent2 << "\"max_recorded_diagnostics\": " << Limits::kMaxRecordedDiagnostics << nl;
    std::cout << indent1 << "}," << nl;

    std::cout << indent1 << "\"scan_observed\": {" << nl;
    std::cout << indent2 << "\"apk_file_bytes\": " << report.apk_file_bytes << "," << nl;
    std::cout << indent2 << "\"archive_entry_count\": " << report.archive_entry_count << "," << nl;
    std::cout << indent2 << "\"relevant_so_count\": " << report.relevant_so_count << "," << nl;
    std::cout << indent2 << "\"analyzed_so_count\": " << report.analyzed_so_count << "," << nl;
    std::cout << indent2 << "\"skipped_so_count\": " << report.skipped_so_count << "," << nl;
    std::cout << indent2 << "\"declared_relevant_uncompressed_bytes\": "
              << report.declared_relevant_uncompressed_bytes << "," << nl;
    std::cout << indent2 << "\"accepted_relevant_uncompressed_bytes\": "
              << report.accepted_relevant_uncompressed_bytes << "," << nl;
    std::cout << indent2 << "\"zip_metadata_peak_bytes\": "
              << report.zip_metadata_peak_bytes << "," << nl;
    std::cout << indent2 << "\"suppressed_diagnostic_count\": "
              << report.suppressed_diagnostic_count << nl;
    std::cout << indent1 << "}," << nl;

    std::cout << indent1 << "\"scan_diagnostics\": [" << nl;
    for (size_t i = 0; i < report.diagnostics.size(); ++i) {
        const auto& diagnostic = report.diagnostics[i];
        std::cout << indent2 << "{" << nl;
        std::cout << indent3 << "\"severity\": \"" << json_escape(diagnostic.severity) << "\"," << nl;
        std::cout << indent3 << "\"code\": \"" << json_escape(diagnostic.code) << "\"," << nl;
        std::cout << indent3 << "\"message\": \""
                  << json_escape(scan_diagnostic_message(diagnostic.code, chinese)) << "\"," << nl;
        std::cout << indent3 << "\"entry\": \"" << json_escape(diagnostic.entry) << "\"," << nl;
        std::cout << indent3 << "\"entry_index\": ";
        if (diagnostic.has_entry_index) std::cout << diagnostic.entry_index;
        else std::cout << "null";
        std::cout << "," << nl;
        std::cout << indent3 << "\"compressed_bytes\": " << diagnostic.compressed_bytes << "," << nl;
        std::cout << indent3 << "\"uncompressed_bytes\": " << diagnostic.uncompressed_bytes << "," << nl;
        std::cout << indent3 << "\"detail\": \"" << json_escape(diagnostic.detail) << "\"" << nl;
        std::cout << indent2 << "}";
        if (i + 1 != report.diagnostics.size()) std::cout << ",";
        std::cout << nl;
    }
    std::cout << indent1 << "]," << nl;
}

static void print_all_results_json_cn(const ApkScanReport &report, bool pretty = true) {
    const char *indent1 = pretty ? "  " : "";
    const char *indent2 = pretty ? "    " : "";
    const char *indent3 = pretty ? "      " : "";
    const char *nl = pretty ? "\n" : "";

    const auto& results = report.results;
    SummaryStats stats = build_summary_stats_zh(results);

    std::cout << "{" << nl;
    print_scan_metadata_json(report, true, indent1, indent2, indent3, nl);

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

        std::cout << indent3 << "\"自定义Linker状态码\": \""
                  << obfuscan::custom_linker::outcome_code(r.custom_linker.outcome)
                  << "\"," << nl;
        std::cout << indent3 << "\"自定义Linker置信度\": \""
                  << obfuscan::custom_linker::confidence_code(r.custom_linker.confidence)
                  << "\"," << nl;
        std::cout << indent3 << "\"自定义Linker装载器分数\": "
                  << std::fixed << std::setprecision(4)
                  << r.custom_linker.loader_score << "," << nl;
        std::cout << indent3 << "\"自定义Linker加固分数\": "
                  << std::fixed << std::setprecision(4)
                  << r.custom_linker.protection_score << "," << nl;
        std::cout << indent3 << "\"自定义Linker证据\": [";
        for (size_t j = 0; j < r.custom_linker.evidence_codes.size(); ++j) {
            if (j) std::cout << ",";
            std::cout << "\"" << json_escape(r.custom_linker.evidence_codes[j]) << "\"";
        }
        std::cout << "]," << nl;
        std::cout << indent3 << "\"自定义Linker证据计数\": {" << nl;
        std::cout << indent3 << "  \"通用Linker噪声\": " << r.custom_linker.counts.generic_linker_noise_hits << "," << nl;
        std::cout << indent3 << "  \"Hook身份\": " << r.custom_linker.counts.hook_identity_hits << "," << nl;
        std::cout << indent3 << "  \"Hook原语\": " << r.custom_linker.counts.hook_primitive_hits << "," << nl;
        std::cout << indent3 << "  \"Loader精确身份\": " << r.custom_linker.counts.explicit_loader_identity_hits << "," << nl;
        std::cout << indent3 << "  \"加固精确身份\": " << r.custom_linker.counts.explicit_protection_identity_hits << "," << nl;
        std::cout << indent3 << "  \"受保护Payload身份\": " << r.custom_linker.counts.explicit_payload_identity_hits << "," << nl;
        std::cout << indent3 << "  \"ELF布局\": " << r.custom_linker.counts.elf_layout_hits << "," << nl;
        std::cout << indent3 << "  \"重定位\": " << r.custom_linker.counts.relocation_hits << "," << nl;
        std::cout << indent3 << "  \"依赖与符号解析\": " << r.custom_linker.counts.dependency_symbol_hits << "," << nl;
        std::cout << indent3 << "  \"构造器\": " << r.custom_linker.counts.constructor_hits << "," << nl;
        std::cout << indent3 << "  \"Linker内部语义\": " << r.custom_linker.counts.linker_internal_hits << "," << nl;
        std::cout << indent3 << "  \"映射API\": " << r.custom_linker.counts.mapping_import_hits << "," << nl;
        std::cout << indent3 << "  \"文件源API\": " << r.custom_linker.counts.file_source_import_hits << "," << nl;
        std::cout << indent3 << "  \"动态链接API\": " << r.custom_linker.counts.dynamic_link_import_hits << "," << nl;
        std::cout << indent3 << "  \"独立装载轴\": " << r.custom_linker.counts.independent_loader_axes << "," << nl;
        std::cout << indent3 << "  \"加固轴\": " << r.custom_linker.counts.protection_axes << "," << nl;
        std::cout << indent3 << "  \"Loader门控通过\": " << (r.custom_linker.loader_gate_passed ? "true" : "false") << "," << nl;
        std::cout << indent3 << "  \"加固门控通过\": " << (r.custom_linker.protection_gate_passed ? "true" : "false") << nl;
        std::cout << indent3 << "}," << nl;
        if (r.custom_linker.loader_component()) {
            std::cout << indent3 << "\"自定义Linker判断\": \""
                      << json_escape(r.possible_custom_linker
                                         ? "疑似自定义Linker加固"
                                         : "自定义ELF Loader组件（未证实加固）")
                      << "\"," << nl;
            if (r.possible_custom_linker) {
                // Legacy field: emit only for an actual protection verdict so
                // old threshold-based clients cannot promote a Loader component.
                std::cout << indent3 << "\"自定义Linker分数\": "
                          << std::fixed << std::setprecision(4)
                          << r.custom_linker.protection_score << "," << nl;
            }
        }

        if (r.runtime_evidence_classes > 0) {
            std::cout << indent3 << "\"运行时替代解释\": {" << nl;
            std::cout << indent3 << "  \"类型\": \"" << json_escape(r.known_runtime_name) << "\"," << nl;
            std::cout << indent3 << "  \"独立证据类别数\": "
                      << static_cast<unsigned>(r.runtime_evidence_classes) << "," << nl;
            std::cout << indent3 << "  \"已确认\": "
                      << (r.known_vm_runtime ? "true" : "false") << "," << nl;
            std::cout << indent3 << "  \"身份字符串命中\": "
                      << r.runtime_raw_identity_hits << "," << nl;
            std::cout << indent3 << "  \"导入API命中\": "
                      << r.runtime_import_api_hits << nl;
            std::cout << indent3 << "}," << nl;
        }

        if (r.vmp_protected_client) {
            std::cout << indent3 << "\"VMP关联证据\": {" << nl;
            std::cout << indent3 << "  \"VMP提供库\": \""
                      << json_escape(r.vmp_provider_so) << "\"," << nl;
            std::cout << indent3 << "  \"DT_NEEDED\": \""
                      << json_escape(r.vmp_needed_library) << "\"," << nl;
            std::cout << indent3 << "  \"共享符号\": [";
            for (size_t j = 0; j < r.vmp_shared_symbols.size(); ++j) {
                if (j) std::cout << ",";
                std::cout << "\"" << json_escape(r.vmp_shared_symbols[j]) << "\"";
            }
            std::cout << "]" << nl;
            std::cout << indent3 << "}," << nl;
        }

        print_vmp_json_cn(r, indent3, nl);
        std::cout << indent3 << "\"建议\": \"" << json_escape(build_advice_zh(r)) << "\"" << nl;
        std::cout << indent2 << "}";

        if (i + 1 != results.size()) std::cout << ",";
        std::cout << nl;
    }
    std::cout << indent1 << "]" << nl;
    std::cout << "}" << nl;
}

static void print_all_results_json_en(const ApkScanReport &report, bool pretty = true) {
    const char *indent1 = pretty ? "  " : "";
    const char *indent2 = pretty ? "    " : "";
    const char *indent3 = pretty ? "      " : "";
    const char *nl = pretty ? "\n" : "";

    const auto& results = report.results;
    SummaryStats stats = build_summary_stats_en(results);

    std::cout << "{" << nl;
    print_scan_metadata_json(report, false, indent1, indent2, indent3, nl);

    std::cout << indent1 << "\"summary\": {" << nl;
    std::cout << indent2 << "\"total_so_count\": " << stats.total << "," << nl;
    std::cout << indent2 << "\"high_risk\": " << stats.high << "," << nl;
    std::cout << indent2 << "\"medium_risk\": " << stats.medium << "," << nl;
    std::cout << indent2 << "\"low_risk\": " << stats.low << "," << nl;
    std::cout << indent2 << "\"zip_container_count\": " << stats.zip_so_container << "," << nl;
    std::cout << indent2 << "\"inner_elf_extracted_count\": " << stats.inner_elf_extracted << nl;
    std::cout << indent1 << "}," << nl;

    std::cout << indent1 << "\"results\": [" << nl;
    for (size_t i = 0; i < results.size(); ++i) {
        const auto &r = results[i];
        std::vector<std::string> en_reasons;
        for (const auto &reason : r.reasons) {
            en_reasons.push_back(reason_to_en(reason));
        }

        std::cout << indent2 << "{" << nl;
        std::cout << indent3 << "\"so_file\": \"" << json_escape(r.so_name) << "\"," << nl;
        std::cout << indent3 << "\"detection_result\": \"" << json_escape(label_to_en(r.final_label)) << "\"," << nl;
        std::cout << indent3 << "\"risk_level\": \"" << json_escape(risk_level_en(r)) << "\"," << nl;
        std::cout << indent3 << "\"description\": \"" << json_escape(build_summary_en(r)) << "\"," << nl;

        if (r.is_zip_container) {
            std::cout << indent3 << "\"container_feature\": \"ZIP container\"," << nl;
        }

        std::cout << indent3 << "\"suspicious_points\": [" << nl;
        for (size_t j = 0; j < en_reasons.size(); ++j) {
            std::cout << indent3 << "  \"" << json_escape(en_reasons[j]) << "\"";
            if (j + 1 != en_reasons.size()) std::cout << ",";
            std::cout << nl;
        }
        std::cout << indent3 << "]," << nl;

        if (!r.entry_previews.empty() && risk_level_en(r) == "High") {
            std::cout << indent3 << "\"entry_previews\": [" << nl;
            size_t limit = std::min<size_t>(r.entry_previews.size(), 4);
            for (size_t k = 0; k < limit; ++k) {
                const auto& ep = r.entry_previews[k];
                std::cout << indent3 << "  {" << nl;
                std::cout << indent3 << "    \"name\": \"" << json_escape(ep.name) << "\"," << nl;
                std::cout << indent3 << "    \"address\": \"0x" << std::hex << ep.va << std::dec << "\"," << nl;
                std::cout << indent3 << "    \"preview\": \"" << json_escape(join_preview_lines(ep.lines, 3)) << "\"" << nl;
                std::cout << indent3 << "  }";
                if (k + 1 != limit) std::cout << ",";
                std::cout << nl;
            }
            std::cout << indent3 << "]," << nl;
        }

        std::cout << indent3 << "\"custom_linker_outcome\": \""
                  << obfuscan::custom_linker::outcome_code(r.custom_linker.outcome)
                  << "\"," << nl;
        std::cout << indent3 << "\"custom_linker_confidence\": \""
                  << obfuscan::custom_linker::confidence_code(r.custom_linker.confidence)
                  << "\"," << nl;
        std::cout << indent3 << "\"custom_linker_loader_score\": "
                  << std::fixed << std::setprecision(4)
                  << r.custom_linker.loader_score << "," << nl;
        std::cout << indent3 << "\"custom_linker_protection_score\": "
                  << std::fixed << std::setprecision(4)
                  << r.custom_linker.protection_score << "," << nl;
        std::cout << indent3 << "\"custom_linker_evidence\": [";
        for (size_t j = 0; j < r.custom_linker.evidence_codes.size(); ++j) {
            if (j) std::cout << ",";
            std::cout << "\"" << json_escape(r.custom_linker.evidence_codes[j]) << "\"";
        }
        std::cout << "]," << nl;
        std::cout << indent3 << "\"custom_linker_evidence_counts\": {" << nl;
        std::cout << indent3 << "  \"generic_linker_noise_hits\": " << r.custom_linker.counts.generic_linker_noise_hits << "," << nl;
        std::cout << indent3 << "  \"hook_identity_hits\": " << r.custom_linker.counts.hook_identity_hits << "," << nl;
        std::cout << indent3 << "  \"hook_primitive_hits\": " << r.custom_linker.counts.hook_primitive_hits << "," << nl;
        std::cout << indent3 << "  \"explicit_loader_identity_hits\": " << r.custom_linker.counts.explicit_loader_identity_hits << "," << nl;
        std::cout << indent3 << "  \"explicit_protection_identity_hits\": " << r.custom_linker.counts.explicit_protection_identity_hits << "," << nl;
        std::cout << indent3 << "  \"explicit_payload_identity_hits\": " << r.custom_linker.counts.explicit_payload_identity_hits << "," << nl;
        std::cout << indent3 << "  \"elf_layout_hits\": " << r.custom_linker.counts.elf_layout_hits << "," << nl;
        std::cout << indent3 << "  \"relocation_hits\": " << r.custom_linker.counts.relocation_hits << "," << nl;
        std::cout << indent3 << "  \"dependency_symbol_hits\": " << r.custom_linker.counts.dependency_symbol_hits << "," << nl;
        std::cout << indent3 << "  \"constructor_hits\": " << r.custom_linker.counts.constructor_hits << "," << nl;
        std::cout << indent3 << "  \"linker_internal_hits\": " << r.custom_linker.counts.linker_internal_hits << "," << nl;
        std::cout << indent3 << "  \"mapping_import_hits\": " << r.custom_linker.counts.mapping_import_hits << "," << nl;
        std::cout << indent3 << "  \"file_source_import_hits\": " << r.custom_linker.counts.file_source_import_hits << "," << nl;
        std::cout << indent3 << "  \"dynamic_link_import_hits\": " << r.custom_linker.counts.dynamic_link_import_hits << "," << nl;
        std::cout << indent3 << "  \"independent_loader_axes\": " << r.custom_linker.counts.independent_loader_axes << "," << nl;
        std::cout << indent3 << "  \"protection_axes\": " << r.custom_linker.counts.protection_axes << "," << nl;
        std::cout << indent3 << "  \"loader_gate_passed\": " << (r.custom_linker.loader_gate_passed ? "true" : "false") << "," << nl;
        std::cout << indent3 << "  \"protection_gate_passed\": " << (r.custom_linker.protection_gate_passed ? "true" : "false") << nl;
        std::cout << indent3 << "}," << nl;
        if (r.custom_linker.loader_component()) {
            std::cout << indent3 << "\"custom_linker_judgment\": \""
                      << json_escape(r.possible_custom_linker
                                         ? "Likely Custom Linker protection"
                                         : "Custom ELF loader component detected (protection not established)")
                      << "\"," << nl;
            if (r.possible_custom_linker) {
                // Legacy field: emit only for an actual protection verdict so
                // old threshold-based clients cannot promote a Loader component.
                std::cout << indent3 << "\"custom_linker_score\": "
                          << std::fixed << std::setprecision(4)
                          << r.custom_linker.protection_score << "," << nl;
            }
        }

        if (r.runtime_evidence_classes > 0) {
            std::cout << indent3 << "\"runtime_alternative\": {" << nl;
            std::cout << indent3 << "  \"family\": \""
                      << json_escape(r.known_runtime_name) << "\"," << nl;
            std::cout << indent3 << "  \"evidence_classes\": "
                      << static_cast<unsigned>(r.runtime_evidence_classes) << "," << nl;
            std::cout << indent3 << "  \"confirmed\": "
                      << (r.known_vm_runtime ? "true" : "false") << "," << nl;
            std::cout << indent3 << "  \"raw_identity_hits\": "
                      << r.runtime_raw_identity_hits << "," << nl;
            std::cout << indent3 << "  \"import_api_hits\": "
                      << r.runtime_import_api_hits << nl;
            std::cout << indent3 << "}," << nl;
        }

        if (r.vmp_protected_client) {
            std::cout << indent3 << "\"vmp_provider_evidence\": {" << nl;
            std::cout << indent3 << "  \"provider_so\": \""
                      << json_escape(r.vmp_provider_so) << "\"," << nl;
            std::cout << indent3 << "  \"needed_library\": \""
                      << json_escape(r.vmp_needed_library) << "\"," << nl;
            std::cout << indent3 << "  \"shared_symbols\": [";
            for (size_t j = 0; j < r.vmp_shared_symbols.size(); ++j) {
                if (j) std::cout << ",";
                std::cout << "\"" << json_escape(r.vmp_shared_symbols[j]) << "\"";
            }
            std::cout << "]" << nl;
            std::cout << indent3 << "}," << nl;
        }

        print_vmp_json_en(r, indent3, nl);
        std::cout << indent3 << "\"suggestion\": \"" << json_escape(build_advice_en(r)) << "\"" << nl;
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
    return (r.vmp_protected_client ? 1.00 : 0.0) +
           (r.custom_linker.loader_component()
                ? r.custom_linker.loader_score * 0.55
                : 0.0) +
           (r.possible_custom_linker ? 0.35 : 0.0) +
           r.packer_score * 1.2 +
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
#ifdef _WIN32
    (void)argc;
#endif

    ApkInputPath apk_path;
    bool output_en = false;

#ifdef _WIN32
    int wide_argc = 0;
    LPWSTR *wide_argv = CommandLineToArgvW(GetCommandLineW(), &wide_argc);
    if (wide_argv) {
        for (int i = 1; i < wide_argc; ++i) {
            std::wstring arg = wide_argv[i];
            if (arg == L"--en") {
                output_en = true;
            } else if (arg.empty() || arg[0] != L'-') {
                apk_path.native = arg;
            }
        }
        if (!apk_path.native.empty()) {
            const int bytes = WideCharToMultiByte(CP_UTF8, 0, apk_path.native.c_str(),
                                                  -1, nullptr, 0, nullptr, nullptr);
            if (bytes > 1) {
                apk_path.utf8.resize(static_cast<size_t>(bytes));
                WideCharToMultiByte(CP_UTF8, 0, apk_path.native.c_str(), -1,
                                    apk_path.utf8.data(), bytes, nullptr, nullptr);
                apk_path.utf8.resize(static_cast<size_t>(bytes - 1));
            }
        }
        LocalFree(wide_argv);
    }
#else
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--en") {
            output_en = true;
        } else if (arg.find("-") != 0) {
            apk_path.utf8 = arg;
        }
    }
#endif

    if (apk_path.utf8.empty()) {
        print_usage(argv[0]);
        return 1;
    }

    ApkScanReport report;
    try {
        report = analyze_arm64_sos_from_apk(apk_path);
        sort_results_by_risk(report.results);
    } catch (const std::bad_alloc&) {
        report = ApkScanReport{};
        report.status = "ERROR";
        add_report_diagnostic(report, "error", "SCANNER_MEMORY_LIMIT", apk_path.utf8);
    } catch (const std::exception& error) {
        report = ApkScanReport{};
        report.status = "ERROR";
        add_report_diagnostic(report, "error", "SCANNER_INTERNAL_ERROR",
                              apk_path.utf8, error.what());
    } catch (...) {
        report = ApkScanReport{};
        report.status = "ERROR";
        add_report_diagnostic(report, "error", "SCANNER_INTERNAL_ERROR",
                              apk_path.utf8, "unknown exception");
    }
    report.analyzed_so_count = report.results.size();
    
    if (output_en) {
        print_all_results_json_en(report, true);
    } else {
        print_all_results_json_cn(report, true);
    }
    return 0;
}
