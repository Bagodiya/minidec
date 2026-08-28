#include "minidec/retval.h"

#include <algorithm>
#include <cstddef>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include "minidec/lift.h"

namespace minidec {

namespace {

// System V puts an integer or pointer result in rax and a floating one in xmm0.
// Only the first turns up today; see the note in the header.
const char* const result_registers[] = {"rax", "xmm0"};

std::string canonical(const std::string& reg) {
    return std::string(whole_register(reg));
}

bool is_result_register(const std::string& canon) {
    for (const char* name : result_registers) {
        if (canon == name) {
            return true;
        }
    }
    return false;
}

// How much a source is worth when several reach the same ret. A real write beats
// a call, which beats a clobber, which beats nothing -- the ret is returning
// something if any path put something there.
int weight(ReturnSource source) {
    switch (source) {
    case ReturnSource::written:
        return 3;
    case ReturnSource::call:
        return 2;
    case ReturnSource::clobber:
        return 1;
    case ReturnSource::entry:
        return 0;
    }
    return 0;
}

// One write of a register version.
struct Write {
    ReturnSource source = ReturnSource::entry;
    unsigned width = 0;
    const SsaPhi* phi = nullptr; // set when the write is a join
};

// What resolving a version came to.
struct Resolved {
    ReturnSource source = ReturnSource::entry;
    unsigned width = 0;
    bool through_phi = false;
};

class ReturnScan {
public:
    explicit ReturnScan(const SsaFunction& fn) : fn_(fn) {}

    ReturnValue run();

private:
    // Every register version the function writes, by name and then version.
    void index_writes();

    // Walk back from one version to the writes responsible for it, following
    // phis until real writes are reached.
    Resolved resolve(const std::string& canon, unsigned version) const;

    const Write* lookup(const std::string& canon, unsigned version) const;

    const SsaFunction& fn_;
    std::map<std::string, std::map<unsigned, Write>> writes_;
};

const Write* ReturnScan::lookup(const std::string& canon, unsigned version) const {
    auto by_reg = writes_.find(canon);
    if (by_reg == writes_.end()) {
        return nullptr;
    }
    auto entry = by_reg->second.find(version);
    if (entry == by_reg->second.end()) {
        return nullptr;
    }
    return &entry->second;
}

void ReturnScan::index_writes() {
    for (const SsaBlock& block : fn_.blocks) {
        for (const SsaPhi& phi : block.phis) {
            if (phi.dst.kind != OperandKind::reg) {
                continue;
            }
            Write write;
            write.source = ReturnSource::entry; // decided by what feeds the phi
            write.phi = &phi;
            writes_[canonical(phi.dst.reg)][phi.dst.version] = write;
        }

        std::size_t next_clobber = 0;
        for (std::size_t i = 0; i < block.code.size(); ++i) {
            const IrInst& inst = block.code[i];

            if (inst.writes_result() && inst.dst.kind == OperandKind::reg) {
                Write write;
                write.source = inst.op == Opcode::call ? ReturnSource::call : ReturnSource::written;
                // A call's rax is i64 whatever the callee actually returned, so
                // only a real write gets to claim a width.
                write.width = write.source == ReturnSource::written ? type_bits(inst.dst.type) : 0;
                writes_[canonical(inst.dst.reg)][inst.dst.version] = write;
            }

            while (next_clobber < block.clobbers.size() && block.clobbers[next_clobber].inst < i) {
                ++next_clobber;
            }
            if (next_clobber < block.clobbers.size() && block.clobbers[next_clobber].inst == i) {
                for (const IrOperand& value : block.clobbers[next_clobber].values) {
                    if (value.kind != OperandKind::reg) {
                        continue;
                    }
                    Write write;
                    write.source = ReturnSource::clobber;
                    writes_[canonical(value.reg)][value.version] = write;
                }
                ++next_clobber;
            }
        }
    }
}

Resolved ReturnScan::resolve(const std::string& canon, unsigned version) const {
    Resolved result;

    std::vector<std::pair<std::string, unsigned>> pending{{canon, version}};
    std::vector<std::pair<std::string, unsigned>> seen;

    while (!pending.empty()) {
        std::pair<std::string, unsigned> current = pending.back();
        pending.pop_back();

        // A loop can bring a phi round to itself, so the same version turns up
        // twice and the walk has to stop rather than go round again.
        if (std::find(seen.begin(), seen.end(), current) != seen.end()) {
            continue;
        }
        seen.push_back(current);

        const Write* write = lookup(current.first, current.second);
        if (write == nullptr) {
            // Version 0, which is the caller's value and not a write at all.
            continue;
        }

        if (write->phi != nullptr) {
            result.through_phi = true;
            for (const IrOperand& incoming : write->phi->incoming) {
                if (incoming.kind == OperandKind::reg) {
                    pending.emplace_back(canonical(incoming.reg), incoming.version);
                }
            }
            continue;
        }

        if (weight(write->source) > weight(result.source)) {
            result.source = write->source;
        }
        result.width = std::max(result.width, write->width);
    }

    return result;
}

ReturnValue ReturnScan::run() {
    index_writes();

    ReturnValue result;

    for (const SsaBlock& block : fn_.blocks) {
        for (std::size_t i = 0; i < block.code.size(); ++i) {
            const IrInst& inst = block.code[i];
            if (inst.op != Opcode::ret || inst.args.empty()) {
                continue;
            }

            // The lifter puts the result register in the first slot and nothing
            // else in any of them.
            const IrOperand& value = inst.args.front();
            if (value.kind != OperandKind::reg) {
                continue;
            }

            const std::string canon = canonical(value.reg);
            if (!is_result_register(canon)) {
                continue;
            }

            const Resolved resolved = resolve(canon, value.version);

            ReturnSite site;
            site.block = block.start;
            site.inst = i;
            site.address = inst.address;
            site.reg = canon;
            site.version = value.version;
            site.width = resolved.width;
            site.source = resolved.source;
            site.through_phi = resolved.through_phi;
            result.sites.push_back(std::move(site));
        }
    }

    for (const ReturnSite& site : result.sites) {
        if (site.source == ReturnSource::entry) {
            continue;
        }
        if (result.reg.empty()) {
            result.reg = site.reg;
            result.floating = site.reg == "xmm0";
        }
        result.width = std::max(result.width, site.width);
    }

    return result;
}

} // namespace

const char* return_source_name(ReturnSource source) {
    switch (source) {
    case ReturnSource::entry:
        return "entry";
    case ReturnSource::written:
        return "written";
    case ReturnSource::call:
        return "call";
    case ReturnSource::clobber:
        return "clobber";
    }
    return "?";
}

bool ReturnValue::returns_value() const {
    for (const ReturnSite& site : sites) {
        if (site.source == ReturnSource::written) {
            return true;
        }
    }
    return false;
}

bool ReturnValue::forwards_call() const {
    if (returns_value()) {
        return false;
    }
    for (const ReturnSite& site : sites) {
        if (site.source == ReturnSource::call) {
            return true;
        }
    }
    return false;
}

bool ReturnValue::consistent() const {
    for (const ReturnSite& site : sites) {
        if (site.source != sites.front().source) {
            return false;
        }
    }
    return true;
}

ReturnValue recover_return_value(const SsaFunction& fn) {
    return ReturnScan(fn).run();
}

} // namespace minidec
