#include <cstddef>
#include <limits>
#include <stdexcept>
#include <vector>

#include <unistd.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>

#include "common.hpp"
#include "target.hpp"

#include "jail.hpp"

namespace sysjail
{
	static std::vector<sock_filter> build_bpf(const std::vector<uint>& syscalls, BlockAction action);

	void jail(Target target, const std::vector<uint>& syscalls, BlockAction action)
	{
		auto filters = build_bpf(syscalls, action);

		if (filters.size() > std::numeric_limits<unsigned short>().max())
			throw std::runtime_error("BPF filter too large");

		sock_fprog filter = {
			.len = static_cast<unsigned short>(filters.size()),
			.filter = filters.data()
		};

		TRY_OS(prctl, PR_SET_NO_NEW_PRIVS, 1, 0, 0);
		TRY_OS(prctl, PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &filter);

		std::vector<const char*> args {target.args().size() + 1, nullptr};

		for (size_t i = 0; i < target.args().size(); i++)
			args[i] = target.args().at(i).c_str();

		TRY_OS(execvp, target.name().c_str(), const_cast<char* const*>(args.data()));
	}

	static std::vector<sock_filter> build_bpf(const std::vector<uint>& syscalls, BlockAction action)
	{
		// cBPF - not eBPF
		std::vector<sock_filter> filter;

		filter.push_back({ BPF_LD | BPF_W | BPF_ABS, 0, 0, 0 });

		for (uint syscall : syscalls)
		{
			// { code, jump_true, jump_false, value }
			filter.push_back({ BPF_JMP | BPF_JEQ | BPF_K, 0, 1, syscall});
			filter.push_back({ BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW});
		}

		filter.push_back({BPF_RET | BPF_K, 0, 0, action.bpf_ret_val()});

		return filter;
	}

	uint BlockAction::bpf_ret_val() noexcept
	{
		switch (tag)
		{
			case Tag::Errno:
				return SECCOMP_RET_ERRNO | err_no;
			case Tag::KillThread:
				return SECCOMP_RET_KILL_THREAD;
			case Tag::KillProcess:
				return SECCOMP_RET_KILL_PROCESS;
			case Tag::Trap:
				return SECCOMP_RET_TRAP;
			case Tag::Trace:
				return SECCOMP_RET_TRACE;
			case Tag::Log:
				return SECCOMP_RET_LOG;
		}
	}
}
