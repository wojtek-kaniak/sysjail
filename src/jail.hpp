#if !defined(INCL_JAIL_HPP)
#define INCL_JAIL_HPP

#include <vector>

#include "common.hpp"
#include "target.hpp"

namespace sysjail
{
	class BlockAction {
		enum class Tag { Errno, KillThread, KillProcess, Trap, Trace, Log };

		Tag tag;
		uint err_no;

		constexpr BlockAction(Tag tag, uint err_no) noexcept
			: tag(tag), err_no(err_no) {}

		public:
		constexpr static BlockAction return_errno(uint err_no) noexcept
		{
			return BlockAction { Tag::Errno, err_no };
		}

		constexpr static BlockAction kill_thread() noexcept
		{
			return BlockAction { Tag::KillThread, 0 };
		}

		constexpr static BlockAction kill_process() noexcept
		{
			return BlockAction { Tag::KillProcess, 0 };
		}

		constexpr static BlockAction trap() noexcept
		{
			return BlockAction { Tag::Trap, 0 };
		}

		constexpr static BlockAction trace() noexcept
		{
			return BlockAction { Tag::Trace, 0 };
		}

		constexpr static BlockAction log() noexcept
		{
			return BlockAction { Tag::Log, 0 };
		}

		uint bpf_ret_val() noexcept;
	};
	
	void jail(Target target, const std::vector<uint>& syscalls, BlockAction action);
}

#endif
