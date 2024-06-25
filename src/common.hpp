#if !defined(INCL_COMMON_HPP)
#define INCL_COMMON_HPP

#include <cerrno>
#include <cstring>
#include <format>
#include <stdexcept>

using uint = unsigned int;
using ushort = unsigned short;

template <auto OsFunc, typename... Args>
void try_os(const char* func_name, Args... args)
{
	int return_value = OsFunc(args...);

	if (return_value != 0)
	{
		throw std::runtime_error(
			std::format("{} failed: {}", func_name, std::strerror(errno))
		);
	}
}

#define TRY_OS(FUNC, ARGS...) try_os<FUNC>(#FUNC, ARGS)

#endif
