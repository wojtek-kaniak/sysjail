#if !defined(INCL_TARGET_HPP)
#define INCL_TARGET_HPP

#include <string>
#include <vector>

namespace sysjail
{
	class Target
	{
		std::string p_name;
		std::vector<std::string> p_args;

		public:
		Target(std::string name, std::vector<std::string> args);

		const std::string& name() const noexcept;

		const std::vector<std::string>& args() const noexcept;
	};
}

#endif
