#include <string>
#include <vector>

#include "target.hpp"

namespace sysjail
{
	Target::Target(std::string name, std::vector<std::string> args)
		: p_name(name), p_args(args) {}

	const std::string& Target::name() const noexcept
	{
		return this->p_name;
	}

	const std::vector<std::string>& Target::args() const noexcept
	{
		return this->p_args;
	}
}
