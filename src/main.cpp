#include <format>
#include <iostream>
#include <ranges>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <boost/optional.hpp>
#include <boost/optional/optional_io.hpp>
#include <boost/convert.hpp>
#include <boost/convert/strtol.hpp>
#include <boost/program_options.hpp>

#include "common.hpp"
#include "jail.hpp"
#include "target.hpp"

constexpr int exit_ok = 0;
constexpr int exit_invalid_cli = 2;

namespace opts = boost::program_options;

static boost::optional<sysjail::BlockAction> action_from_cli(
	boost::optional<ushort> err_no,
	bool kill_process,
	bool kill_thread,
	bool trap,
	bool trace,
	bool log
);

int main(int argc, char** argv)
{
	if (argc == 0)
		throw std::runtime_error("too few arguments (no arg 0)");

	opts::options_description options {"Options"};

	boost::optional<std::string> syscalls_opt;
	bool help_opt;

	options.add_options()
		("help", opts::bool_switch(&help_opt), "display this help and exit")
		("syscalls", opts::value(&syscalls_opt), "allow provided syscalls (required)")
		;

	opts::options_description action_options {"Actions"};

	boost::optional<ushort> errno_opt;
	bool kill_thread_opt;
	bool kill_process_opt;
	bool trap_opt;
	bool trace_opt;
	bool log_opt;

	action_options.add_options()
		("errno",        opts::value(&errno_opt)->implicit_value(EPERM), "return the provided errno (default: EPERM)")
		("kill-thread",  opts::bool_switch(&kill_thread_opt),            "kill the invoking thread")
		("kill-process", opts::bool_switch(&kill_process_opt),           "kill the invoking process")
		("trap",         opts::bool_switch(&trap_opt),                   "raise SIGSYS, see `SECCOMP_RET_TRAP`")
		("trace",        opts::bool_switch(&trace_opt),                  "notify a tracer, see `SECCOMP_RET_TRACE`")
		("log",          opts::bool_switch(&log_opt),                    "log the syscall and execute it, see `SECCOMP_RET_LOG`")
		;
	
	// `options` + hidden options
	opts::options_description all_options;
	all_options
		.add(options)
		.add(action_options);

	std::vector<std::string> target_opt;

	all_options.add_options()
		("target", opts::value(&target_opt));

	opts::positional_options_description positionals {};
	positionals.add("target", -1);

	auto parser = opts::command_line_parser(argc, argv)
		.options(all_options)
		.positional(positionals);

	opts::variables_map cli;

	try
	{
		opts::store(parser.run(), cli);
	}
	catch (opts::error_with_option_name err)
	{
		std::cerr << err.what() << "\n";
		return exit_invalid_cli;
	}

	opts::notify(cli);

	if (help_opt)
	{
		std::cout
			<< std::format("Usage: {} [option]... target\n\n", argv[0])
			<< options
			<< "\n"
			<< action_options;

		return exit_ok;
	}

	if (!syscalls_opt.is_initialized())
	{
		std::cerr << "option 'syscalls' is required\n";
		return exit_invalid_cli;
	}

	if (target_opt.empty())
	{
		std::cerr << "'target' is required\n";
		return exit_invalid_cli;
	}

	std::vector<uint> syscalls {};

	auto allow = *syscalls_opt
		| std::ranges::views::split(',')
		| std::ranges::views::transform([](auto word) {
			return std::string_view(word);
		});

	for (std::string_view i: allow)
	{
		boost::optional<uint> num = boost::convert<uint>(i, boost::cnv::strtol());

		if (!num)
		{
			std::cerr << "invalid syscall number\n";
			return exit_invalid_cli;
		}

		syscalls.push_back(*num);
	}

	sysjail::Target target {target_opt.at(0), target_opt};

	boost::optional<sysjail::BlockAction> action = action_from_cli(
		errno_opt, kill_process_opt, kill_thread_opt, trap_opt, trace_opt, log_opt
	);

	if (!action)
	{
		return exit_invalid_cli;
	}

	sysjail::jail(target, syscalls, *action);
}

static boost::optional<sysjail::BlockAction> action_from_cli(
	boost::optional<ushort> err_no,
	bool kill_process,
	bool kill_thread,
	bool trap,
	bool trace,
	bool log
)
{
	ushort args_provided = err_no.is_initialized()
		+ kill_process + kill_thread + trap + trace + log;
	
	if (args_provided > 1)
	{
		std::cerr << "multiple actions specified\n";
		return {};
	}
	
	if (err_no)
		return sysjail::BlockAction::return_errno(*err_no);
	else if (kill_process)
		return sysjail::BlockAction::kill_process();
	else if (kill_thread)
		return sysjail::BlockAction::kill_thread();
	else if (trap)
		return sysjail::BlockAction::trap();
	else if (trace)
		return sysjail::BlockAction::trace();
	else if (log)
		return sysjail::BlockAction::log();
	else
	{
		std::cerr << "no action specified\n";
		return {};
	}
}
