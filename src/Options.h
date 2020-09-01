//
// Created by nova on 7/23/20.
//

#ifndef ACMED_OPTIONS_H
#define ACMED_OPTIONS_H

#include <map>
#include <tuple>
#include <string>
#include <getopt.h>
#include <exception>
#include <utility>
#include <iostream>
#include "utils/Codes.h"

class Options
{
public:
	Options(int argc, char** argv);
	~Options();
	std::tuple<std::string, bool, bool, std::string> get();

private:
	int argc;
	char** argv;
	struct option* longOptions;
	std::map<std::string, std::map<std::string, std::string>> selectedOption;
};

class OptionsException : std::exception
{
public:
	explicit OptionsException(std::string str) : message(std::move(str)) {}
	~OptionsException() noexcept override = default;;

	[[nodiscard]] const char* what() const noexcept override {
		return message.c_str();
	}

private:
	std::string message;
};

#endif //ACMED_OPTIONS_H
