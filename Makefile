# This file lets you format the code-base with a single command.
FILES := $(shell find . -name '*.c' -o -name '*.h' -o -name '*.cpp' -o -name '*.hpp' -o -name '*.cc' -o -name '*.hh')
.PHONY: format
format:
	clang-format -i -style=file $(FILES)

.PHONY: format-check
format-check:
	clang-format --dry-run --Werror -style=file $(FILES)
