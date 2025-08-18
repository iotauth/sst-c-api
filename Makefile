# This file lets you format the code-base with a single command.
FILES := $(shell find . \
    -path '*/build' -prune -o \
    -path './embedded/lib' -prune -o \
    \( -name '*.c' -o -name '*.h' -o -name '*.cpp' -o -name '*.hpp' -o -name '*.cc' -o -name '*.hh' \) -print)

.PHONY: format
format:
	clang-format -i -style=file $(FILES)

.PHONY: format-check
format-check:
	clang-format --dry-run --Werror -style=file $(FILES)
