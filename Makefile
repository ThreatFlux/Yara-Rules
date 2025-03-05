# Makefile for YARA Rules Project

# Compiler and flags
YARAC=yarac
YARA=yara
FIND=find

# Directories
SRC_DIR=src
BUILD_DIR=build

# Find all .yar files recursively
YARA_RULES=$(shell find $(SRC_DIR) -type f -name "*.yar")
COMPILED_RULES=$(patsubst $(SRC_DIR)/%.yar,$(BUILD_DIR)/%.yarc,$(YARA_RULES))

# Ensure build directories exist
BUILD_DIRS=$(sort $(dir $(COMPILED_RULES)))

# Default target
all: compile

# Create build directories
$(BUILD_DIRS):
	mkdir -p $@

# Compile individual rules
$(BUILD_DIR)/%.yarc: $(SRC_DIR)/%.yar | $(BUILD_DIRS)
	@echo "Compiling $<..."
	$(YARAC)  $< $@
	@echo "Successfully compiled $<"

# Compile all rules
$(BUILD_DIR)/all.yarc: $(COMPILED_RULES)
	@echo "Compiling all rules..."
	$(YARAC) $(COMPILED_RULES) $@
	@echo "Successfully compiled all rules"
# Main targets
.PHONY: compile test clean scan help report check

# Compile all rules
compile: $(COMPILED_RULES)
	@echo "All rules compiled successfully"

# Compile all rules into a single file
compile-all: $(BUILD_DIR)/all.yarc
	@echo "All rules compiled into a single file"

# Test rule syntax
test:
	@echo "Testing YARA rule syntax..."
	@for rule in $(YARA_RULES); do \
		echo "Testing $$rule..."; \
		$(YARA) -C $$rule /dev/null || exit 1; \
	done
	@echo "All rules passed syntax check"

# Clean compiled rules
clean:
	@echo "Cleaning compiled rules..."
	@rm -rf $(BUILD_DIR)

# Scan a target with all rules
# Usage: make scan TARGET=/path/to/file [THREADS=4]
scan: compile
	@if [ -z "$(TARGET)" ]; then \
		echo "Please specify a target: make scan TARGET=/path/to/file"; \
		exit 1; \
	fi
	@echo "Scanning $(TARGET) with all rules..."
	@$(YARA) -r $(if $(THREADS),-p $(THREADS),) -C $(BUILD_DIR)/**/*.yarc "$(TARGET)"

# Check dependencies
check:
	@echo "Checking YARA installation..."
	@command -v $(YARA) >/dev/null 2>&1 || { echo "YARA not found. Please install YARA first."; exit 1; }
	@command -v $(YARAC) >/dev/null 2>&1 || { echo "YARAC not found. Please install YARA first."; exit 1; }
	@echo "YARA version: $$($(YARA) --version)"
	@echo "All dependencies satisfied."

# Help target
help:
	@echo "YARA Rules Makefile"
	@echo "Available targets:"
	@echo "  make compile    - Compile all YARA rules"
	@echo "  make test      - Test syntax of all rules"
	@echo "  make clean     - Remove compiled rules"
	@echo "  make scan      - Scan a target with all rules"
	@echo "                   Usage: make scan TARGET=/path/to/file [THREADS=4]"
	@echo "  make check     - Check if YARA is installed correctly"
	@echo "  make report    - Generate a summary of all rules"
	@echo "  make help      - Show this help message"

# Report target - generates a summary of all rules
report:
	@echo "YARA Rules Report"
	@echo "=================="
	@echo "Total rules: $(words $(YARA_RULES))"
	@echo "\nRules by category:"
	@echo "----------------"
	@for dir in $$(find $(SRC_DIR) -type d); do \
		count=$$(find $$dir -maxdepth 1 -type f -name "*.yar" | wc -l); \
		if [ $$count -gt 0 ]; then \
			echo "$${dir#$(SRC_DIR)/}: $$count rules"; \
		fi; \
	done
	@echo "\nMost recently modified rules:"
	@echo "-------------------------"
	@ls -lt $(YARA_RULES) | head -n 5
