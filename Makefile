# --- Настройки ---
LLVM_CONFIG ?= llvm-config
CLANG       ?= clang
OPT         ?= opt
AFL_CC      ?= afl-cc
PYTHON      ?= python3
CXX			= clang++

CFLAGS_LLVM = -O0 -g -fno-discard-value-names
CFLAGS_BIN  = -O0 -g

SRC          = buffer_overflow.c
PASS_SRC     = VulnerablePathPass.cpp
PASS_SO      = VulnPathPass.so
REPORT       = report.plist
CONFIG       = vulnerabilities.cfg
IR_ORIG      = buffer_overflow.ll
IR_FUZZ      = output_fuzz.ll
FUZZ_BIN     = fuzz_target
INST_BIN	 = inst_binary

SEED_DIR     = seeds
OUT     	 = out

# --- Цели по умолчанию ---
.PHONY: all build fuzz clean test

all: $(FUZZ_BIN)

# --- Сборка только LLVM-пасса ---
build: $(PASS_SO)

# --- 1. Сборка LLVM-пасса ---
$(PASS_SO): $(PASS_SRC)
	$(CXX) -std=c++14 \
		$$($(LLVM_CONFIG) --cxxflags) \
		-fPIC -shared -o $@ $< \
		$$($(LLVM_CONFIG) --ldflags --libs core analysis )

# --- 2. Генерация исходного LLVM IR ---
$(IR_ORIG): $(SRC)
	$(CLANG) -S -emit-llvm $(CFLAGS_LLVM) $< -o $@

# --- 3. Запуск статического анализатора ---

$(REPORT): $(SRC)
	$(CLANG) --analyze \
		-Xanalyzer -analyzer-checker=security.insecureAPI.strcpy \
		-Xanalyzer -analyzer-checker=security.insecureAPI.gets \
		-Xanalyzer -analyzer-output=plist \
		-o $@ $<

# --- 4. Генерация конфигурации из отчёта ---
$(CONFIG): $(REPORT) parse_plist_to_config.py
	$(PYTHON) parse_plist_to_config.py $< $@

# --- 5. Применение вашего пасса → инструментированный IR ---
# ВАЖНО: pass должен уметь читать $(CONFIG)
$(IR_FUZZ): $(IR_ORIG) $(CONFIG) $(PASS_SO)
	$(OPT) -load ./$(PASS_SO) -vuln-path -S $< -o $@

# --- 6. Бинарь c AFL---
$(FUZZ_BIN): $(IR_FUZZ)
	$(AFL_CC) $(CFLAGS_BIN) $< -o $@

# --- 7. Бинарь БЕЗ AFL ---
$(INST_BIN): $(IR_FUZZ)
	$(CLANG) $(CFLAGS_BIN) $< -o $@

# --- 8. Запуск фаззинга ---
fuzz: $(FUZZ_BIN)
	@echo "Запуск фаззинга инструментированной программы..."
	afl-fuzz -i $(SEED_DIR) -o $(OUT) -- ./$(FUZZ_BIN)

# --- 9. Быстрая проверка вручную ---
test: $(FUZZ_BIN)
	@echo "=== Тестирование инструментированной программы ==="
	@for f in $(SEED_DIR)/*; do \
		echo "Тестируем: $$f"; \
		timeout 1 ./$(FUZZ_BIN) "$$f" && echo "  [OK]" || echo "  [CRASH or EXIT]"; \
		echo; \
	done

# --- 10. Очистка ---
clean:
	rm -f $(IR_ORIG) $(IR_FUZZ) $(REPORT) $(CONFIG) $(FUZZ_BIN) $(INST_BIN)
	rm -rf $(OUT)

clean_so: clean
	rm -f $(PASS_SO)