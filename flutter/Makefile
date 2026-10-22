.PHONY: web tablet phone emu connect-tablet reload-web restart-web reload-tablet restart-tablet reload-phone restart-phone reload-emu restart-emu reload-all restart-all analyze

# Wireless tablet (SM X810). On tablet: Developer options → Wireless debugging → ON.
# Pair: make connect-tablet PAIR_HOST=192.168.0.169:PORT CODE=123456
# Then: make connect-tablet CONNECT_HOST=192.168.0.169:PORT
connect-tablet:
	@./connect-tablet.sh status
	@if [ -n "$(PAIR_HOST)" ] && [ -n "$(CODE)" ]; then ./connect-tablet.sh pair $(PAIR_HOST) $(CODE); fi
	@if [ -n "$(CONNECT_HOST)" ]; then ./connect-tablet.sh connect $(CONNECT_HOST); fi

web:
	./dev.sh web

tablet:
	./dev.sh tablet

phone:
	./dev.sh phone

emu:
	./dev.sh emu

reload-web:
	@echo r > /tmp/atomic_app_web_pipe

restart-web:
	@echo R > /tmp/atomic_app_web_pipe

reload-tablet:
	@echo r > /tmp/atomic_app_tablet_pipe

restart-tablet:
	@echo R > /tmp/atomic_app_tablet_pipe

reload-phone:
	@echo r > /tmp/atomic_app_phone_pipe

restart-phone:
	@echo R > /tmp/atomic_app_phone_pipe

reload-emu:
	@echo r > /tmp/atomic_app_emu_pipe

restart-emu:
	@echo R > /tmp/atomic_app_emu_pipe

reload-all:
	@echo r > /tmp/atomic_app_web_pipe 2>/dev/null; echo r > /tmp/atomic_app_tablet_pipe 2>/dev/null; echo r > /tmp/atomic_app_phone_pipe 2>/dev/null; echo r > /tmp/atomic_app_emu_pipe 2>/dev/null

restart-all:
	@echo R > /tmp/atomic_app_web_pipe 2>/dev/null; echo R > /tmp/atomic_app_tablet_pipe 2>/dev/null; echo R > /tmp/atomic_app_phone_pipe 2>/dev/null; echo R > /tmp/atomic_app_emu_pipe 2>/dev/null

analyze:
	@~/.local/share/mise/installs/flutter/3.22.1-stable/bin/flutter analyze lib/
