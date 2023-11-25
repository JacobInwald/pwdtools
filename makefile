DESTDIR ?= /usr/local/bin

install:
	@echo "Installing pwdtools..."
	@sudo cp pwdtools.py $(DESTDIR)/pwdtools
	@sudo chmod +x $(DESTDIR)/pwdtools
	@echo "Installation Successful!"

uninstall:
	@sudo rm -f $(DESTDIR)/pwdtools
	@echo "pwdtools has been removed"