DESTDIR ?= /usr/local/bin/pwdtools

setup:
	@echo "Setting up pwdtools..."
	@pip3 install -r requirements.txt

install:
	@echo "Installing pwdtools..."
	@pip3 install -r requirements.txt
	@sudo cp pwdtools.py $(DESTDIR)/pwdtools
	@sudo cp pwdlib.py $(DESTDIR)/pwdlib.py
	@sudo chmod +x $(DESTDIR)/pwdtools/pwdtools
	@echo "Installation Successful!"

uninstall:
	@sudo rm -rf $(DESTDIR)/pwdtools
	@echo "pwdtools has been removed"