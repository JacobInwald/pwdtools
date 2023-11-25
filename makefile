# Change this to be the directory you normally install custom scripts to
DESTDIR ?= /usr/local/bin

install:
	@echo "Installing pwdtools..."
	@pip3 install -r requirements.txt
	@sudo mkdir -p $(DESTDIR)/pwdlib
	@sudo cp pwdtools.py $(DESTDIR)/pwdtools
	@sudo cp -r pwdlib $(DESTDIR)
	@sudo chmod +x $(DESTDIR)/pwdtools
	@echo "Installation Successful!"

uninstall:
	@sudo rm -rf $(DESTDIR)/pwdlib
	@sudo rm -f $(DESTDIR)/pwdtools
	@echo "pwdtools has been removed"