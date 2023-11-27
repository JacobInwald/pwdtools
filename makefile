# Change this to be the directory you normally install custom scripts to
DESTDIR ?= /usr/local/bin

install:
	@echo "Installing pwdtools..."
	@pip3 install -r requirements.txt	
	@sudo cp pwdtools.py $(DESTDIR)/pwdtools
	@sudo mkdir -p $(DESTDIR)/pwdtools_src
	@sudo cp -r pwdtools_src $(DESTDIR)
	@sudo chmod +x $(DESTDIR)/pwdtools
	@echo "Installation Successful!"

uninstall:
	@sudo rm -rf $(DESTDIR)/pwdtools_src
	@sudo rm -f $(DESTDIR)/pwdtools
	@echo "pwdtools has been removed"