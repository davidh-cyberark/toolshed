# Makefile

# Updated: <2023-07-10 11:46:21 david.hisel>

# LICENSE

BINDIR = ./bin
TOOLDIR = ./tools

PLANTUML_DL_URL = https://github.com/plantuml/plantuml/releases/download/v1.2023.9/plantuml.jar
NPMDIR = $(shell npm root)
VERSION = $(shell cat VERSION)
NEXTVERSION = $(shell echo "$(VERSION)" | awk -F. '{print $$1"."$$2"."$$3+1}')

LDFLAGS = -ldflags "-X main.version=$(VERSION)"

all: $(BINDIR)/toolshed $(BINDIR)/provengine | $(BINDIR)

$(BINDIR):
	mkdir -p $@

$(BINDIR)/toolshed: VERSION ./cmd/toolshed/toolshed.go | $(BINDIR)
	go build -o $@ $(LDFLAGS) ./cmd/toolshed

$(BINDIR)/provengine: VERSION ./cmd/provengine/provengine.go | $(BINDIR)
	go build -o $@ $(LDFLAGS) ./cmd/provengine

versionbump:
	echo "$(VERSION)" | awk -F. '{print $$1"."$$2"."$$3+1}' > VERSION

docs: README.html

markdown-it:
	curl -sLJO $(PLANTUML_DL_URL) -o plantuml.jar
	mv plantuml.jar $(BINDIR)/plantuml.jar
	npm install markdown-it --save
	npm install markdown-it-cli --save
	npm install markdown-it-meta-header --save
	npm install markdown-it-plantuml-ex --save
	echo "NPMDIR - $(NPMDIR)"
	cp $(BINDIR)/plantuml.jar $(NPMDIR)/markdown-it-plantuml-ex/lib/plantuml.jar

README.html: markdown-it README.md
	npx markdown-it-cli -o README.html README.md

clean:
	rm -rf $(BINDIR)/toolshed $(BINDIR)/provengine
	rm -rf README.html

realclean: clean
	rm -rf $(BINDIR)/plantuml.jar
	rm -rf $(BINDIR)/markdown-it
	rm -rf ./node_modules package.json package-lock.json

vardump:
	@echo "VERSION: $(VERSION)"
	@echo "NEXTVERSION: $(NEXTVERSION)"
	@echo "NPMDIR: $(NPMDIR)"
	@echo "PLANTUML_DL_URL: $(PLANTUML_DL_URL)"
	@echo "LDFLAGS: $(LDFLAGS)"
