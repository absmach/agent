all: dev

.PHONY: all docker

dev:
	elm make src/Main.elm --output=main.js

prod:
	elm make --optimize src/Main.elm --output=main.js

run:
	elm reactor

docker:
ifeq ($(GOARCH), arm)
	docker build --tag=magistrala/ui-arm -f docker/Dockerfile.arm .
else
	docker build --tag=magistrala/ui -f docker/Dockerfile .
endif

clean:
	rm -f main.js

mrproper: clean
	rm -rf elm-stuff