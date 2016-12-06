all: tests
	./build

tests:
	./build tests

.PHONY: clean
clean:
	./build clean
