all: mdpc test

mdpc: mdpc.c
	gcc -o mdpc mdpc.c
clean:
	rm -f mdpc
test:
	@echo Running the tests...
	@./runtests
