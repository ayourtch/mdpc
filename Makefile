all: mdpc test

mdpc: mdpc.c
clean:
	${RM} -f mdpc
test:
	@echo Running the tests...
	@./runtests
