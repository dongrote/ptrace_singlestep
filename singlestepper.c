#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <errno.h>
#include <sys/user.h>
#include <stdint.h>

void fprint_wait_status(FILE *stream, int status)
{
    if( WIFSTOPPED(status) ) {
        fprintf(stream, "Child stopped: %d\n", WSTOPSIG(status));
    }
    if( WIFEXITED(status) ) {
        fprintf(stream, "Child exited: %d\n", WEXITSTATUS(status));
    }
    if( WIFSIGNALED(status) ) {
        fprintf(stream, "Child signaled: %d\n", WTERMSIG(status));
    }
    if( WCOREDUMP(status) ) {
        fprintf(stream, "Core dumped.\n");
    }
}

int ptrace_instruction_pointer(int pid, uint32_t *eip)
{
    struct user_regs_struct regs;
    if( ptrace(PTRACE_GETREGS, pid, NULL, (void*)&regs) ) {
        fprintf(stderr, "Error fetching registers from child process: %s\n",
            strerror(errno));
        return -1;
    }
    if( eip )
        *eip = regs.eip;
    return 0;
}

int singlestep(int pid)
{
    int retval, status;
    retval = ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
    if( retval ) {
        return retval;
    }
    waitpid(pid, &status, 0);
    return status;
}

int main(int argc, char ** argv, char **envp)
{
    uint32_t eip;
    pid_t pid;
    int status;
    char *program;
    if (argc < 2) {
        fprintf(stderr, "Usage: %s elffile arg0 arg1 ...\n", argv[0]);
        exit(-1);
    }
    program = argv[1];
    char ** child_args = (char**) &argv[1];

    pid = fork();
    if( pid == -1 ) {
        fprintf(stderr, "Error forking: %s\n", strerror(errno));
        exit(-1);
    }
    if( pid == 0 ) {
        /* child */
        if( ptrace(PTRACE_TRACEME, 0, 0, 0) ) {
            fprintf(stderr, "Error setting TRACEME: %s\n", strerror(errno));
            exit(-1);
        }
        execve(program,child_args,envp);
    } else {
        /* parent */
        waitpid(pid, &status, 0);
        fprint_wait_status(stderr,status);
        while( WIFSTOPPED(status) ) {
            if( ptrace_instruction_pointer(pid, &eip) ) {
                break;
            }
            fprintf(stderr, "EIP: %p\n", (void*)eip);
            status = singlestep(pid);
        }
        fprint_wait_status(stderr, status);
        fprintf(stderr, "Detaching\n");
        ptrace(PTRACE_DETACH, pid, 0, 0);
    }

    return 0;
}
