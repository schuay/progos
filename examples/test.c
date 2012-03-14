/* test.c

   Experiments with syscalls
   argc < 2            Print Hello World
   argv[1][0] == 'p'   print argv[2]
              == 'e'   Exec Test
              == 'f'   File test
              == 'F'   File descriptor stress test
              == 'h'   Halt
              == '0'   Null-Pointer Access
*/

#include <stdio.h>
#include <syscall.h>

#define LARGE_BUF_SIZE 4150
char  large_buf[LARGE_BUF_SIZE];

#define NUM_EXEC_CHILDS 7
char *execs[NUM_EXEC_CHILDS] = { "test", "test p FOO", "test p BAR", "test f", "test 0", &large_buf[0], "test^" };

#define MAX_FD 4097

static void init_args(void);
static void init_args()
{
    int i = 0;
    char *t = "";
    while(i < LARGE_BUF_SIZE-1) {
      if(!*t) t = "test ";
      large_buf[i++] = *t++;
    }
    large_buf[LARGE_BUF_SIZE-1]='\0';
}

int
main (int argc, char** argv)
{
    if(argc < 2) {
        printf("Hello World!\n");
        exit(0);
    }
    init_args();
    if(argv[1][0] == 'e') {
        int r = 0;
        int i;
        int tid[NUM_EXEC_CHILDS];

        for(i = 0; i < NUM_EXEC_CHILDS; i++) {
            tid[i] = exec(execs[i]);
        }
        for(i = 0; i < NUM_EXEC_CHILDS; i++) {
            if (tid[i] >= 0) {
                r = wait(tid[i]);
                printf("P child %d exited with exit code %d\n",i, r);
            } else {
                printf("P child %d failed to start\n", i);
            }
        }
    } else if(argv[1][0] == 'f') {
        char buf[10];
        int r;
        create ("test.txt", 10);
        int handle = open ("test.txt");
        if (handle < 2)
            printf ("open(test.txt) returned %d", handle);
        if ((r=write(handle,"987654321",10)) != 10) {
            printf("write failed: %d not %d\n",r,10);
            exit(1);
        }
        seek(handle,0);
        if ((r=read(handle, buf, 10)) != 10) {
            printf("read failed: %d not %d\n",r,10);
            exit(1);
        }
        printf("test.txt: %s\n", buf);
    } else if(argv[1][0] == 'F') {
        int j,i;
        create ("foo.txt", 10);
        for (j = 0; j < 5; j++) {
            for (i = 2; i <= MAX_FD; i++) {
                if (open ("foo.txt") < 0) {
                    printf("Opening the %d's file failed\n",i-2);
                    break;
                }
            }
            while(--i >= 2) {
                close (i);
            }
        }
    } else if(argv[1][0] == '0') {
        printf("Null pointer value is: %d\n",*((int*)NULL));
    } else if(argv[1][0] == 'h') {
        halt();
    } else if(argv[1][0] == 'p' && argc >= 3) {
        printf("%s\n", argv[2]);
    } else {
        printf("ARGV[1] is %s\n", argv[1]);
    }
    return 0;
}
