/* Read-only KernelSU v3.3.1 UAPI probe. No module load/unload or device reboot.
 * Interface: vendor/KernelSU at 0c0fdb960178fa12d80d6cbcfdcb6ad8be6a865d. */
#include <dirent.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>
int main(void) {
    DIR *d=opendir("/proc/self/fd"); if(!d) return 2;
    int fd=-1; struct dirent *e;
    while((e=readdir(d))) {
        char *end, path[128], target[256]; long n=strtol(e->d_name,&end,10);
        if(!e->d_name[0] || *end || n<0 || n>1000000) continue;
        snprintf(path,sizeof(path),"/proc/self/fd/%ld",n);
        ssize_t size=readlink(path,target,sizeof(target)-1); if(size<0) continue;
        target[size]=0;
        if(!strcmp(target,"anon_inode:[ksu_driver]") || !strcmp(target,"anon_inode:[ksu_driver_su]")) { fd=(int)n; break; }
    }
    closedir(d);
    if(fd<0) {
        /* Official KernelSU driver-FD acquisition ABI. These magic numbers are
         * deliberately different from Linux reboot magic: unhandled -> EINVAL,
         * never a reboot. It only returns an anonymous ioctl FD. */
        syscall(SYS_reboot,0xDEADBEEFUL,0xCAFEBABEUL,0,&fd);
    }
    if(fd<0) { fprintf(stderr,"PROBE_NO_DRIVER_FD\n"); return 3; }
    uint32_t appid=0xffffffffu;
    if(ioctl(fd,_IOC(_IOC_READ,'K',10,0),&appid)) { perror("GET_MANAGER_APPID"); return 4; }
    printf("manager_appid=%u\n",appid);
    return 0;
}
