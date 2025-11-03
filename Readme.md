PPPoE Receive Side Scaling implementation leveraging XDP cpumaps or ... how to make PPP go vrooooom.

## Motivation
https://cehrig.dev/braindumps/2025-10-16-multi-threaded-pppoe-using-xdp.html

TLDR: Prevent single-core interrupt floods
```
Tasks: 174 total,   3 running, 171 sleeping,   0 stopped,   0 zombie
%Cpu0  :  0.0 us,  0.0 sy,  0.0 ni,100.0 id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st 
%Cpu1  :  2.0 us,  0.0 sy,  0.0 ni, 98.0 id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st 
%Cpu2  :  0.0 us,  0.0 sy,  0.0 ni,100.0 id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st 
%Cpu3  :  0.0 us,  0.0 sy,  0.0 ni,100.0 id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st 
%Cpu4  :  0.0 us,  0.0 sy,  0.0 ni,100.0 id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st 
%Cpu5  :  0.0 us,  0.0 sy,  0.0 ni,100.0 id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st 
%Cpu6  :  0.0 us,  0.0 sy,  0.0 ni,  0.0 id,  0.0 wa,  0.0 hi,100.0 si,  0.0 st 
%Cpu7  :  2.0 us,  0.0 sy,  0.0 ni, 98.0 id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st 
MiB Mem :   3920.2 total,   3177.8 free,    532.6 used,    424.6 buff/cache     
MiB Swap:    980.0 total,    980.0 free,      0.0 used.   3387.6 avail Mem 

    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND                                                                                                                                                                
     57 root      20   0       0      0      0 R  94.1   0.0   2:12.61 ksoftirqd/6
```

## Build
Adjust `MAX_CPU` for maximum vrooom.
```
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -c ppp-xdp-kern.c -o ppp-xdp-kern.o
```

## Attach
Attach this program to your physical device. `enp1s0f0` as an example. `xdpdrv` because my X710 supports XDP driver mode.
```
ip link set dev enp1s0f0 xdpdrv object ppp-xdp-kern.o sec xdp
```

## Configure cpumap
Write queue size for each CPU core
```
$ bpftool map update name cpu_map key 0x00 0x00 0x00 0x00 value 0x00 0x40 0x00 0x00
$ bpftool map update name cpu_map key 0x01 0x00 0x00 0x00 value 0x00 0x40 0x00 0x00
$ bpftool map update name cpu_map key 0x02 0x00 0x00 0x00 value 0x00 0x40 0x00 0x00
...
```

## Speed
![Speed Test](vroom.png)