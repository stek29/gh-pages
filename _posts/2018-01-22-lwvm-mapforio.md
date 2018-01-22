---
title: LightweightVolumeManager::\_mapForIO
---

### Remounting root as RW on iOS
Obvioulsy, rootfs is mounted as readonly on iOS
To remount it as RW, an update mount can be made.

However, there are special checks preventing that:

- In mount_common: it doesn't allow MNT_UPDATE for vnode with VROOT flag set:

```c
	if (flags & MNT_UPDATE) {
		if ((vp->v_flag & VROOT) == 0) {
			error = EINVAL;
			goto out1;
		}
		...
	}
```

- [According](http://newosxbook.com/QiLin/qilin.pdf) to [Morpheus\_\_\_\_\_\_](https://twiiter.com/Morpheus\_\_\_\_\_\_), in sandbox's macf hooks

So to overcome that, `VROOT` is unset on `rootvnode->v_flag`, and `mount` is called.

### LwVM
See [theiphonewiki](https://www.theiphonewiki.com/wiki/LwVM).

tl;dr: iOS 5.0 - iOS 11.0 partition table & kext/iokit driver creating proxy GPT partition table.

During it's functioning, `LightweightVolumeManager::_mapForIO` is called.
There are some checks inside of that function, which don't allow mapping `/`.

See FriedAppleTeam's JailbreakDIY slides, page 40.
(note: `isRootWriteable` is actually `rootedRamdisk`)

### APFS & HFS
With transition to apfs, both `/` and `/var` are on same `apfs` container.
Because of that, `/` can't be ro.
Also, as of iOS 11, LightweightVolumeManager isn't used at all.

### Bypassing checks
There are two checks, i.e. mapping fails with error `0xE0002C4` if any of following are true:
- `(partitionIndex == 0) && (blockType == 2) && !rootedRamdisk() && !PE_i_can_has_kernel_configuration()` 
- `(blockType == 2) && (operation & 1) && partition->isWriteProtected()`
  (note: isWriteProtected is inlined in release kernels)

here's assembly:
```
BL              __ZL13rootedRamdiskv
MOV             X28, X0

...

// w27 -- blockType, w21 -- partition index
CMP             W27, #2
CSET            W8, EQ
CBNZ            W21, check2
EOR             W9, W28, #1
AND             W8, W8, W9
CBZ             W8, check2
BL              _PE_i_can_has_kernel_configuration
TBZ             W0, #0, fail

check2:
CMP             W27, #2
B.NE            canMap
TBNZ            W26, #0, canMap
LDR             X8, [X20,#0x1A0]
LDRB            W8, [X8,#0x28]
CBZ             W8, canMap

fail:
; return "the device is write locked" here

canMap:

; continue mapping

```

Usually they're bypassed by changing `PE_i_can_has_kernel_configuration`'s entry in `__got` to ret1 gadget, and jumping over `partition->isWriteProtected` check.

However, that won't work reliably without KPP bypass and won't work at all on KTRR devices.
So, different methods are needed.

Let's start with easier one

### partition->isWriteProtected
LightweightVolumeManager has internal array of pointers to `LwVMPartiton`
It's located at offset 0x1A0.
(And at offset 0x198 it has actual size of array).

Normally the size is 3:
- 0 is `/` (System)
- 1 is `/var` (Data)
- 2 is Baseband

`LwVMPartiton` has `bool isWriteProtected` at offset 0x28.
If that flag is set, mapping would obviously fail.

To unset that flag, we have to locate `LightweightVolumeManagerInstance`, and do something like:
`(uint8_t*)(uint8_t* LightweightVolumeManagerInstance)[0x1A0][0x28] = 0`

Finding `LightweightVolumeManagerInstance` is easy: open io_service_t for it, find it's in-kernel address, and read kobject from that port.

Here's sample code from Meredian:

```c
const unsigned OFF_LWVM__PARTITIONS = 0x1a0;
const unsigned OFF_LWVMPART__ISWP = 0x28;

void fix_root_iswriteprotected(void) {
	io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("LightweightVolumeManager"));
	uint64_t inkernel = find_port_address(service);

	uint64_t lwvm_kaddr = rk64(inkernel + OFF_IPC_PORT__IP_KOBJECT);
	uint64_t rootp_kaddr = rk64(lwvm_kaddr + OFF_LWVM__PARTITIONS);
	uint64_t rootp_iswp_addr = rootp_kaddr + OFF_LWVMPART__ISWP;
	// assert(rk64(rootp_iswp_addr) == 1)
	wk64(rootp_iswp_addr, 0);
}
```

### rootedRamdisk
Here's reversed source of that function:

```c
boolean_t PE_parse_boot_argn(const char* arg_string, void *arg_ptr, int max_len);

bool rootedRamdisk(void) {
	char root[32];
	boolean_t parsed;

	if (!PE_parse_boot_argn("rd", root, sizeof(root))
		&& !PE_parse_boot_argn("rootdev", root, sizeof(root))) {
		return false;
	}

	return
		root[0] == 'm' &&
		root[1] == 'd' &&
		// root[3] doesn't matter		
		root[0] == '\0';
}
```

So, it checks if boot arg `rd=mdX` / `rootdev=mdX` is there, and if it's not `false` is returned.

here's `PE_parse_boot_argn`:

```c
boolean_t
PE_parse_boot_argn(const char *arg_string, void *arg_ptr, int max_len)
{
    return PE_parse_boot_argn_internal(arg_string, arg_ptr, max_len, FALSE);
}
```

`PE_parse_boot_argn_internal` gets boot args cmdline with `PE_boot_args` and parses that.

```c
typedef struct PE_state {
    boolean_t    initialized;
    PE_Video    video;
    void        *deviceTreeHead;
    void        *bootArgs;
} PE_state_t;


char *
PE_boot_args(
    void)
{
    return (char *)((boot_args *)PE_state.bootArgs)->CommandLine;
}
```

`boot_args` is platform-specific, here's it's `arm` definition:

```c
typedef struct boot_args {
    uint16_t        Revision;            /* Revision of boot_args structure */
    uint16_t        Version;            /* Version of boot_args structure */
    uint64_t        virtBase;            /* Virtual base of memory */
    uint64_t        physBase;            /* Physical base of memory */
    uint64_t        memSize;            /* Size of memory */
    uint64_t        topOfKernelData;    /* Highest physical address used in kernel data area */
    Boot_Video        Video;                /* Video Information */
    uint32_t        machineType;        /* Machine Type */
    void            *deviceTreeP;        /* Base of flattened device tree */
    uint32_t        deviceTreeLength;    /* Length of flattened tree */
    char            CommandLine[BOOT_LINE_LENGTH];    /* Passed in command line */
    uint64_t        bootFlags;        /* Additional flags specified by the bootloader */
    uint64_t        memSizeActual;        /* Actual size of memory */
} boot_args;
```

looking through assembly gets us to following code in `PE_parse_boot_argn_internal`:

```
ADR             X8, _PE_state
LDR             X26, [X8, #0xA0]
LDRB            W21, [X26, #0x6C]!
```

From here we can see where `PE_state` is, see that `PE_state->bootArgs` is at offset `0xa0` and `boot_args.CommandLine` is at offset `0x6c`.

`_PE_state` is obviously in `__bss`, and `boot_args` seems to be in rw memory too.

To verify our findings, we can write some string into that memory and use `sysctl kern.bootargs` to retrieve it.

So, `rd=md0` can be added into `boot_args.CommandLine` to make `rootedRamdisk` return `true`.

Sample code from Meredian:

```c
void fake_rootedramdisk(void) {
	unsigned cmdline_offset;
	uint64_t pestate_bootargs = find_boot_args(&cmdline_offset);

	if (pestate_bootargs == 0) {
		return;
	}

	uint64_t struct_boot_args = rk64(pestate_bootargs);
	uint64_t boot_args_cmdline = struct_boot_args + cmdline_offset;

	// max size is 256 on arm
	char buf_bootargs[256];

	rkbuffer(boot_args_cmdline, buf_bootargs, sizeof(buf_bootargs));
	strcat(buf_bootargs, " rd=md0 ");
	wkbuffer(boot_args_cmdline, buf_bootargs, sizeof(buf_bootargs));
}
```

