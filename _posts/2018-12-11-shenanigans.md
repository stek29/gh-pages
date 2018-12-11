---
title: Shenanigans, Shenanigans!
---

## Requiring privileges
Some kernel APIs should be restricted only to "special" binaries/users.

Here's an example, from `fs_snapshot` syscall, on how it's often done on kernel side:

```c
int
fs_snapshot(__unused proc_t p, struct fs_snapshot_args *uap,
    __unused int32_t *retval)
{
	int error;
	vfs_context_t ctx = vfs_context_current();

	error = priv_check_cred(vfs_context_ucred(ctx), PRIV_VFS_SNAPSHOT, 0);
	if (error)
		return (error);
	// perform requested action -- userland has required privileges
}
```

And `priv_check_cred` is essentially a wrapper for `mac_priv_check` + `mac_priv_grant`, which have similar structure:

```c
int
mac_priv_check(kauth_cred_t cred, int priv)
{
	int error;

	if (!mac_cred_check_enforce(cred))
		return 0;

	MAC_CHECK(priv_check, cred, priv);

	return (error);
}
```

As you can see, those functions don't even get to callout to MACF policies if `mac_cred_check_enforce` returns false.

```c
static __inline__ bool mac_cred_check_enforce(kauth_cred_t cred)
{
	return (cred != proc_ucred(kernproc));
}
```

## Getting the privileges
So, if you want the privilege to be granted, you either should actually posess everything that is required for that, or have kernel's ucred.

The latter was the standard approach before iOS 11:

<blockquote class="twitter-tweet" data-cards="hidden" data-lang="en"><p lang="en" dir="ltr">It causes panic on iOS 11, quite sure it&#39;s not because of refs.<br><br>IIRC &amp; If I reversed correctly It tests something related to kernel&#39;s task/proc directly, and causes panic with &quot;shenanigans&quot; in message.<br><br>Example of panic log: <a href="https://t.co/JjU4Bb5BM8">https://t.co/JjU4Bb5BM8</a></p>&mdash; Viktor Oreshkin (@stek29) <a href="https://twitter.com/stek29/status/946473221020372992?ref_src=twsrc%5Etfw">December 28, 2017</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

So, starting with iOS 11 it no longer works -- simply "stealing" kernel's ucred unleashes panic on you with meaningless message.

So, everyone just switched to the former approach:
- if you need to be root -- just patch up your posix part of ucred (uid/gid and friends)
- to bypass some checks just zero out your macf label's perpolicy slots
- if that doesn't work, hotswap amfi's perpolicy slot with OSDictionary containing arbitrary entitlements
- or just execute a program which does have privileges you need, sigstop it, and steal it's ucred

## Looking deeper into mitigation
Searching for panic string or looking at panic backtrace quickly leads to following snippet in the sandbox kext:

```c
void sb_evaluate(uint64_t retbuf[3], void *sbx_mac_ctx, unsigned int op, sbx_ctx_t* sbx_ctx) {
  uint64_t retval[3] = {0};

  retval[0] = (uint32_t) derive_cred(sbx_ctx);
  if (LOW(retval[0])) {
  	HIGH(retval[0]) = 1;
  	goto end;
  }

  struct ucred* cur_ucred = sbx_ctx->ucred;
  // struct ucred *is_kernel_cred_kerncred is a global variable
  struct ucred* kernel_cred = is_kernel_cred_kerncred;
  if (!kernel_cred) {
    struct ucred* tmp = kauth_cred_proc_ref(kernproc);
    if (!OSCompareAndSwapPtr(NULL, &tmp, &is_kernel_cred_kerncred)) {
      kauth_cred_unref(tmp);
    }
    kernel_cred = is_kernel_cred_kerncred;
  }

  if (kernel_cred == cur_ucred) {
    if (!sbx_ctx->refheld_proc) {
      cur_proc = sbx_ctx->proc;
      if (cur_proc && cur_proc != kernproc) {
          panic("\"shenanigans!\"");
      }
    }
    retval[2] = 0;
    retval[1] = 0;
    retval[0] = 0;
    goto end;
  }

  // actual checks using eval

end:
  if (!sbx_ctx->no_free) {
    free_filter_context(sbx_ctx, sbx_mac_ctx);
  }

  retbuf[2] = retval[2];
  retbuf[1] = retval[1];
  retbuf[0] = retval[0];
}
```

So, the sb_evaluate explicitly checks against kernel ucred and allows everything without even eval'ing.
However, it also checks that proc matches kernproc -- and panics otherwise.

The address of kernel's ucred is cached in a global pointer `is_kernel_cred_kerncred`, which is set on first access and cached afterwards.

## Bypass
So, if the cached pointer is not null and is not equal to any ucred pointer, the check would be always skipped -- so, just overwrite the `is_kernel_cred_kerncred` with invalid kernel pointer (0xca13feba37be :) to never see shenanigans panic.

I am not sure what the consequences of (possibly) rejecting kernel in sandbox might be, so it'd be better to reverse the overwrite once kernel ucred is no longer possessed by your proc.

IMO, it's yet another example of mitigation which does nothing against malware writers, but does cause problems for jailbreakers.

Sorry if I'm making your private technique public :(
Also, I won't be surprised if apple moves the `is_kernel_cred_kerncred` into const section and initializes it with kext initializers -- or even refactors everything and exposes a new symbol for kernel's ucred.

P.S. thanks for asking me questions which make me want to reverse things to answer them, and thanks for the article name -- you know who you are.

## Patchfinder

### Extending patchfinder
patchfinder everyone and their dog are using only considers following type of function prologue when looking for start of function:

```asm
STP X, X, [SP, #imm1]!
STP X, X, [SP, #imm2]
STP X, X, [SP, #imm3]
...
ADD X29, SP, #addimm
```

It could be detected by looking for `ADD X29, SP, #addimm` and then for `STP X, X, [SP, #imm1]!`.
And number of stps would be `addimm/16 + 1` (1 for STP!).

However, at least in iOS 11.3.1, another type of prologue can be found (when function has larger stack?):

```asm
SUB SP, SP, #subimm
STP X, X, [SP, #imm1]
STP X, X, [SP, #imm2]
//...
ADD X29, SP, #addimm
```

It could be detected by looking for `ADD X29, SP, #addimm`, and then for `SUB SP, SP, #subimm` within `addimm/16 + 1` instructions, and checking that all instructions between ADD and SUB are STP/STR.

So, here's the patch for bof64:
```c
// after this original code
addr_t prev = where - ((delta >> 4) + 1) * 4;
uint32_t au = *(uint32_t *)(buf + prev);
if ((au & 0xFFC003E0) == 0xA98003E0) {
    // printf("%x: STP x, y, [SP,#-imm]!\n", prev);
    return prev;
}

// add this code
for (addr_t diff = 4; diff < delta/4+4; diff+=4) {
    uint32_t ai = *(uint32_t *)(buf + where - diff);
    // SUB SP, SP, #imm
    if ((ai&0xFFC003FF) == 0xD10003FF) {
        return where - diff;
    }
    // Not stp and not str
    if (((ai & 0xFFC003E0) != 0xA90003E0) && (ai&0xFFC001F0) != 0xF90001E0) {
        break;
    }
}
```

### Finding the variable

- Panic happens in `sb_evaluate`
- `_is_kernel_cred_kerncred` is the first thing referenced in it


```asm
ADRP  X24, #_is_kernel_cred_kerncred@PAGE
LDR   X8, [X24,#_is_kernel_cred_kerncred@PAGEOFF]
CBNZ  X8, ...
```

So, here's what patchfinder does:

- find xref to `shenanigans` panic string (in prelink)
- find start of function (that's `sb_evaluate`)
- find first adrp/ldr pair
- make sure it's followed by cbnz

```c
addr_t find_shenanigans(void) {
    addr_t ref = find_strref("\"shenanigans!", 1, 1);
    ref -= kerndumpbase;

    // find sb_evaluate
    ref = bof64(kernel, prelink_base, ref);

    // ADRP Xm, #_is_kernel_cred_kerncred@PAGE
    ref = step64(kernel, ref, 0x100, 0x90000000, 0x9F000000);

    // pc base
    uint64_t val = kerndumpbase;

    uint32_t *insn = (uint32_t*)(kernel+ref);
    // add pc (well, offset)
    val += ((uint8_t*)(insn) - kernel) & ~0xfff;
    uint8_t xm = *insn & 0x1f;
    
    // add imm: immhi(bits 23-5)|immlo(bits 30-29)
    val += (*insn<<9 & 0x1ffffc000) | (*insn>>17 & 0x3000);

    ++insn;
    // LDR Xn, [Xm,#_is_kernel_cred_kerncred@PAGEOFF]
    if ((*insn & 0xF9C00000) != 0xF9400000) {
        return 0;
    }
    if (((*insn>>5)&0x1f) != xm) {
        return 0;
    }
    // add pageoff
    val += ((*insn >> 10) & 0xFFF) << 3;
    uint8_t xn = (*insn&0x1f);

    ++insn;
    // CBNZ Xn, ...
    if ((*insn & 0xFC000000) != 0xB4000000) {
        return 0;
    }
    if ((*insn & 0x1f) != xn) {
        return 0;
    }
    
    return val;
}
```