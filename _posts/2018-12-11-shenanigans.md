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