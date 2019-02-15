---
title: TouchBar overflow
---

[Duo Labs have recently published another post in their series on T2 coprocessor/iBridge](https://duo.com/labs/research/apple-t2-xpc). Kinda sad they've "burned" remotectl tho -- Apple worked so hard on restricting coproc interface, and left such a usefult debugging tool for good guys to (ab)use!

That reminded me of my long abandoned research on first gen touchbar, and I've decieded to publish it, considering that I'm likely not going to get back to it.

There's a very dumb stack overflow vulnerability in eosd -- one of the main daemons which runs as unsandboxed root -- on first gen iBridge.

Both eosd (on iBridge) and EmbeddedOSSupportHost.framework (on macOS) have common utility functions for eos_message's. For more info, have a look at [github repo supplementing this post](https://github.com/stek29/touchbar_overflow).

They're serialized into header and payload. Header has fixed size -- at most 4+512 bytes (have a look at `eos_message_serialized` in the `EmbeddedOSSupportHost.h`).

eos utilizes a wrapper around `recv(2)` which keeps calling recv until it receives exact amount of bytes it wants (since `recv` can return less bytes then specified).

When new message is recieved on socket, `eos_message_recieve` is called (see supplimentary repo), which contains following code:
```c
struct eos_message_serialized message = {};
int rv = 0;

rv = recv_all((int) conn, &message.raw_header_len, sizeof(message.raw_header_len));
if (!rv) {
	LOG("Cant recv incoming header length");
	goto endret;
}

// Not present in older versions (i.e. on first gen iBridge on touchbars)
if (message.raw_header_len > sizeof(message.header)) {
	LOG("Header length too large");
	goto endret;
}

rv = recv_all((int) conn, &message.header, message.raw_header_len);
if (!rv) {
	LOG("Cant recv incoming header");
	goto endret;
}
```

Notice the check for `raw_header_len` being less than allocated buffer: That check wasn't present on older version of code which is used on iBridge1,1.
Essentially, it boils down to following:

```c
void iamvulnerable(int sock) {
	uint32_t size;
	char buffer[0x100];
	recv_all(sock, &size, sizeof(size));
	recv_all(sock, buffer, size); // size might be greater than sizeof(buffer)!
}
```

Textbook example of stack buffer overflow (`s/gets/recv/g`) in software critical for $3000 machine.

And here's the best part: It's fixed in `EmbeddedOSSupportHost.framework`!

So, Apple has found and fixed this truly dumb vuln by themselves, but hasn't bothered to issue new version of OS for iBridge1,1!

I was planning to dig deeper into it: exploit terribly old kernel, and start looking further, but:
- I didn't have much time
- It'd be quite useless considering that Apple has ditched T1 coprocessor in newer models.
- It is very easy to find

So, that's the reason I am dropping -- and the fact that vuln is very, very easy to spot, and is fixed for sure in newer versions.

Finally, here's the demo (see `poc.sh` in the [repo](https://github.com/stek29/touchbar_overflow)):
[![asciicast](https://asciinema.org/a/FjTSc8YtedqYNd6tHsEniOxjv.svg)](https://asciinema.org/a/FjTSc8YtedqYNd6tHsEniOxjv)

Sorry for all the typos -- didn't have much time to do this nicely, and if I didn't do it now, I'd most likely put it off again.

UPDATE:

btw, if eosd keeps crashing, it doesn't reply to `watchd` watchdog, which makes `watchd` cause panic of touchbar, which makes host panic -- abuse TouchBar to DoS the host :)

Oh, and just for the reference, I think I found this like a year ago (Feb 2018) -- judging by tweets I made on TouchBar from that time and by private discussions I've had about the vuln.
