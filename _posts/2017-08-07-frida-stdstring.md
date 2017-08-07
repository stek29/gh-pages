---
title: Frida and std::string
---

## What's this about?
I was looking through issues on [frida-core](https://github.com/frida/frida-core), and [#124](https://github.com/frida/frida-core/issues/124) got my attention. 
Here's the question:

>How do I print the value of the third argument for this function?
>
> ```cpp
>CommonUtils::decodeCStringForBase64(char const*, char const*, std::string &)
> ```
>
>Currently I can print the first and second argument by using `Memory.readUtf8String`.

So let's have a look on how to print that argument, by digging into how C++ compiler and linker work.

## The plan

Most obvious way to print std::string with [Frida](https://frida.re) is to use [`std::string::c_str()`](http://en.cppreference.com/w/cpp/string/basic_string/c_str) to get `char *`:

> `const char* c_str() const;`
> 
> Returns a pointer to a null-terminated character array with data equivalent to those stored in the string.

Then we could use `Memory.readUtf8String` on returned pointer. Should be easy, huh?

## Setup
All of this was written and tested on x86_64 macOS.

I'm going to intercept calls to `interceptMe` function in following `target.cpp`:

```cpp
#include <string>
#include <iostream>

void interceptMe(std::string &str) {
  std::cout << str << std::endl;
}

int main(void) {
  std::string s;
  while (std::cin) {
    std::getline(std::cin, s);
    interceptMe(s);
  }

  return EXIT_SUCCESS;
}
```

I'll use Frida's JS CLI in this article

## Finding the function

Let's get address of `interceptMe` first:

```
[Local::ProcName::target]-> Module.enumerateExportsSync('target').filter(function(exp) { return exp.name.indexOf('interceptMe') !== -1; })
[
    {
        "address": "0x101fc43d0",
        "name": "\_Z11interceptMeRNSt3\_\_112basic\_stringIcNS\_11char\_traitsIcEENS\_9allocatorIcEEEE",
        "type": "function"
    }
]
```

I'm not using `Module.findExportByName` here because of name mangling, which is going to be discussed later.

## Passing by refrence

Usually passing objects by refrence is actually passing by pointer with "syntactic sugar". C++ standard doesn't define how it has to be implemented, but almost always it's implemented as a wrapped pointer.
So we can just interpret the first parameter of `interceptMe` as pointer to `std::string`.

## Calling convention
[Interceptor.attach knows nothing about ABIs and calling conventions](https://t.me/fridadotre/7151), so there's no easy way to extract function args in frida (using frida-trace via frida-compile can possibly help, but I haven't tried it yet)

x86_64 macOS [uses](https://developer.apple.com/library/content/documentation/DeveloperTools/Conceptual/LowLevelABI/140-x86-64_Function_Calling_Conventions/x86_64.html) SystemV AMD64 ABI's calling convention.
Which means that first argument to `interceptMe` would be passed in RDI register, which is accessible in Interceptor.attach callbacks through `this.context.rdi`.

Let's try it:
```
[Local::ProcName::target]-> Interceptor.attach(ptr("0x103e2c3d0"), function() { console.log(this.context.rdi); })
```

Now switch back to terminal with target and type something, while looking at terminal with frida. You'll quickly see some address logged. It would stay the same though, since we are always passing same object to `interceptMe`.

## Getting string contents -- The easy way
What if you had some function which accepts pointer to `std::string` and returns it's `::c_str()`?
It'd be cool, right? But sadly our target doesn't have that function, and finding it in libc++ is hard.
But wait, can't we just "inject" our C++ code into target?
Good news: we can -- by making a dynamic library of it.

### Shared libraries
Dynamic|shared libraries|objects are out of topic of this article. Let me [quote Wikipedia](https://en.wikipedia.org/wiki/Shared_library):
> A shared library or shared object is a file that is intended to be shared by executable files and further shared object files. Modules used by a program are loaded from individual shared objects into memory at load time or run time, rather than being copied by a linker when it creates a single monolithic executable file for the program.

### Making a dylib
Let's make a simple function which accepts refrence to `std::string` and returns it's `::c_str()`:

```cpp
#include <string>
extern "C" {
const char *toUTF8Ref(std::string &str) {
  return str.c_str();
}
}
```

`extern "C"` disables some C++ features, most importantly name mangling (hold on, you're almost there!) for functions. Which means it would be much easier to load our function in runtime.

Compile it with clang:
`clang -dynamiclib getstr_dl.cpp -lc++ -o getstr_dl.dylib`

### Loading the lib
Sadly, frida doesn't have any module for a convinient work with dynamic libs.
POSIX standartizes set of function to work with dynamic libraries, which are declared in `dlfcn.h`.
We'll need `dlopen`, `dlsym` (and `dlclose` to tidy up).
Have a look at [`dlopen(3)`](https://linux.die.net/man/3/dlopen):

> `void *dlopen(const char *filename, int flag);`
> The function dlopen() loads the dynamic library file named by the null-terminated string filename and returns an opaque "handle" for the dynamic library. If filename contains a slash ("/"), then it is interpreted as a (relative or absolute) pathname. 

> `void *dlsym(void *handle, const char *symbol);`
> The function dlsym() takes a "handle" of a dynamic library returned by dlopen() and the null-terminated symbol name, returning the address where that symbol is loaded into memory. 

Here's how you'd load our `toUTF8Ref` in C++:

```cpp
void *handle = dlopen("/path/to/getstr_dl.dylib", RTLD_LAZY); // or RTLD_NOW, doesn't really matter here
void *toUTF8Ref_ptr = dlsym(handle, "toUTF8Ref");
/* use toUTF8Ref_ptr */
dlclose(handle);
```

Same thing can be easily done in frida. Let's get `dlopen` and `dlsym` functions:
```javascript
const dlopen = new NativeFunction(Module.findExportByName(null, 'dlopen'), 'pointer', ['pointer', 'int'])
const dlsym = new NativeFunction(Module.findExportByName(null, 'dlsym'), 'pointer', ['pointer', 'pointer'])
```

But what about `RTLD_LAZY` | `RTLD_NOW`? Just look them up at your platform's `dlfcn.h`. For macOS `RTLD_LAZY` is defined as `0x1`
```javascript
const RTLD_LAZY = 1;
```

Now load `getstr_dl` and get the handle:
```javascript
var handle = dlopen("/path/to/getstr_dl.dylib", 1);
```
Or **Error: invalid argument value** instead of it...
We have to alloc all the strings in process memory first, we can't pass JS strings to NativeFunction!
```javascript
var path = Memory.allocUtf8String("/path/to/getstr_dl.dylib");
var symb = Memory.allocUtf8String("toUTF8Ref");
```

Now finally load it and get address of `toUTF8Ref`:
```javascript
var handle = dlopen("/path/to/getstr_dl.dylib", 1);
var toUTF8Ref_ptr = dlsym(handle, symb);
```

And make a NativeFunction of it:
```
var toUTF8Ref = new NativeFunction(toUTF8Ref_ptr, 'pointer', ['pointer']);
```

### Using the lib
We know how to get pointer to string passed to `inteceptMe`, and how to get `::c_str()` of it using our dylib. Let's put everything together:
```javascript
Interceptor.attach(ptr("0x103e2c3d0"), function() {
	console.log(Memory.readUtf8String(
		toUTF8Ref(this.context.rdi)
	)); 
})
```

Switch back to `interceptMe` again, and type `Frida is cool`. See the same string printed in terminal with frida. Viola.

## The hard way
### Name mangling

C++ has amazing features: classes, templates, namespaces, function overloading and etc.
But linker knows nothing about those features, and that's why name mangling is used by compiler:

> [Name mangling is the encoding of function and variable names into unique names so that linkers can separate common names in the language.](https://www.ibm.com/support/knowledgecenter/en/ssw_ibm_i_72/rzarg/name_mangling.htm)

Unfortunately, C++ does not have a standard mangling scheme, so each compiler uses its own.
In fact, C++ has no standard ABI, which introduces other problems for reverse engeneering.
However, modern GCC, Clang and Intel complier use the same scheme, compilant with Itanium C++ ABI.

You can read more about C++ Name mangling and demangling [here](https://blog.oakbits.com/index.php?post/2016/03/02/Finding-The-Mangled-Name-Of-A-C-Method)

However, most easy way to get needed symbol is... just to grep libc++ symbols!

### Finding the symbol
In C++ `std::string` is `std::basic_string<char>`, so we want `std::basic_string<char, ...>::c_str()`.
Let's get symbols from libc++ and grep them:
```
$ nm /usr/lib/libc++.dylib | grep basic_string | grep 5c_str
000000000003f450 t __ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE5c_strEv
0000000000042882 t __ZNKSt3__112basic_stringIwNS_11char_traitsIwEENS_9allocatorIwEEE5c_strEv
```

I'm using `5c_str` and not just `c_str` because `basic_string` contains `c_str`, and thus latter wouldn't be effective. (And because I know that `"c_str".length === 5" :D)

Demangle those names (use c++filt or [demangler.com](https://demangler.com)):
```cpp
_std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::c_str() const
_std::__1::basic_string<wchar_t, std::__1::char_traits<wchar_t>, std::__1::allocator<wchar_t> >::c_str() const
```

Ok, so we need first one, which has offset `0x3f450`.

### Intance methods
C++ instance methods usually have implicit parameter `this`, which points to instance method is called on.
I wasn't able to find any good references on this, so here's my horrible example (it's even more horrible because of my poor knowledge of asm). If you know a better argument/demonstration please share it with me.

```cpp
class Cls { 
public:
	int z; // for padding
	int y = 0; // to force default ctor
	void bar(int x) {
		y += x;
	};
};

int main(void) {
	Cls inst;
	inst.bar(3);
}
```

Let's compile and disassemble it:

```assembly
_main:
0000000100000f10	pushq	%rbp
0000000100000f11	movq	%rsp, %rbp
0000000100000f14	subq	$0x10, %rsp
0000000100000f18	leaq	-0x8(%rbp), %rdi
0000000100000f1c	callq	__ZN3ClsC1Ev ## Cls::Cls()
0000000100000f21	leaq	-0x8(%rbp), %rdi
0000000100000f25	movl	$0x3, %esi
0000000100000f2a	callq	0x100000f96 ## symbol stub for: __ZN3Cls3barEi
0000000100000f2f	xorl	%eax, %eax
0000000100000f31	addq	$0x10, %rsp
0000000100000f35	popq	%rbp
0000000100000f36	retq
0000000100000f37	nopw	(%rax,%rax)
__ZN3ClsC1Ev:
0000000100000f40	pushq	%rbp
0000000100000f41	movq	%rsp, %rbp
0000000100000f44	subq	$0x10, %rsp
0000000100000f48	movq	%rdi, -0x8(%rbp)
0000000100000f4c	movq	-0x8(%rbp), %rdi
0000000100000f50	callq	__ZN3ClsC2Ev ## Cls::Cls()
0000000100000f55	addq	$0x10, %rsp
0000000100000f59	popq	%rbp
0000000100000f5a	retq
0000000100000f5b	nopl	(%rax,%rax)
__ZN3Cls3barEi:
0000000100000f60	pushq	%rbp
0000000100000f61	movq	%rsp, %rbp
0000000100000f64	movq	%rdi, -0x8(%rbp)
0000000100000f68	movl	%esi, -0xc(%rbp)
0000000100000f6b	movq	-0x8(%rbp), %rdi
0000000100000f6f	movl	-0xc(%rbp), %esi
0000000100000f72	addl	0x4(%rdi), %esi
0000000100000f75	movl	%esi, 0x4(%rdi)
0000000100000f78	popq	%rbp
0000000100000f79	retq
0000000100000f7a	nopw	(%rax,%rax)
__ZN3ClsC2Ev:
0000000100000f80	pushq	%rbp
0000000100000f81	movq	%rsp, %rbp
0000000100000f84	movq	%rdi, -0x8(%rbp)
0000000100000f88	movq	-0x8(%rbp), %rdi
0000000100000f8c	movl	$0x0, 0x4(%rdi)
0000000100000f93	popq	%rbp
0000000100000f94	retq
```

Let's start with `_main`.
After `leaq` on `..f18` line `rdi` contains address of `inst`, which is stored on stack.
Then `Cls::Cls()` is called. As we know from calling conventions section, `rdi` contains first integer or pointer argument.
After inst is initialized `rdi` is reloaded again, and `0x3` is loaded to `rsi` (`esi` is the same register but with different size).
And `Cls::bar(int)` is called. And as we know, `rdi` has first argument and `rsi` has second argument.
So actually `Cls::bar(int)` has an implicit first argument `Cls * const this` and second argument `int x`.

Now look at `Cls::Cls()`. After some `call`s it ends at `..f8c` and moves `0x0` to address at `rdi + 4 bytes`.
And `y` has offset of 4 bytes in `Cls` because first 4 bytes are used for `z`.

Let's have a look at `Cls::bar(int)` too.
The only useful instruction is `add` on `..f72`: `rsi` is added at address calculated as `rdi + 4 bytes` on `..f72` line.

So we can see once more that `this` is passed as implicit argument to any non-static member function.

So, `std::string`'s `c_str` implementation would have pointer to string as first argument and would return pointer to char array.

### Making a NativeFunction
Sadly, frida doesn't have an API to access "private" symbols currently (`Modules.enumerateSymbols` would be nice :D).
And needed symbol is private -- notice the small `t` in nm output.
So we'll just use offset from nm output, and add it to the base address of libc++.1.dylib:

```javascript
var string_c_str_ptr = Module.findBaseAddress('libc++.1.dylib').add(0x3f450);
var string_c_str = new NativeFunction(string_c_str_ptr, 'pointer', ['pointer']);
```

UPD: looks like `Module.enumerateSymbols` was added into frida. I'm still leaving this to demonstrate how custom offsets can be used.

### Attaching
We should use the same code as we had with toUTF8Ref:

```javascript
Interceptor.attach(ptr("0x103e2c3d0"), function() {
	console.log(Memory.readUtf8String(
		string_c_str(this.context.rdi)
	)); 
})
```

Switch back to `interceptMe` once more, and type `I love Frida <3`. See the same string printed in terminal with frida. We did it once again, yay :D