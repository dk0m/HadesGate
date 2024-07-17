
# HadesGate

A New Method Of Retrieving System Call Service Numbers By Parsing NtOsKrnl Exports.


## How Does It Work?

If we open ```ntoskrnl.exe``` in IDA, And search for functions with the **Zw** prefix and select a random one, For example **ZwAlpcCreatePort**, We will find this:

```
public ZwAlpcCreatePort
ZwAlpcCreatePort proc near
mov     rax, rsp
cli
sub     rsp, 10h
push    rax
pushfq
push    10h
lea     rax, nullsub_4
push    rax
mov     eax, 7Bh <--- This is the SSN
jmp     sub_140411580
ZwAlpcCreatePort endp
```

So what **HadesGate** does is parse the exports, Look for functions with the **Zw** prefix, Go through the stub's memory until we find a **0xB8** opcode in the stub, Which indicates we are currently going through the **mov eax, SSN** line, Then HadesGate extracts the SSN from the function and returns.

## Problems With It
This method will NOT get you every single **SSN** you want, So I wouldn't suggest using it in a real engagement unless the system calls you need are exported in **ntoskrnl.exe**.

