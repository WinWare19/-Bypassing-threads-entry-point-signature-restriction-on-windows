The famous method to create a new thread on windows is the KERNEL32!CreateThread  function , it takes few parameters including the thread starting point.
Unfortunately, the starting point must have this signature DWORD __stdcall StartingPoint(LPVOID param) which restricts it to accept only one parameter.

This is not actually a huge problem as  the parameter isn't used in most cases, so you don't need parameters at all. But what if you were in a case where you need to create a thread that must start with more than one parameter, is it possible to do that ?

The answer is yes, i've written this simple c code that is valid on both x86 and x64 architectures, it create a simple thread that has a function that takes four parameters as it's starting point and also it shows you how to manually setup a stack frame on both architectures.
