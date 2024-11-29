#include <iostream>
#include <Windows.h>

void __stdcall CustomThreadEntryPoint(int param1, int param2, LPCSTR param3, LPCSTR param4) {
	printf_s("param1 : %d\n", param1);
	printf_s("param2 : %d\n", param2);
	printf_s("param3 : %s\n", param3);
	printf_s("param4 : %s\n", param4);
}


int main() {

	// creating our thread in a suspended state and without setting it's entry point
	HANDLE thread = CreateThread(NULL, 0x0, NULL, NULL, CREATE_SUSPENDED, NULL);
	if (!thread) {
		printf_s("CreateThread() failed with 0x%X\n", GetLastError());
		return 0x0;
	}

	// capturing the thread's context which contains cpu registers values at a specific time
	CONTEXT context = { 0x0 };
	context.ContextFlags = CONTEXT_FULL;
	GetThreadContext(thread, &context);

#if defined (_M_X64)

	// if we are in a 64bit process:

	// shellcode for clearing the stack after returning from the function and exiting the previously created thread
	BYTE shellcode[] = {
		0x6a, 0x0, // push rsp, 0h
		0x48, 0xb8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // mov rax, NULL
		0xff, 0xd0, // call rax
		0x48, 0x83, 0xc4, 0x08 // add rsp, 08h
	};

	*((DWORD64*)(shellcode + 4)) = (DWORD64)ExitThread; // update the value at RAX to the address of KERNEL32!ExitThread

	// allocating enough executable memory for out shellcode
	LPBYTE free_stack = (LPBYTE)VirtualAlloc(0x0, 18, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	// writing the shellcode to the allocated range
	SIZE_T written_bytes = 0x0;
	if (!WriteProcessMemory(GetCurrentProcess(), free_stack, (LPCVOID)shellcode, 18, &written_bytes) || written_bytes != 18) {
		VirtualFree(free_stack, 22, MEM_RELEASE | MEM_DECOMMIT);
		printf_s("WriteProcessMemory() failed with 0x%X\n", GetLastError());
		return 0x0;
	}

	/*  When working on x86, you can directly push all parameters onto the stack using the PUSH instruction.
		However, in x64, things are a little bit different. The first four parameters are  are passed using general-purpose registers (RCX, RDX, R8, and R9  for integers and pointers). 
		If there are more than four parameters, you push them onto the stack directly using the PUSH instruction. */

	context.Rcx = 20; // param1
	context.Rdx = 10;
	context.R8 = (DWORD64)((LPCSTR)"param3"); // param3
	context.R9 = (DWORD64)((LPCSTR)"param4"); // param4

	/*
	  - The CALL instruction which is used to call functions and procedures actually does two things :
			first: pushing the returned address onto the stack ( the address of the instruction after the CALL instruction )
			second: doing an uncoditional jump to the address provided as an operand ( the procedure's address )
	  
	  - The PUSH instruction also does two things :
			first: decrementing the value of RSP  by 8 to make space for the pushed operand ( allocation on the stack 
				is done by decrementing it not incrementing because the stack grows downward so it goes from higher to lower addresses ) 
			second: changing the value of [RSP] { the value at the memory address pointed to by RSP } 
				to point to the opearnd of the instruction which is in our case the return address

	*/

	// decrementing the RSP as we say before
	context.Rsp -= sizeof(DWORD64);

	// changing the value at [RSP] to 
	*((DWORD64*)context.Rsp) = (DWORD64)free_stack; // retrurn address

	// finally changing the value of the RIP register to point to our function which is the last action that is done by the call instruction ( this is similar to [ jmp CustomThreadEntryPoint ] in assembly )
	context.Rip = (DWORD64)CustomThreadEntryPoint;

#elif defined (_M_IX86)
	BYTE shellcode[] = { 
		0x83, 0xC4, 0x10, // add esp, 16 ( deallocating parameters space 4 * sizeof(DWORD) = 16)
		0x6a, 0x0, // push 0h 
		0xB8, 0x0, 0x00, 0x00, 0x00, // mov eax, NULL
		0xFF, 0xD0, // call eax
		0x83, 0xC4, 0x04 // add esp, 4
	};

	// setting the value at EAX to the adddress of KERNEL32!ExitThread
	*((DWORD32*)(shellcode + 6)) = (DWORD32)ExitThread;

	LPBYTE free_stack = (LPBYTE)VirtualAlloc(0x0, 15, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	SIZE_T written_bytes = 0x0;
	if (!WriteProcessMemory(GetCurrentProcess(), free_stack, (LPCVOID)shellcode, 15, &written_bytes) || written_bytes != 15) {
		VirtualFree(free_stack, 14, MEM_RELEASE | MEM_DECOMMIT);
		printf_s("WriteProcessMemory() failed with 0x%X\n", GetLastError());
		return 0x0;
	}
	
	// push the parameters directly onto the stack not link x64 ( don't use general pusrpose registers )

	context.Esp -= sizeof(DWORD32);
	*((LPCSTR*)context.Esp) = "param4"; // param4
	context.Esp -= sizeof(DWORD32);
	*((LPCSTR*)context.Esp) = "param3"; // param3
	context.Esp -= sizeof(DWORD32);
	*((DWORD32*)context.Esp) = 10; // param2
	context.Esp -= sizeof(DWORD32);
	*((DWORD32*)context.Esp) = 20; // param1
	context.Esp -= sizeof(DWORD32);
	*((DWORD32*)context.Esp) = (DWORD32)free_stack; // retrurn address

	// changing the vaalue of the Eip register 
	context.Eip = (DWORD32)CustomThreadEntryPoint;
#endif

	// save the thread context
	SetThreadContext(thread, &context);

	// resume the thread execution
	ResumeThread(thread);

	// wait for the thread to terminate 
	WaitForSingleObject(thread, (DWORD)-1);

	// release the thread handle
	CloseHandle(thread);

	// free the previously allocated space
#if defined (_M_IX86) 
	VirtualFree(free_stack, 15, MEM_RELEASE | MEM_DECOMMIT);
#elif defined (_M_X64)
	VirtualFree(free_stack, 18, MEM_RELEASE | MEM_DECOMMIT);
#endif

	// finish the program execution
	return 0x0;
}
