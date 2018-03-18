# PortableExecutable
A Class for walking a PE file structure. x86 or x64 compatible.

Built as a Static Library for easy implementation elsewhere.

We use ReadProcessMemory wrapped with VirtualProtect to make
sure we have access to the pages we want to read. This also
allows us to read from a foreign process if we choose to.
The parent application is responcible for having the proper
permissions and calling OpenProcess to retrieve a handle for
the process they want to walk. We default to our current
process with a pseudo handle from GetCurrentProcess(). And
we use QueryInformationProcess to lookup the PEB incase we
are not looking at our own process.

Using wrapper functions and a flag based on whether or not
the process is 64bit, we can make sure we use the proper
IMAGE_XXX structures while traversing the PE headers.
