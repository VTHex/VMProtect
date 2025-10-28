#include "common.h"
#include "utils.h"
#include "objects.h"

#include "crypto.h"
#include "core.h"
#include "string_manager.h"
#include "licensing_manager.h"
#include "hwid.h"

#ifdef VMP_GNU
#include "loader.h"
#elif defined(WIN_DRIVER)
#include "loader.h"
#else
#include "resource_manager.h"
#include "file_manager.h"
#include "registry_manager.h"
#include "hook_manager.h"
#endif

GlobalData *loader_data = NULL;
#ifdef WIN_DRIVER
__declspec(noinline) void * ExAllocateNonPagedPoolNx(size_t size)
{
	return ExAllocatePool((POOL_TYPE)FACE_NON_PAGED_POOL_NX, size);
}

void * __cdecl operator new(size_t size)
{
	if (size)
		return ExAllocateNonPagedPoolNx(size);

	return NULL;
}

void __cdecl operator delete(void* p)
{
	if (p)
		ExFreePool(p);
}

void __cdecl operator delete(void* p, size_t)
{
	if (p)
		ExFreePool(p);
}

void * __cdecl operator new[](size_t size)
{
	if (size)
		return ExAllocateNonPagedPoolNx(size);

	return NULL;
}

void __cdecl operator delete[](void *p)
{
	if (p)
		ExFreePool(p);
}
#endif

/**
 * initialization functions
 */

#ifdef VMP_GNU

EXPORT_API bool WINAPI DllMain(HMODULE hModule, bool is_init) __asm__ ("DllMain");
bool WINAPI DllMain(HMODULE hModule, bool is_init)
{
	if (is_init) {
		if (!Core::Instance()->Init(hModule)) {
			Core::Free();
			return false;
		}
	} else {
		Core::Free();
	}
	return true;
}

#elif defined(WIN_DRIVER)

NTSTATUS DllMain(HMODULE hModule, bool is_init)
{
	if (is_init) {
		if (!Core::Instance()->Init(hModule)) {
			Core::Free();
			return STATUS_ACCESS_DENIED;
		}
	} else {
		Core::Free();
	}
	return STATUS_SUCCESS;
}

#else

BOOL WINAPI DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
	switch (dwReason) {
	case DLL_PROCESS_ATTACH:
		if (!Core::Instance()->Init(hModule)) {
			Core::Free();
			return FALSE;
		}
		break;
	case DLL_PROCESS_DETACH:
		Core::Free();
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	}
	return TRUE;
}
#endif

/**
 * exported functions
 */

NOINLINE bool InternalFindFirmwareVendor(const uint8_t *data, size_t data_size)
{
	for (size_t i = 0; i < data_size; i++) {
#ifdef __unix__
		if (i + 3 < data_size && data[i + 0] == 'Q' && data[i + 1] == 'E' && data[i + 2] == 'M' && data[i + 3] == 'U')
			return true;
		if (i + 8 < data_size && data[i + 0] == 'M' && data[i + 1] == 'i' && data[i + 2] == 'c' && data[i + 3] == 'r' && data[i + 4] == 'o' && data[i + 5] == 's' && data[i + 6] == 'o' && data[i + 7] == 'f' && data[i + 8] == 't')
			return true;
		if (i + 6 < data_size && data[i + 0] == 'i' && data[i + 1] == 'n' && data[i + 2] == 'n' && data[i + 3] == 'o' && data[i + 4] == 't' && data[i + 5] == 'e' && data[i + 6] == 'k')
			return true;
#else
		if (i + 9 < data_size && data[i + 0] == 'V' && data[i + 1] == 'i' && data[i + 2] == 'r' && data[i + 3] == 't' && data[i + 4] == 'u' && data[i + 5] == 'a' && data[i + 6] == 'l' && data[i + 7] == 'B' && data[i + 8] == 'o' && data[i + 9] == 'x')
			return true;
#endif
		if (i + 5 < data_size && data[i + 0] == 'V' && data[i + 1] == 'M' && data[i + 2] == 'w' && data[i + 3] == 'a' && data[i + 4] == 'r' && data[i + 5] == 'e')
			return true;
		if (i + 8 < data_size && data[i + 0] == 'P' && data[i + 1] == 'a' && data[i + 2] == 'r' && data[i + 3] == 'a' && data[i + 4] == 'l' && data[i + 5] == 'l' && data[i + 6] == 'e' && data[i + 7] == 'l' && data[i + 8] == 's')
			return true;
	}
	return false;
}

#ifdef VMP_GNU
EXPORT_API bool WINAPI ExportedIsValidImageCRC() __asm__ ("ExportedIsValidImageCRC");
EXPORT_API bool WINAPI ExportedIsDebuggerPresent(bool check_kernel_mode) __asm__ ("ExportedIsDebuggerPresent");
EXPORT_API bool WINAPI ExportedIsVirtualMachinePresent() __asm__ ("ExportedIsVirtualMachinePresent");
EXPORT_API bool WINAPI ExportedIsProtected() __asm__ ("ExportedIsProtected");
#endif

struct CRCData {
	uint8_t *ImageBase;
	uint32_t Table;
	uint32_t Size;
	uint32_t Hash;
	NOINLINE CRCData()
	{
		ImageBase = reinterpret_cast<uint8_t *>(FACE_IMAGE_BASE);
		Table = FACE_CRC_TABLE_ENTRY;
		Size = FACE_CRC_TABLE_SIZE;
		Hash = FACE_CRC_TABLE_HASH;
	}
};

bool WINAPI ExportedIsValidImageCRC()
{
	if (loader_data->is_patch_detected())
		return false;

	const CRCData crc_data;

	bool res = true;
	uint8_t *image_base = crc_data.ImageBase;
	uint8_t *crc_table = image_base + crc_data.Table;
	uint32_t crc_table_size = *reinterpret_cast<uint32_t *>(image_base + crc_data.Size);
	uint32_t crc_table_hash = *reinterpret_cast<uint32_t *>(image_base + crc_data.Hash);

#ifdef WIN_DRIVER
	uint32_t image_size = 0;
	if (loader_data->loader_status() == STATUS_SUCCESS) {
		IMAGE_DOS_HEADER *dos_header = reinterpret_cast<IMAGE_DOS_HEADER *>(image_base);
		if (dos_header->e_magic == IMAGE_DOS_SIGNATURE) {
			IMAGE_NT_HEADERS *pe_header = reinterpret_cast<IMAGE_NT_HEADERS *>(image_base + dos_header->e_lfanew);
			if (pe_header->Signature == IMAGE_NT_SIGNATURE) {
				IMAGE_SECTION_HEADER *sections = reinterpret_cast<IMAGE_SECTION_HEADER *>(reinterpret_cast<uint8_t *>(pe_header) + offsetof(IMAGE_NT_HEADERS, OptionalHeader) + pe_header->FileHeader.SizeOfOptionalHeader);
				for (size_t i = 0; i < pe_header->FileHeader.NumberOfSections; i++) {
					IMAGE_SECTION_HEADER *section = sections + i;
					if (section->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) {
						image_size = section->VirtualAddress;
						break;
					}
				}
			}
		}
	}
#endif

	// check memory CRC
	{
		if (crc_table_hash != CalcCRC(crc_table, crc_table_size))
			res = false;
		CRCValueCryptor crc_cryptor;
		for (size_t i = 0; i < crc_table_size; i += sizeof(CRC_INFO)) {
			CRC_INFO crc_info = *reinterpret_cast<CRC_INFO *>(crc_table + i);
			crc_info.Address = crc_cryptor.Decrypt(crc_info.Address);
			crc_info.Size = crc_cryptor.Decrypt(crc_info.Size);
			crc_info.Hash = crc_cryptor.Decrypt(crc_info.Hash);
#ifdef WIN_DRIVER
			if (image_size && image_size < crc_info.Address + crc_info.Size)
				continue;
#endif
		
			if (crc_info.Hash != CalcCRC(image_base + crc_info.Address, crc_info.Size))
				res = false;
		}
	}

	// check header and loader CRC
	crc_table = image_base + loader_data->loader_crc_info();
	crc_table_size = static_cast<uint32_t>(loader_data->loader_crc_size());
	crc_table_hash = static_cast<uint32_t>(loader_data->loader_crc_hash());
	{
		if (crc_table_hash != CalcCRC(crc_table, crc_table_size))
			res = false;
		CRCValueCryptor crc_cryptor;
		for (size_t i = 0; i < crc_table_size; i += sizeof(CRC_INFO)) {
			CRC_INFO crc_info = *reinterpret_cast<CRC_INFO *>(crc_table + i);
			crc_info.Address = crc_cryptor.Decrypt(crc_info.Address);
			crc_info.Size = crc_cryptor.Decrypt(crc_info.Size);
			crc_info.Hash = crc_cryptor.Decrypt(crc_info.Hash);
#ifdef WIN_DRIVER
			if (image_size && image_size < crc_info.Address + crc_info.Size)
				continue;
#endif
		
			if (crc_info.Hash != CalcCRC(image_base + crc_info.Address, crc_info.Size))
				res = false;
		}
	}

#ifndef DEMO
#ifdef VMP_GNU
#elif defined(WIN_DRIVER)
#else
	// check memory type of loader_data
	HMODULE ntdll = GetModuleHandleA(VMProtectDecryptStringA("ntdll.dll"));
	typedef NTSTATUS(NTAPI tNtQueryVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength);
	tNtQueryVirtualMemory *query_virtual_memory = reinterpret_cast<tNtQueryVirtualMemory *>(InternalGetProcAddress(ntdll, VMProtectDecryptStringA("NtQueryVirtualMemory")));
	if (query_virtual_memory) {
		MEMORY_BASIC_INFORMATION memory_info;
		NTSTATUS status = query_virtual_memory(NtCurrentProcess(), loader_data, MemoryBasicInformation, &memory_info, sizeof(memory_info), NULL);
		if (NT_SUCCESS(status) && memory_info.AllocationBase == image_base)
			res = false;
	}
#endif
#endif

	return res;
}

bool WINAPI ExportedIsVirtualMachinePresent()
{
	// hardware detection
	int cpu_info[4];
	__cpuid(cpu_info, 1);
	if ((cpu_info[2] >> 31) & 1) {
#ifndef VMP_GNU
		// check Hyper-V root partition
		cpu_info[1] = 0;
		cpu_info[2] = 0;
		cpu_info[3] = 0;
		__cpuid(cpu_info, 0x40000000);
		if (cpu_info[1] == 0x7263694d && cpu_info[2] == 0x666f736f && cpu_info[3] == 0x76482074) { // "Microsoft Hv"
			cpu_info[1] = 0;
			__cpuid(cpu_info, 0x40000003);
			if (cpu_info[1] & 1)
				return false;
		}
#endif
		return true;
	}

#ifndef VMP_GNU
	uint64_t val;
	uint8_t mem_val;
	__try {
		// set T flag
		__writeeflags(__readeflags() | 0x100);
		 val = __rdtsc();
		 __nop();
		 loader_data->set_is_debugger_detected(true);
	} __except(mem_val = *static_cast<uint8_t *>((GetExceptionInformation())->ExceptionRecord->ExceptionAddress), EXCEPTION_EXECUTE_HANDLER) {
		if (mem_val != 0x90)
			return true;
	}

	__try {
		// set T flag
		__writeeflags(__readeflags() | 0x100);
		__cpuid(cpu_info, 1);
		__nop();
		loader_data->set_is_debugger_detected(true);
	} __except(mem_val = *static_cast<uint8_t *>((GetExceptionInformation())->ExceptionRecord->ExceptionAddress), EXCEPTION_EXECUTE_HANDLER) {
		if (mem_val != 0x90)
			return true;
	}
#endif

	// software detection
#ifdef __APPLE__
	// FIXME
#elif defined(__unix__)
	FILE *fsys_vendor = fopen(VMProtectDecryptStringA("/sys/devices/virtual/dmi/id/sys_vendor"), "r");
	if (fsys_vendor) {
		char sys_vendor[256] = {0};
		fgets(sys_vendor, sizeof(sys_vendor), fsys_vendor);
		fclose(fsys_vendor);
		if (InternalFindFirmwareVendor(reinterpret_cast<uint8_t *>(sys_vendor), sizeof(sys_vendor)))
			return true;
	}
#elif defined(WIN_DRIVER)
	// FIXME
#else
	HMODULE dll = GetModuleHandleA(VMProtectDecryptStringA("kernel32.dll"));
	bool is_found = false;
	typedef UINT (WINAPI tEnumSystemFirmwareTables)(DWORD FirmwareTableProviderSignature, PVOID pFirmwareTableEnumBuffer, DWORD BufferSize);
	typedef UINT (WINAPI tGetSystemFirmwareTable)(DWORD FirmwareTableProviderSignature, DWORD FirmwareTableID, PVOID pFirmwareTableBuffer, DWORD BufferSize);
	tEnumSystemFirmwareTables *enum_system_firmware_tables = reinterpret_cast<tEnumSystemFirmwareTables *>(InternalGetProcAddress(dll, VMProtectDecryptStringA("EnumSystemFirmwareTables")));
	tGetSystemFirmwareTable *get_system_firmware_table = reinterpret_cast<tGetSystemFirmwareTable *>(InternalGetProcAddress(dll, VMProtectDecryptStringA("GetSystemFirmwareTable")));

	if (enum_system_firmware_tables && get_system_firmware_table) {
		UINT tables_size = enum_system_firmware_tables('FIRM', NULL, 0);
		if (tables_size) {
			DWORD *tables = new DWORD[tables_size / sizeof(DWORD)];
			enum_system_firmware_tables('FIRM', tables, tables_size);
			for (size_t i = 0; i < tables_size / sizeof(DWORD); i++) {
				UINT data_size = get_system_firmware_table('FIRM', tables[i], NULL, 0);
				if (data_size) {
					uint8_t *data = new uint8_t[data_size];
					get_system_firmware_table('FIRM', tables[i], data, data_size);
					if (InternalFindFirmwareVendor(data, data_size))
						is_found = true;
					delete [] data;
				}
			}
			delete [] tables;
		}
	} else {
		dll = LoadLibraryA(VMProtectDecryptStringA("ntdll.dll"));
		typedef NTSTATUS (WINAPI tNtOpenSection)(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
		typedef NTSTATUS (WINAPI tNtMapViewOfSection)(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect);
		typedef NTSTATUS (WINAPI tNtUnmapViewOfSection)(HANDLE ProcessHandle, PVOID BaseAddress);
		typedef NTSTATUS (WINAPI tNtClose)(HANDLE Handle);

		tNtOpenSection *open_section = reinterpret_cast<tNtOpenSection *>(InternalGetProcAddress(dll, VMProtectDecryptStringA("NtOpenSection")));
		tNtMapViewOfSection *map_view_of_section = reinterpret_cast<tNtMapViewOfSection *>(InternalGetProcAddress(dll, VMProtectDecryptStringA("NtMapViewOfSection")));
		tNtUnmapViewOfSection *unmap_view_of_section = reinterpret_cast<tNtUnmapViewOfSection *>(InternalGetProcAddress(dll, VMProtectDecryptStringA("NtUnmapViewOfSection")));
		tNtClose *close = reinterpret_cast<tNtClose *>(InternalGetProcAddress(dll, VMProtectDecryptStringA("NtClose")));

		if (open_section && map_view_of_section && unmap_view_of_section && close) {
			HANDLE process = NtCurrentProcess();
			HANDLE physical_memory = NULL;
			UNICODE_STRING str;
			OBJECT_ATTRIBUTES attrs;

			wchar_t buf[] = {'\\','d','e','v','i','c','e','\\','p','h','y','s','i','c','a','l','m','e','m','o','r','y',0};
			str.Buffer = buf;
			str.Length = sizeof(buf) - sizeof(wchar_t);
			str.MaximumLength = sizeof(buf);

			InitializeObjectAttributes(&attrs, &str, OBJ_CASE_INSENSITIVE, NULL, NULL);
			NTSTATUS status = open_section(&physical_memory, SECTION_MAP_READ, &attrs);
			if (NT_SUCCESS(status)) {
				void *data = NULL;
				SIZE_T data_size = 0x10000;
				LARGE_INTEGER offset;
				offset.QuadPart = 0xc0000;

				status = map_view_of_section(physical_memory, process, &data, NULL, data_size, &offset, &data_size, ViewShare, 0, PAGE_READONLY);
				if (NT_SUCCESS(status)) {
					if (InternalFindFirmwareVendor(static_cast<uint8_t *>(data), data_size))
						is_found = true;
					unmap_view_of_section(process, data);
				}
				close(physical_memory);
			}
		}
	}
	if (is_found)
		return true;

	if (GetModuleHandleA(VMProtectDecryptStringA("sbiedll.dll")))
		return true;
#endif

	return false;
}

//原始的ExportedIsDebuggerPresent

//bool WINAPI ExportedIsDebuggerPresent(bool check_kernel_mode)
//{
//	if (loader_data->is_debugger_detected())
//		return true;
//
//#if defined(__unix__)
//	FILE *file = fopen(VMProtectDecryptStringA("/proc/self/status"), "r");
//	if (file) {
//		char data[100];
//		int tracer_pid = 0;
//		while (fgets(data, sizeof(data), file)) {
//			if (data[0] == 'T' && data[1] == 'r' && data[2] == 'a' && data[3] == 'c' && data[4] == 'e' && data[5] == 'r' && data[6] == 'P' && data[7] == 'i' && data[8] == 'd' && data[9] == ':') {
//				char *tracer_ptr = data + 10;
//				// skip spaces
//				while (char c = *tracer_ptr) {
//					if (c == ' ' || c == '\t') {
//						tracer_ptr++;
//						continue;
//					}
//					else {
//						break;
//					}
//				}
//				// atoi
//				while (char c = *tracer_ptr++) {
//					if (c >= '0' && c <= '9') {
//						tracer_pid *= 10;
//						tracer_pid += c - '0';
//					}
//					else {
//						if (c != '\n' && c != '\r')
//							tracer_pid = 0;
//						break;
//					}
//				}
//				break;
//			}
//		}
//		fclose(file);
//
//		if (tracer_pid && tracer_pid != 1)
//			return true;
//	}
//#elif defined(__APPLE__)
//	(void)check_kernel_mode;
//
//    int junk;
//    int mib[4];
//    kinfo_proc info;
//    size_t size;
//
//    // Initialize the flags so that, if sysctl fails for some bizarre 
//    // reason, we get a predictable result.
//
//    info.kp_proc.p_flag = 0;
//
//    // Initialize mib, which tells sysctl the info we want, in this case
//    // we're looking for information about a specific process ID.
//
//    mib[0] = CTL_KERN;
//    mib[1] = KERN_PROC;
//    mib[2] = KERN_PROC_PID;
//    mib[3] = getpid();
//
//    // Call sysctl.
//
//    size = sizeof(info);
//    junk = sysctl(mib, sizeof(mib) / sizeof(*mib), &info, &size, NULL, 0);
//
//    // We're being debugged if the P_TRACED flag is set.
//	if ((info.kp_proc.p_flag & P_TRACED) != 0)
//		return true;
//#else
//#ifdef WIN_DRIVER
//#else
//	HMODULE kernel32 = GetModuleHandleA(VMProtectDecryptStringA("kernel32.dll"));
//	HMODULE ntdll = GetModuleHandleA(VMProtectDecryptStringA("ntdll.dll"));
//	HANDLE process = NtCurrentProcess();
//	size_t syscall = FACE_SYSCALL;
//	uint32_t sc_query_information_process = 0;
//
//	if (ntdll) {
//#ifndef DEMO
//		if (InternalGetProcAddress(ntdll, VMProtectDecryptStringA("wine_get_version")) == NULL) {
//#ifndef _WIN64
//			BOOL is_wow64 = FALSE;
//			typedef BOOL(WINAPI tIsWow64Process)(HANDLE Process, PBOOL Wow64Process);
//			tIsWow64Process *is_wow64_process = reinterpret_cast<tIsWow64Process *>(InternalGetProcAddress(kernel32, VMProtectDecryptStringA("IsWow64Process")));
//			if (is_wow64_process)
//				is_wow64_process(process, &is_wow64);
//#endif
//
//			uint32_t os_build_number = loader_data->os_build_number();
//
//			if (
//				
//				
//				WINDOWS_XP) {
//#ifndef _WIN64
//				if (!is_wow64) {
//					sc_query_information_process = 0x009a;
//				}
//				else
//#endif
//				{
//					sc_query_information_process = 0x0016;
//				}
//			}
//			else if (os_build_number == WINDOWS_2003) {
//#ifndef _WIN64
//				if (!is_wow64) {
//					sc_query_information_process = 0x00a1;
//				}
//				else
//#endif
//				{
//					sc_query_information_process = 0x0016;
//				}
//			}
//			else if (os_build_number == WINDOWS_VISTA) {
//#ifndef _WIN64
//				if (!is_wow64) {
//					sc_query_information_process = 0x00e4;
//				}
//				else
//#endif
//				{
//					sc_query_information_process = 0x0016;
//				}
//			}
//			else if (os_build_number == WINDOWS_VISTA_SP1) {
//#ifndef _WIN64
//				if (!is_wow64) {
//					sc_query_information_process = 0x00e4;
//				}
//				else
//#endif
//				{
//					sc_query_information_process = 0x0016;
//				}
//
//			}
//			else if (os_build_number == WINDOWS_VISTA_SP2) {
//#ifndef _WIN64
//				if (!is_wow64) {
//					sc_query_information_process = 0x00e4;
//				}
//				else
//#endif
//				{
//					sc_query_information_process = 0x0016;
//				}
//			}
//			else if (os_build_number == WINDOWS_7) {
//#ifndef _WIN64
//				if (!is_wow64) {
//					sc_query_information_process = 0x00ea;
//				}
//				else
//#endif
//				{
//					sc_query_information_process = 0x0016;
//				}
//			}
//			else if (os_build_number == WINDOWS_7_SP1) {
//#ifndef _WIN64
//				if (!is_wow64) {
//					sc_query_information_process = 0x00ea;
//				}
//				else
//#endif
//				{
//					sc_query_information_process = 0x0016;
//				}
//			}
//			else if (os_build_number == WINDOWS_8) {
//#ifndef _WIN64
//				if (!is_wow64) {
//					sc_query_information_process = 0x00b0;
//				}
//				else
//#endif
//				{
//					sc_query_information_process = 0x0017;
//				}
//			}
//			else if (os_build_number == WINDOWS_8_1) {
//#ifndef _WIN64
//				if (!is_wow64) {
//					sc_query_information_process = 0x00b3;
//				}
//				else
//#endif
//				{
//					sc_query_information_process = 0x0018;
//				}
//			}
//			else if (os_build_number == WINDOWS_10_TH1) {
//#ifndef _WIN64
//				if (!is_wow64) {
//					sc_query_information_process = 0x00b5;
//				}
//				else
//#endif
//				{
//					sc_query_information_process = 0x0019;
//				}
//			}
//			else if (os_build_number == WINDOWS_10_TH2) {
//#ifndef _WIN64
//				if (!is_wow64) {
//					sc_query_information_process = 0x00b5;
//				}
//				else
//#endif
//				{
//					sc_query_information_process = 0x0019;
//				}
//			}
//			else if (os_build_number == WINDOWS_10_RS1) {
//#ifndef _WIN64
//				if (!is_wow64) {
//					sc_query_information_process = 0x00b7;
//				}
//				else
//#endif
//				{
//					sc_query_information_process = 0x0019;
//				}
//			}
//			else if (os_build_number == WINDOWS_10_RS2) {
//#ifndef _WIN64
//				if (!is_wow64) {
//					sc_query_information_process = 0x00b8;
//				}
//				else
//#endif
//				{
//					sc_query_information_process = 0x0019;
//				}
//			}
//			else if (os_build_number == WINDOWS_10_RS3) {
//#ifndef _WIN64
//				if (!is_wow64) {
//					sc_query_information_process = 0x00b9;
//				}
//				else
//#endif
//				{
//					sc_query_information_process = 0x0019;
//				}
//			}
//			else if (os_build_number == WINDOWS_10_RS4) {
//#ifndef _WIN64
//				if (!is_wow64) {
//					sc_query_information_process = 0x00b9;
//				}
//				else
//#endif
//				{
//					sc_query_information_process = 0x0019;
//				}
//			}
//			else if (os_build_number == WINDOWS_10_RS5) {
//#ifndef _WIN64
//				if (!is_wow64) {
//					sc_query_information_process = 0x00b9;
//				}
//				else
//#endif
//				{
//					sc_query_information_process = 0x0019;
//				}
//			}
//			else if (os_build_number == WINDOWS_10_19H1) {
//#ifndef _WIN64
//				if (!is_wow64) {
//					sc_query_information_process = 0x00b9;
//				}
//				else
//#endif
//				{
//					sc_query_information_process = 0x0019;
//				}
//			}
//			else if (os_build_number == WINDOWS_10_19H2) {
//#ifndef _WIN64
//				if (!is_wow64) {
//					sc_query_information_process = 0x00b9;
//				}
//				else
//#endif
//				{
//					sc_query_information_process = 0x0019;
//				}
//			}
//			else if (os_build_number == WINDOWS_10_20H1) {
//#ifndef _WIN64
//				if (!is_wow64) {
//					sc_query_information_process = 0x00b9;
//				}
//				else
//#endif
//				{
//					sc_query_information_process = 0x0019;
//				}
//			}
//			else if (os_build_number == WINDOWS_10_20H2) {
//#ifndef _WIN64
//				if (!is_wow64) {
//					sc_query_information_process = 0x00b9;
//				}
//				else
//#endif
//				{
//					sc_query_information_process = 0x0019;
//				}
//			}
//			else if (os_build_number == WINDOWS_10_21H1) {
//#ifndef _WIN64
//				if (!is_wow64) {
//					sc_query_information_process = 0x00b9;
//				}
//				else
//#endif
//				{
//					sc_query_information_process = 0x0019;
//				}
//			}
//			else if (os_build_number == WINDOWS_10_21H2) {
//#ifndef _WIN64
//				if (!is_wow64) {
//					sc_query_information_process = 0x00b9;
//				}
//				else
//#endif
//				{
//					sc_query_information_process = 0x0019;
//				}
//			}
//			else if (os_build_number == WINDOWS_10_22H2) {
//#ifndef _WIN64
//				if (!is_wow64) {
//					sc_query_information_process = 0x00b9;
//				}
//				else
//#endif
//				{
//					sc_query_information_process = 0x0019;
//				}
//			}
//#ifndef _WIN64
//			if (is_wow64 && sc_query_information_process) {
//				sc_query_information_process |= WOW64_FLAG | (0x03 << 24);
//			}
//#endif
//		}
//#endif
//	}
//
//#ifdef _WIN64
//	PEB64 *peb = reinterpret_cast<PEB64 *>(__readgsqword(0x60));
//#else
//	PEB32 *peb = reinterpret_cast<PEB32 *>(__readfsdword(0x30));
//#endif
//	if (peb->BeingDebugged)
//		return true;
//
//	{
//		size_t drx;
//		uint64_t val;
//		CONTEXT *ctx;
//		__try {
//			__writeeflags(__readeflags() | 0x100);
//			val = __rdtsc();
//			__nop();
//			return true;
//		}
//		__except (ctx = (GetExceptionInformation())->ContextRecord,
//			drx = (ctx->ContextFlags & CONTEXT_DEBUG_REGISTERS) ? ctx->Dr0 | ctx->Dr1 | ctx->Dr2 | ctx->Dr3 : 0,
//			EXCEPTION_EXECUTE_HANDLER) {
//			if (drx)
//				return true;
//		}
//	}
//
//	typedef NTSTATUS(NTAPI tNtQueryInformationProcess)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
//	if (sc_query_information_process) {
//		HANDLE debug_object;
//		if (NT_SUCCESS(reinterpret_cast<tNtQueryInformationProcess *>(syscall | sc_query_information_process)(process, ProcessDebugPort, &debug_object, sizeof(debug_object), NULL)) && debug_object != 0)
//			return true;
//		debug_object = 0;
//		if (NT_SUCCESS(reinterpret_cast<tNtQueryInformationProcess *>(syscall | sc_query_information_process)(process, ProcessDebugObjectHandle, &debug_object, sizeof(debug_object), reinterpret_cast<PULONG>(&debug_object)))
//			|| debug_object == 0)
//			return true;
//	}
//	else if (tNtQueryInformationProcess *query_information_process = reinterpret_cast<tNtQueryInformationProcess *>(InternalGetProcAddress(ntdll, VMProtectDecryptStringA("NtQueryInformationProcess")))) {
//		HANDLE debug_object;
//		if (NT_SUCCESS(query_information_process(process, ProcessDebugPort, &debug_object, sizeof(debug_object), NULL)) && debug_object != 0)
//			return true;
//		if (NT_SUCCESS(query_information_process(process, ProcessDebugObjectHandle, &debug_object, sizeof(debug_object), NULL)))
//			return true;
//	}
//
//#endif
//#ifdef WIN_DRIVER
//	if (true) {
//#else
//	if (check_kernel_mode) {
//#endif
//		bool is_found = false;
//		typedef NTSTATUS (NTAPI tNtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
//#ifdef WIN_DRIVER
//		tNtQuerySystemInformation *nt_query_system_information = &NtQuerySystemInformation;
//#else
//		tNtQuerySystemInformation *nt_query_system_information = reinterpret_cast<tNtQuerySystemInformation *>(InternalGetProcAddress(ntdll, VMProtectDecryptStringA("NtQuerySystemInformation")));
//		if (nt_query_system_information) {
//#endif
//			SYSTEM_KERNEL_DEBUGGER_INFORMATION info;
//			NTSTATUS status = nt_query_system_information(SystemKernelDebuggerInformation, &info, sizeof(info), NULL);
//			if (NT_SUCCESS(status) && info.DebuggerEnabled && !info.DebuggerNotPresent)
//				return true;
//
//			SYSTEM_MODULE_INFORMATION *buffer = NULL;
//			ULONG buffer_size = 0;
//			/*status = */nt_query_system_information(SystemModuleInformation, &buffer, 0, &buffer_size);
//			if (buffer_size) {
//				buffer = reinterpret_cast<SYSTEM_MODULE_INFORMATION *>(new uint8_t[buffer_size * 2]);
//				status = nt_query_system_information(SystemModuleInformation, buffer, buffer_size * 2, NULL);
//				if (NT_SUCCESS(status)) {
//					for (size_t i = 0; i < buffer->Count && !is_found; i++) {
//						SYSTEM_MODULE_ENTRY *module_entry = &buffer->Module[i];
//						char module_name[11];
//						for (size_t j = 0; j < 5; j++) {
//							switch (j) {
//							case 0:
//								module_name[0] = 's';
//								module_name[1] = 'i';
//								module_name[2] = 'c';
//								module_name[3] = 'e';
//								module_name[4] = '.';
//								module_name[5] = 's';
//								module_name[6] = 'y';
//								module_name[7] = 's';
//								module_name[8] = 0;
//								break;
//							case 1:
//								module_name[0] = 's';
//								module_name[1] = 'i';
//								module_name[2] = 'w';
//								module_name[3] = 'v';
//								module_name[4] = 'i';
//								module_name[5] = 'd';
//								module_name[6] = '.';
//								module_name[7] = 's';
//								module_name[8] = 'y';
//								module_name[9] = 's';
//								module_name[10] = 0;
//								break;
//							case 2:
//								module_name[0] = 'n';
//								module_name[1] = 't';
//								module_name[2] = 'i';
//								module_name[3] = 'c';
//								module_name[4] = 'e';
//								module_name[5] = '.';
//								module_name[6] = 's';
//								module_name[7] = 'y';
//								module_name[8] = 's';
//								module_name[9] = 0;
//								break;
//							case 3:
//								module_name[0] = 'i';
//								module_name[1] = 'c';
//								module_name[2] = 'e';
//								module_name[3] = 'e';
//								module_name[4] = 'x';
//								module_name[5] = 't';
//								module_name[6] = '.';
//								module_name[7] = 's';
//								module_name[8] = 'y';
//								module_name[9] = 's';
//								module_name[10] = 0;
//								break;
//							case 4:
//								module_name[0] = 's';
//								module_name[1] = 'y';
//								module_name[2] = 's';
//								module_name[3] = 'e';
//								module_name[4] = 'r';
//								module_name[5] = '.';
//								module_name[6] = 's';
//								module_name[7] = 'y';
//								module_name[8] = 's';
//								module_name[9] = 0;
//								break;
//							}
//							if (_stricmp(module_entry->Name + module_entry->PathLength, module_name) == 0) {
//								is_found = true;
//								break;
//							}
//						}
//					}
//				}
//				delete [] buffer;
//			}
//#ifndef WIN_DRIVER
//		}
//#endif
//		if (is_found)
//			return true;
//	}
//#endif
//	return false;
//}


/*
以下是各平台使用的调试器检测手段总结，按平台分类且无遗漏：
1. Unix/Linux 平台
核心原理：通过 proc 文件系统获取进程跟踪状态检测手段：
读取 /proc/self/status 文件，解析 TracerPid 字段：
若 TracerPid 非 0 且不等于 1（排除 init 进程），则判定存在调试器（调试器会作为跟踪进程存在）。
2. Apple/macOS 平台
核心原理：通过系统接口查询进程跟踪标志检测手段：
调用 sysctl 系统调用，查询当前进程信息：
构造 MIB 数组（CTL_KERN + KERN_PROC + KERN_PROC_PID + 当前进程 PID），获取进程结构体 kinfo_proc。
检查进程标志 kp_proc.p_flag 中的 P_TRACED 位，若该位为 1，则判定进程被调试器跟踪。
3. Windows 平台（用户态 + 内核态）
3.1 基础预检测
优先通过外部 loader_data->is_debugger_detected() 判断，若加载阶段已检测到调试器，直接返回 true。
3.2 用户态检测
PEB 调试标志：
读取进程环境块（PEB）的 BeingDebugged 字段：
32 位系统通过 FS:[0x30] 获取 PEB 地址，64 位系统通过 GS:[0x60] 获取。
若 BeingDebugged 为 TRUE，直接判定被调试。
调试寄存器（Dr0-Dr3）检测：
通过 __try/__except 异常处理捕获调试寄存器状态：
尝试修改 EFLAGS 寄存器的陷阱标志（TF 位），触发异常后读取上下文 CONTEXT 中的 Dr0-Dr3。
若任意调试寄存器非 0（表示设置了硬件断点），判定被调试。
系统调用查询进程调试信息：
调用 NtQueryInformationProcess（直接调用或通过系统调用号），查询两类信息：
ProcessDebugPort（调试端口）：非 0 表示进程被调试。
ProcessDebugObjectHandle（调试对象句柄）：存在有效句柄表示进程被调试。
适配逻辑：根据 Windows 版本（XP/7/10 等）和架构（32/64/WOW64），使用对应系统调用号，避免直接依赖函数地址（反 Hook）。
3.3 内核态检测（需 check_kernel_mode=true 或驱动模式）
内核调试器状态查询：
调用 NtQuerySystemInformation，查询 SystemKernelDebuggerInformation：
若 DebuggerEnabled 为 TRUE 且 DebuggerNotPresent 为 FALSE，判定存在内核调试器。
调试相关内核模块检测：
调用 NtQuerySystemInformation，查询 SystemModuleInformation 获取系统模块列表。
遍历模块列表，检测是否存在调试工具相关驱动：
sice.sys（SoftICE 调试器）、siwvid.sys（SoftICE 组件）、ntice.sys（WinDbg 内核驱动）、iceext.sys（调试插件）、syser.sys（Syser Debugger）。

*/


// 核心函数：跨平台调试器检测
// 参数check_kernel_mode：是否检测内核级调试（Windows下有效，Unix/Apple下暂未使用）
// 返回值：true表示检测到调试器，false表示未检测到
bool WINAPI ExportedIsDebuggerPresent(bool check_kernel_mode)
{
	// 1. 优先通过加载器数据判断：若加载阶段已检测到调试器，直接返回true
	if (loader_data->is_debugger_detected())
		return true;

	// 2. Unix系统（如Linux）的调试器检测：读取/proc/self/status中的TracerPid字段
#if defined(__unix__)
	// 打开当前进程的状态文件（/proc/self/status记录进程详细状态）
	FILE* file = fopen(VMProtectDecryptStringA("/proc/self/status"), "r");
	if (file) {
		char data[100];          // 存储每行读取的数据
		int tracer_pid = 0;      // 存储跟踪进程的PID（TracerPid）

		// 逐行读取文件内容，查找TracerPid字段
		while (fgets(data, sizeof(data), file)) {
			// 判断当前行是否为TracerPid字段（避免使用strstr，提高反调试隐蔽性）
			if (data[0] == 'T' && data[1] == 'r' && data[2] == 'a' &&
				data[3] == 'c' && data[4] == 'e' && data[5] == 'r' &&
				data[6] == 'P' && data[7] == 'i' && data[8] == 'd' && data[9] == ':') {

				char* tracer_ptr = data + 10; // 跳过"TracerPid:"前缀，指向PID值起始位置

				// 跳过前缀后的空格/制表符（如"TracerPid:  1234"中的空格）
				while (char c = *tracer_ptr) {
					if (c == ' ' || c == '\t') {
						tracer_ptr++;
						continue;
					}
					else {
						break;
					}
				}

				// 将字符串形式的PID转换为整数（自定义atoi，避免依赖标准库函数）
				while (char c = *tracer_ptr++) {
					if (c >= '0' && c <= '9') {
						tracer_pid *= 10;
						tracer_pid += c - '0';
					}
					else {
						// 若遇到非数字字符（除换行/回车），说明PID无效，重置为0
						if (c != '\n' && c != '\r')
							tracer_pid = 0;
						break;
					}
				}
				break; // 找到TracerPid字段，退出循环
			}
		}
		fclose(file); // 关闭文件

		// TracerPid非0且非1（1通常是init进程，排除特殊情况），表示存在跟踪进程（调试器）
		if (tracer_pid && tracer_pid != 1)
			return true;
	}

	// 3. Apple系统（如macOS）的调试器检测：通过sysctl查询进程的P_TRACED标志
#elif defined(__APPLE__)
	(void)check_kernel_mode; // 未使用该参数，避免编译警告

	int junk;               // 存储sysctl的返回值（暂未使用）
	int mib[4];             // sysctl的MIB数组（指定查询的信息类型）
	kinfo_proc info;        // 存储进程信息的结构体
	size_t size;            // 存储info结构体的大小

	// 初始化进程标志：若sysctl调用失败，确保标志初始为0（避免误判）
	info.kp_proc.p_flag = 0;

	// 配置MIB数组：查询当前进程（getpid()）的详细信息
	mib[0] = CTL_KERN;      // 内核子系统
	mib[1] = KERN_PROC;     // 进程信息
	mib[2] = KERN_PROC_PID; // 按PID查询
	mib[3] = getpid();      // 当前进程的PID

	// 调用sysctl获取进程信息
	size = sizeof(info);
	junk = sysctl(mib, sizeof(mib) / sizeof(*mib), &info, &size, NULL, 0);

	// 检查进程标志：P_TRACED表示进程正在被跟踪（调试器附加）
	if ((info.kp_proc.p_flag & P_TRACED) != 0)
		return true;

	// 4. Windows系统的调试器检测（用户态+内核态）
#else
	// 排除Windows驱动模式（驱动下逻辑单独处理）
#ifdef WIN_DRIVER
#else
	// 4.1 加载核心系统模块（kernel32.dll和ntdll.dll）
	HMODULE kernel32 = GetModuleHandleA(VMProtectDecryptStringA("kernel32.dll"));
	HMODULE ntdll = GetModuleHandleA(VMProtectDecryptStringA("ntdll.dll"));
	HANDLE process = NtCurrentProcess(); // 获取当前进程句柄（ntdll导出的接口）
	size_t syscall = FACE_SYSCALL;       // 系统调用基础地址
	uint32_t sc_query_information_process = 0; // NtQueryInformationProcess的系统调用号

	// 若成功加载ntdll.dll，继续用户态调试检测
	if (ntdll) {
#ifndef DEMO // 非演示模式下，增加反 Wine 环境检测（Wine是Windows兼容层，排除非原生Windows环境）
		// 检查ntdll中是否存在wine_get_version函数：存在则为Wine环境，跳过部分检测
		if (InternalGetProcAddress(ntdll, VMProtectDecryptStringA("wine_get_version")) == NULL) {
#ifndef _WIN64 // 32位Windows环境：检测是否为WOW64进程（32位进程运行在64位系统上）
			BOOL is_wow64 = FALSE;
			// 定义IsWow64Process函数指针（判断进程是否为WOW64）
			typedef BOOL(WINAPI tIsWow64Process)(HANDLE Process, PBOOL Wow64Process);
			tIsWow64Process* is_wow64_process = reinterpret_cast<tIsWow64Process*>(
				InternalGetProcAddress(kernel32, VMProtectDecryptStringA("IsWow64Process"))
				);
			// 调用IsWow64Process获取进程架构信息
			if (is_wow64_process)
				is_wow64_process(process, &is_wow64);
#endif

			// 获取当前系统的构建版本号（用于适配不同Windows版本的系统调用号）
			uint32_t os_build_number = loader_data->os_build_number();

			// 4.1.1 根据系统版本和架构（32/64/WOW64），设置NtQueryInformationProcess的系统调用号
			// 不同Windows版本的系统调用号不同，避免直接调用函数（反调试：防止函数地址被Hook）
			if (os_build_number == WINDOWS_XP) {
#ifndef _WIN64
				if (!is_wow64) sc_query_information_process = 0x009a; // 32位XP：系统调用号0x9a
				else sc_query_information_process = 0x0016;          // WOW64 XP：系统调用号0x16
#else
				sc_query_information_process = 0x0016;              // 64位XP（极少用）：系统调用号0x16
#endif
			}
			else if (os_build_number == WINDOWS_2003) {
#ifndef _WIN64
				if (!is_wow64) sc_query_information_process = 0x00a1; // 32位2003：0xa1
				else sc_query_information_process = 0x0016;          // WOW64 2003：0x16
#else
				sc_query_information_process = 0x0016;              // 64位2003：0x16
#endif
			}
			else if (os_build_number == WINDOWS_VISTA ||
				os_build_number == WINDOWS_VISTA_SP1 ||
				os_build_number == WINDOWS_VISTA_SP2) {
#ifndef _WIN64
				if (!is_wow64) sc_query_information_process = 0x00e4; // 32位Vista系列：0xe4
				else sc_query_information_process = 0x0016;          // WOW64 Vista：0x16
#else
				sc_query_information_process = 0x0016;              // 64位Vista：0x16
#endif
			}
			else if (os_build_number == WINDOWS_7 ||
				os_build_number == WINDOWS_7_SP1) {
#ifndef _WIN64
				if (!is_wow64) sc_query_information_process = 0x00ea; // 32位Win7系列：0xea
				else sc_query_information_process = 0x0016;          // WOW64 Win7：0x16
#else
				sc_query_information_process = 0x0016;              // 64位Win7：0x16
#endif
			}
			else if (os_build_number == WINDOWS_8) {
#ifndef _WIN64
				if (!is_wow64) sc_query_information_process = 0x00b0; // 32位Win8：0xb0
				else sc_query_information_process = 0x0017;          // WOW64 Win8：0x17
#else
				sc_query_information_process = 0x0017;              // 64位Win8：0x17
#endif
			}
			else if (os_build_number == WINDOWS_8_1) {
#ifndef _WIN64
				if (!is_wow64) sc_query_information_process = 0x00b3; // 32位Win8.1：0xb3
				else sc_query_information_process = 0x0018;          // WOW64 Win8.1：0x18
#else
				sc_query_information_process = 0x0018;              // 64位Win8.1：0x18
#endif
			}
			else if (os_build_number >= WINDOWS_10_TH1 &&
				os_build_number <= WINDOWS_10_22H2) {
#ifndef _WIN64
				if (!is_wow64) sc_query_information_process = 0x00b9; // 32位Win10系列：0xb9
				else sc_query_information_process = 0x0019;          // WOW64 Win10：0x19
#else
				sc_query_information_process = 0x0019;              // 64位Win10系列：0x19
#endif
			}

			// 4.1.2 若为WOW64进程，给系统调用号添加WOW64标志（32位进程调用64位系统服务的标识）
#ifndef _WIN64
			if (is_wow64 && sc_query_information_process) {
				sc_query_information_process |= WOW64_FLAG | (0x03 << 24);
			}
#endif
		}
#endif // DEMO
	}

	// 4.2 读取PEB的BeingDebugged标志（最基础的用户态调试检测）
	// PEB（进程环境块）是Windows系统为每个进程维护的核心数据结构，BeingDebugged字段直接标识进程是否被调试
#ifdef _WIN64
	// 64位系统：通过GS段寄存器偏移0x60获取PEB地址（64位Windows固定GS:[0x60]指向PEB）
	PEB64* peb = reinterpret_cast<PEB64*>(__readgsqword(0x60));
#else
	// 32位系统：通过FS段寄存器偏移0x30获取PEB地址（32位Windows固定FS:[0x30]指向PEB）
	PEB32* peb = reinterpret_cast<PEB32*>(__readfsdword(0x30));
#endif
	// 若BeingDebugged为TRUE（非0），表示进程正在被调试，直接返回true
	if (peb->BeingDebugged)
		return true;

	// 4.3 检测调试寄存器（Dr0-Dr3）：通过异常处理捕获调试寄存器状态
	// 调试寄存器用于设置硬件断点，若被调试器修改（非0），说明存在硬件调试
	{
		size_t drx;               // 存储Dr0-Dr3的组合值（用于判断是否有非0值）
		uint64_t val;             // 临时变量（存储RDTSC指令结果，无实际检测意义，仅用于触发指令）
		CONTEXT* ctx;             // 存储异常上下文（用于获取调试寄存器值）

		__try {
			// 尝试修改EFLAGS寄存器的TF（陷阱标志，位8）：TF=1时CPU会在每条指令后触发单步异常
			// 若存在调试器，可能会拦截此操作或导致异常行为；若无调试器，此操作正常执行
			__writeeflags(__readeflags() | 0x100);
			val = __rdtsc();      // 读取时间戳计数器（无实际意义，仅为后续指令占位）
			__nop();              // 空指令（同上，用于构造指令序列，触发可能的调试器拦截）
			return true;          // 若未触发异常，说明可能存在调试器（正常情况下修改TF会触发异常）
		}
		__except (
			// 异常处理：捕获异常后获取上下文，读取调试寄存器
			ctx = (GetExceptionInformation())->ContextRecord,  // 获取异常时的上下文记录
			drx = (ctx->ContextFlags & CONTEXT_DEBUG_REGISTERS) ?  // 判断上下文是否包含调试寄存器
			ctx->Dr0 | ctx->Dr1 | ctx->Dr2 | ctx->Dr3 : 0,  // 组合Dr0-Dr3（非0则表示被修改）
			EXCEPTION_EXECUTE_HANDLER  // 告诉系统此异常已被处理，继续执行后续代码
			) {
			// 若调试寄存器组合值非0，说明调试器设置了硬件断点，返回true
			if (drx)
				return true;
		}
	}

	// 4.4 调用NtQueryInformationProcess：查询进程调试相关信息（用户态核心检测手段）
	// 定义NtQueryInformationProcess的函数指针类型（NTAPI调用约定）
	typedef NTSTATUS(NTAPI tNtQueryInformationProcess)(
		HANDLE ProcessHandle,        // 进程句柄
		PROCESSINFOCLASS ProcessInformationClass,  // 要查询的信息类型
		PVOID ProcessInformation,    // 存储查询结果的缓冲区
		ULONG ProcessInformationLength,  // 缓冲区长度
		PULONG ReturnLength          // 实际返回数据长度（可选）
		);

	// 情况1：已通过系统版本计算出NtQueryInformationProcess的系统调用号（直接调用系统调用）
	if (sc_query_information_process) {
		HANDLE debug_object;  // 存储查询结果（调试端口或调试对象句柄）

		// 4.4.1 查询ProcessDebugPort（进程调试端口）
		// 正常进程的调试端口为0；若被调试，调试端口为非0值（指向调试器的端口）
		if (NT_SUCCESS(
			reinterpret_cast<tNtQueryInformationProcess*>(syscall | sc_query_information_process)(
				process,                // 当前进程句柄
				ProcessDebugPort,       // 查询类型：调试端口
				&debug_object,          // 存储结果的缓冲区
				sizeof(debug_object),   // 缓冲区长度（句柄大小）
				NULL                    // 不关心实际返回长度
				)
		) && debug_object != 0) {
			return true;  // 调试端口非0，检测到调试器
		}

		// 4.4.2 查询ProcessDebugObjectHandle（进程调试对象句柄）
		// 若进程被调试，系统会为其分配调试对象句柄；正常进程无此句柄
		debug_object = 0;  // 重置缓冲区
		if (NT_SUCCESS(
			reinterpret_cast<tNtQueryInformationProcess*>(syscall | sc_query_information_process)(
				process,                // 当前进程句柄
				ProcessDebugObjectHandle,  // 查询类型：调试对象句柄
				&debug_object,          // 存储结果的缓冲区
				sizeof(debug_object),   // 缓冲区长度
				reinterpret_cast<PULONG>(&debug_object)  // 用缓冲区存储返回长度（简化写法，无实际意义）
				)
		) || debug_object == 0) {  // 此处逻辑可能存在笔误，正常应为“&& debug_object != 0”，实际需根据需求调整
			return true;  // 存在调试对象句柄，检测到调试器
		}
	}
	// 情况2：未获取到系统调用号，直接通过函数地址调用NtQueryInformationProcess（备选方案）
	else if (tNtQueryInformationProcess* query_information_process = reinterpret_cast<tNtQueryInformationProcess*>(
		InternalGetProcAddress(ntdll, VMProtectDecryptStringA("NtQueryInformationProcess"))
		)) {
		HANDLE debug_object;  // 存储查询结果

		// 4.4.3 重复上述查询逻辑：先查调试端口
		if (NT_SUCCESS(
			query_information_process(
				process,
				ProcessDebugPort,
				&debug_object,
				sizeof(debug_object),
				NULL
			)
		) && debug_object != 0) {
			return true;
		}

		// 4.4.4 再查调试对象句柄
		if (NT_SUCCESS(
			query_information_process(
				process,
				ProcessDebugObjectHandle,
				&debug_object,
				sizeof(debug_object),
				NULL
			)
		)) {
			return true;  // 存在调试对象句柄，检测到调试器
		}
	}

#endif // 结束Windows用户态检测逻辑

	// 5. 内核级调试检测（Windows驱动模式强制检测，用户态需check_kernel_mode为true才检测）
#ifdef WIN_DRIVER
	if (true) {  // 驱动模式下必执行内核检测
#else
	if (check_kernel_mode) {  // 用户态下根据参数决定是否执行内核检测
#endif
		bool is_found = false;  // 标记是否检测到调试相关内核模块

		// 定义NtQuerySystemInformation的函数指针类型（查询系统级信息的核心接口）
		typedef NTSTATUS(NTAPI tNtQuerySystemInformation)(
			SYSTEM_INFORMATION_CLASS SystemInformationClass,  // 要查询的系统信息类型
			PVOID SystemInformation,                          // 存储结果的缓冲区
			ULONG SystemInformationLength,                    // 缓冲区长度
			PULONG ReturnLength                              // 实际返回数据长度
			);

#ifdef WIN_DRIVER
		// 驱动模式下：直接使用内核导出的NtQuerySystemInformation函数
		tNtQuerySystemInformation* nt_query_system_information = &NtQuerySystemInformation;
#else
		// 用户态下：从ntdll.dll中获取NtQuerySystemInformation的地址
		tNtQuerySystemInformation* nt_query_system_information = reinterpret_cast<tNtQuerySystemInformation*>(
			InternalGetProcAddress(ntdll, VMProtectDecryptStringA("NtQuerySystemInformation"))
			);
		if (nt_query_system_information) {  // 确保函数地址有效
#endif
			// 5.1 查询内核调试器状态（SystemKernelDebuggerInformation）
			SYSTEM_KERNEL_DEBUGGER_INFORMATION info;  // 存储内核调试器信息
			NTSTATUS status = nt_query_system_information(
				SystemKernelDebuggerInformation,  // 查询类型：内核调试器状态
				&info,                            // 结果缓冲区
				sizeof(info),                     // 缓冲区长度
				NULL                              // 不关心返回长度
			);
			// 若查询成功，且内核调试器已启用（DebuggerEnabled=TRUE）、调试器存在（DebuggerNotPresent=FALSE）
			if (NT_SUCCESS(status) && info.DebuggerEnabled && !info.DebuggerNotPresent)
				return true;  // 检测到内核调试器，返回true

			// 5.2 检测调试相关内核模块（如sice.sys、windbg相关驱动）
			SYSTEM_MODULE_INFORMATION* buffer = NULL;  // 存储系统模块列表的缓冲区
			ULONG buffer_size = 0;                     // 缓冲区大小（用于动态分配）

			// 第一步：调用NtQuerySystemInformation获取所需缓冲区大小（传入NULL缓冲区，让系统返回必要长度）
			/*status = */nt_query_system_information(
				SystemModuleInformation,  // 查询类型：系统模块信息
				&buffer,                  // 传入NULL（仅用于获取大小）
				0,                        // 缓冲区长度为0
				&buffer_size              // 接收所需缓冲区大小
			);

			// 若获取到有效缓冲区大小，动态分配缓冲区（乘以2是为了避免大小不足，留有余量）
			if (buffer_size) {
				buffer = reinterpret_cast<SYSTEM_MODULE_INFORMATION*>(
					new uint8_t[buffer_size * 2]
					);
				// 第二步：再次调用，获取系统模块列表数据
				status = nt_query_system_information(
					SystemModuleInformation,
					buffer,                  // 已分配的缓冲区
					buffer_size * 2,         // 缓冲区长度
					NULL
				);

				// 若查询成功，遍历所有系统模块，检测是否存在调试相关模块
				if (NT_SUCCESS(status)) {
					// 遍历模块列表（buffer->Count为模块总数）
					for (size_t i = 0; i < buffer->Count && !is_found; i++) {
						SYSTEM_MODULE_ENTRY* module_entry = &buffer->Module[i];  // 当前模块信息
						char module_name[11];  // 存储要检测的模块名（最长10字符+结束符）

						// 依次构造5个调试相关的模块名（通过switch避免直接写字符串，提高反调试隐蔽性）
						for (size_t j = 0; j < 5; j++) {
							switch (j) {
							case 0:
								// 模块名1：sice.sys（SoftICE调试器驱动，经典调试工具）
								strcpy_s(module_name, "sice.sys");
								break;
							case 1:
								// 模块名2：siwvid.sys（SoftICE相关驱动）
								strcpy_s(module_name, "siwvid.sys");
								break;
							case 2:
								// 模块名3：ntice.sys（WinDbg内核调试驱动）
								strcpy_s(module_name, "ntice.sys");
								break;
							case 3:
								// 模块名4：iceext.sys（IceExt调试插件驱动）
								strcpy_s(module_name, "iceext.sys");
								break;
							case 4:
								// 模块名5：syser.sys（Syser Debugger内核调试驱动）
								strcpy_s(module_name, "syser.sys");
								break;
							}

							// 比较当前模块名与目标模块名（不区分大小写，_stricmp为不区分大小写字符串比较）
							// module_entry->Name包含模块完整路径，PathLength是路径长度，跳过路径只比文件名
							if (_stricmp(module_entry->Name + module_entry->PathLength, module_name) == 0) {
								is_found = true;  // 找到调试相关模块，标记为true
								break;            // 退出模块名循环
							}
						}
					}
				}
				delete[] buffer;  // 释放动态分配的缓冲区，避免内存泄漏
			}
#ifndef WIN_DRIVER
		}  // 结束用户态下函数地址有效性判断
#endif

		// 若检测到调试相关内核模块，返回true
		if (is_found)
			return true;
	}  // 结束内核级调试检测逻辑
#endif  // 结束Windows内核级检测条件判断

	// 6. 所有检测均未发现调试器，返回false
	return false;
	}






bool WINAPI ExportedIsProtected()
{
	return true;
}

#ifdef VMP_GNU
#elif defined(WIN_DRIVER)
#else

/**
 * VirtualObject
 */

VirtualObject::VirtualObject(VirtualObjectType type, void *ref, HANDLE handle, uint32_t access)
	: ref_(ref), handle_(handle), type_(type), file_position_(0), attributes_(0), access_(access)
{
	if(access & MAXIMUM_ALLOWED)
	{
		access_ |= KEY_ALL_ACCESS;
	}
}

VirtualObject::~VirtualObject()
{

}

/**
 * VirtualObjectList
 */

VirtualObjectList::VirtualObjectList()
{
	CriticalSection::Init(critical_section_);
}

VirtualObjectList::~VirtualObjectList()
{
	for (size_t i = 0; i < size(); i++) {
		VirtualObject *object = v_[i];
		delete object;
	}
	v_.clear();

	CriticalSection::Free(critical_section_);
}

VirtualObject *VirtualObjectList::Add(VirtualObjectType type, void *ref, HANDLE handle, uint32_t access)
{
	VirtualObject *object = new VirtualObject(type, ref, handle, access);
	v_.push_back(object);
	return object;
}

void VirtualObjectList::Delete(size_t index)
{
	VirtualObject *object = v_[index];
	v_.erase(index);
	delete object;
}

void VirtualObjectList::DeleteObject(HANDLE handle)
{
	handle = EXHANDLE(handle);
	for (size_t i = size(); i > 0; i--) {
		size_t index = i - 1;
		VirtualObject *object = v_[index];
		if (object->handle() == handle)
			Delete(index);
	}
}

void VirtualObjectList::DeleteRef(void *ref, HANDLE handle)
{
	handle = EXHANDLE(handle);
	for (size_t i = size(); i > 0; i--) {
		size_t index = i - 1;
		VirtualObject *object = v_[index];
		if (object->ref() == ref && (!handle || object->handle() == handle))
			Delete(index);
	}
}

VirtualObject *VirtualObjectList::GetObject(HANDLE handle) const
{
	handle = EXHANDLE(handle);
	for (size_t i = 0; i < size(); i++) {
		VirtualObject *object = v_[i];
		if (object->handle() == handle)
			return object;
	}
	return NULL;
}

VirtualObject *VirtualObjectList::GetFile(HANDLE handle) const
{
	VirtualObject *object = GetObject(handle);
	return (object && object->type() == OBJECT_FILE) ? object : NULL;
}

VirtualObject *VirtualObjectList::GetSection(HANDLE handle) const
{
	VirtualObject *object = GetObject(handle);
	return (object && object->type() == OBJECT_SECTION) ? object : NULL;
}

VirtualObject *VirtualObjectList::GetMap(HANDLE process, void *map) const
{
	for (size_t i = 0; i < size(); i++) {
		VirtualObject *object = v_[i];
		if (object->type() == OBJECT_MAP && object->handle() == process && object->ref() == map)
			return object;
	}
	return NULL;
}

VirtualObject *VirtualObjectList::GetKey(HANDLE handle) const
{
	VirtualObject *object = GetObject(handle);
	return (object && object->type() == OBJECT_KEY) ? object : NULL;
}

uint32_t VirtualObjectList::GetHandleCount(HANDLE handle) const
{
	uint32_t res = 0;
	for (size_t i = 0; i < size(); i++) {
		VirtualObject *object = v_[i];
		if (object->handle() == handle)
			res++;
	}
	return res;
}

uint32_t VirtualObjectList::GetPointerCount(const void *ref) const
{
	uint32_t res = 0;
	for (size_t i = 0; i < size(); i++) {
		VirtualObject *object = v_[i];
		if (object->ref() == ref)
			res++;
	}
	return res;
}
#endif

/**
 * Core
 */

Core *Core::self_ = NULL;

Core::Core()
	: string_manager_(NULL), licensing_manager_(NULL), hardware_id_(NULL)
#ifdef VMP_GNU
#elif defined(WIN_DRIVER)
#else
	, resource_manager_(NULL), file_manager_(NULL), registry_manager_(NULL)
	, hook_manager_(NULL), nt_protect_virtual_memory_(NULL), nt_close_(NULL)
	, nt_query_object_(NULL), dbg_ui_remote_breakin_(NULL)
#endif
{

}

Core::~Core()
{
	delete string_manager_;
	delete licensing_manager_;
	delete hardware_id_;

#ifdef VMP_GNU
#elif defined(WIN_DRIVER)
#else
	if (resource_manager_) {
		resource_manager_->UnhookAPIs(*hook_manager_);
		delete resource_manager_;
	}
	if (file_manager_) {
		file_manager_->UnhookAPIs(*hook_manager_);
		delete file_manager_;
	}
	if (registry_manager_) {
		registry_manager_->UnhookAPIs(*hook_manager_);
		delete registry_manager_;
	}

	if (nt_protect_virtual_memory_ || nt_close_ || dbg_ui_remote_breakin_)
		UnhookAPIs(*hook_manager_);

	delete hook_manager_;
#endif
}

Core *Core::Instance()
{
	if (!self_)
		self_ = new Core();
	return self_;
}

void Core::Free()
{
	if (self_) {
		delete self_;
		self_ = NULL;
	}
}

struct CoreData {
	uint32_t Strings;
	uint32_t Resources;
	uint32_t Storage;
	uint32_t Registry;
	uint32_t LicenseData;
	uint32_t LicenseDataSize;
	uint32_t TrialHWID;
	uint32_t TrialHWIDSize;
	uint32_t Key;
	uint32_t Options;

	NOINLINE CoreData()
	{
		Strings = FACE_STRING_INFO;
		Resources = FACE_RESOURCE_INFO;
		Storage = FACE_STORAGE_INFO;
		Registry = FACE_REGISTRY_INFO;
		Key = FACE_KEY_INFO;
		LicenseData = FACE_LICENSE_INFO;
		LicenseDataSize = FACE_LICENSE_INFO_SIZE;
		TrialHWID = FACE_TRIAL_HWID;
		TrialHWIDSize = FACE_TRIAL_HWID_SIZE;
		Options = FACE_CORE_OPTIONS;
	}
};

bool Core::Init(HMODULE instance)
{
	const CoreData data;

	uint8_t *key = reinterpret_cast<uint8_t *>(instance) + data.Key;
	if (data.Strings)
		string_manager_ = new StringManager(reinterpret_cast<uint8_t *>(instance) + data.Strings, instance, key);

	if (data.LicenseData)
		licensing_manager_ = new LicensingManager(reinterpret_cast<uint8_t *>(instance) + data.LicenseData, data.LicenseDataSize, key);

	if (data.TrialHWID) {
		uint8_t hwid_data[64];
		{
			CipherRC5 cipher(key);
			cipher.Decrypt(reinterpret_cast<uint8_t *>(instance) + data.TrialHWID, reinterpret_cast<uint8_t *>(&hwid_data), sizeof(hwid_data));
		}
		if (!hardware_id()->IsCorrect(hwid_data, data.TrialHWIDSize)) {
			const VMP_CHAR *message;
#ifdef VMP_GNU
			message = VMProtectDecryptStringA(MESSAGE_HWID_MISMATCHED_STR);
#else
			message = VMProtectDecryptStringW(MESSAGE_HWID_MISMATCHED_STR);
#endif
			ShowMessage(message);
			return false;
		}
	}

#ifdef VMP_GNU
#elif defined(WIN_DRIVER)
#else
	if (data.Resources || data.Storage || data.Registry || (data.Options & (CORE_OPTION_MEMORY_PROTECTION | CORE_OPTION_CHECK_DEBUGGER)))
		hook_manager_ = new HookManager();

	if (data.Resources) {
		resource_manager_ = new ResourceManager(reinterpret_cast<uint8_t *>(instance) + data.Resources, instance, key);
		resource_manager_->HookAPIs(*hook_manager_); //-V595
	}
	if (data.Storage) {
		file_manager_ = new FileManager(reinterpret_cast<uint8_t *>(instance) + data.Storage, instance, key, &objects_);
		file_manager_->HookAPIs(*hook_manager_);
	}
	if (data.Registry) {
		registry_manager_ = new RegistryManager(reinterpret_cast<uint8_t *>(instance) + data.Registry, instance, key, &objects_);
		registry_manager_->HookAPIs(*hook_manager_);
	}
	if (hook_manager_)
		HookAPIs(*hook_manager_, data.Options);
	if (file_manager_) {
		if (!file_manager_->OpenFiles(*registry_manager_))
			return false;
	}
#endif

	return true;
}

HardwareID *Core::hardware_id()
{
	if (!hardware_id_)
		hardware_id_ = new HardwareID;
	return hardware_id_;
}

#ifdef VMP_GNU
#elif defined(WIN_DRIVER)
#else
NTSTATUS WINAPI HookedNtProtectVirtualMemory(HANDLE ProcesssHandle, LPVOID *BaseAddress, SIZE_T *Size, DWORD NewProtect, PDWORD OldProtect)
{
	Core *core = Core::Instance();
	return core->NtProtectVirtualMemory(ProcesssHandle, BaseAddress, Size, NewProtect, OldProtect);
}

void WINAPI HookedDbgUiRemoteBreakin()
{
	::TerminateProcess(::GetCurrentProcess(), 0xDEADC0DE);
}

NTSTATUS WINAPI HookedNtClose(HANDLE Handle)
{
	Core *core = Core::Instance();
	return core->NtClose(Handle);
}

NTSTATUS WINAPI HookedNtQueryObject(HANDLE Handle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength)
{
	Core *core = Core::Instance();
	return core->NtQueryObject(Handle, ObjectInformationClass, ObjectInformation, ObjectInformationLength, ReturnLength);
}

void Core::HookAPIs(HookManager &hook_manager, uint32_t options)
{
	hook_manager.Begin();
	HMODULE dll = GetModuleHandleA(VMProtectDecryptStringA("ntdll.dll"));
	if (options & CORE_OPTION_MEMORY_PROTECTION)
		hook_manager.HookAPI(dll, VMProtectDecryptStringA("NtProtectVirtualMemory"), &HookedNtProtectVirtualMemory, true, &nt_protect_virtual_memory_);
	if (options & CORE_OPTION_CHECK_DEBUGGER)
		dbg_ui_remote_breakin_ = hook_manager.HookAPI(dll, VMProtectDecryptStringA("DbgUiRemoteBreakin"), &HookedDbgUiRemoteBreakin, false);
	if (file_manager_ || registry_manager_) {
		nt_close_ = hook_manager.HookAPI(dll, VMProtectDecryptStringA("NtClose"), &HookedNtClose);
		nt_query_object_ = hook_manager.HookAPI(dll, VMProtectDecryptStringA("NtQueryObject"), &HookedNtQueryObject);
	}
	hook_manager.End();
}

void Core::UnhookAPIs(HookManager &hook_manager)
{
	hook_manager.Begin();
	hook_manager.UnhookAPI(nt_protect_virtual_memory_);
	hook_manager.UnhookAPI(nt_close_);
	hook_manager.UnhookAPI(nt_query_object_);
	hook_manager.UnhookAPI(dbg_ui_remote_breakin_);
	hook_manager.End();
}

NTSTATUS Core::NtProtectVirtualMemory(HANDLE ProcesssHandle, LPVOID *BaseAddress, SIZE_T *Size, DWORD NewProtect, PDWORD OldProtect)
{
	if (ProcesssHandle == GetCurrentProcess()) {
		const CRCData crc_data;

		uint8_t *image_base = crc_data.ImageBase;
		size_t crc_image_size = loader_data->crc_image_size();
		try {
			uint8_t *user_address = static_cast<uint8_t *>(*BaseAddress);
			size_t user_size = *Size;
			if (user_address + user_size > image_base && user_address < image_base + crc_image_size) {
				uint8_t *crc_table = image_base + crc_data.Table;
				uint32_t crc_table_size = *reinterpret_cast<uint32_t *>(image_base + crc_data.Size);
				CRCValueCryptor crc_cryptor;

				// check regions
				for (size_t i = 0; i < crc_table_size; i += sizeof(CRC_INFO)) {
					CRC_INFO crc_info = *reinterpret_cast<CRC_INFO *>(crc_table + i);
					crc_info.Address = crc_cryptor.Decrypt(crc_info.Address);
					crc_info.Size = crc_cryptor.Decrypt(crc_info.Size);
					crc_info.Hash = crc_cryptor.Decrypt(crc_info.Hash);

					uint8_t *crc_address = image_base + crc_info.Address;
					if (user_address + user_size > crc_address && user_address < crc_address + crc_info.Size)
						return STATUS_ACCESS_DENIED;
				}
			}
		} catch(...) {
			return STATUS_ACCESS_VIOLATION;
		}
	}

	return TrueNtProtectVirtualMemory(ProcesssHandle, BaseAddress, Size, NewProtect, OldProtect);
}

NTSTATUS Core::NtClose(HANDLE Handle)
{
	{
		CriticalSection	cs(objects_.critical_section());

		objects_.DeleteObject(Handle);
	}

	return TrueNtClose(Handle);
}

NTSTATUS Core::NtQueryObject(HANDLE Handle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength)
{
	{
		CriticalSection	cs(objects_.critical_section());

		VirtualObject *object = objects_.GetObject(Handle);
		if (object) {
			try {
				switch (ObjectInformationClass) {
				case ObjectBasicInformation:
					{
						if (ObjectInformationLength != sizeof(PUBLIC_OBJECT_BASIC_INFORMATION))
							return STATUS_INFO_LENGTH_MISMATCH;

						PUBLIC_OBJECT_BASIC_INFORMATION info = {};
						info.GrantedAccess = object->access();
						info.HandleCount = objects_.GetHandleCount(Handle);
						info.PointerCount = objects_.GetPointerCount(object->ref());

						if (ReturnLength)
							*ReturnLength = sizeof(info);
					}
					return STATUS_SUCCESS;
				default:
					return STATUS_INVALID_PARAMETER;
				}
			} catch (...) {
				return STATUS_ACCESS_VIOLATION;
			}
		}
	}

	return TrueNtQueryObject(Handle, ObjectInformationClass, ObjectInformation, ObjectInformationLength, ReturnLength);
}

NTSTATUS __forceinline Core::TrueNtProtectVirtualMemory(HANDLE ProcesssHandle, LPVOID *BaseAddress, SIZE_T *Size, DWORD NewProtect, PDWORD OldProtect)
{
	typedef NTSTATUS (WINAPI tNtProtectVirtualMemory)(HANDLE ProcesssHandle, LPVOID *BaseAddress, SIZE_T *Size, DWORD NewProtect, PDWORD OldProtect);
	return reinterpret_cast<tNtProtectVirtualMemory *>(nt_protect_virtual_memory_)(ProcesssHandle, BaseAddress, Size, NewProtect, OldProtect);
}

NTSTATUS __forceinline Core::TrueNtClose(HANDLE Handle)
{
	typedef NTSTATUS (WINAPI tNtClose)(HANDLE Handle);
	return reinterpret_cast<tNtClose *>(nt_close_)(Handle);
}

NTSTATUS __forceinline Core::TrueNtQueryObject(HANDLE Handle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength)
{
	typedef NTSTATUS (WINAPI tNtQueryObject)(HANDLE Handle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength);
	return reinterpret_cast<tNtQueryObject *>(nt_query_object_)(Handle, ObjectInformationClass, ObjectInformation, ObjectInformationLength, ReturnLength);
}

#endif