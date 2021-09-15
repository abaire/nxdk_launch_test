#include <hal/video.h>
#include <hal/xbox.h>
#include <nxdk/mount.h>
#include <nxdk/path.h>
#include <pbkit/pbkit.h>
#include <windows.h>
#include <xboxkrnl/xboxkrnl.h>

#include <cassert>
#include <cstring>
#include <string>

// Mounts the path containing this xbe as "A:".
static BOOL mount_drive_a() {
  if (nxIsDriveMounted('A')) {
    DbgPrint("A: already mounted!");
    return FALSE;
  }

  CHAR targetPath[MAX_PATH];
  nxGetCurrentXbeNtPath(targetPath);

  LPSTR filenameStr;
  filenameStr = strrchr(targetPath, '\\');
  assert(filenameStr != NULL);
  *(filenameStr + 1) = '\0';

  BOOL status = nxMountDrive('A', targetPath);
  return status;
}

static BOOL mount_drives() {
  if (!mount_drive_a()) {
    DbgPrint("[ERROR]: Mounting error: Could not mount drive A\n");
    return FALSE;
  }
  if (!nxMountDrive('X', R"(\Device\Harddisk0\Partition3)")) {
    DbgPrint("[ERROR]: Mounting error: Could not mount drive X\n");
    return FALSE;
  }
  if (!nxMountDrive('Y', R"(\Device\Harddisk0\Partition4)")) {
    DbgPrint("[ERROR]: Mounting error: Could not mount drive Y\n");
    return FALSE;
  }
  if (!nxMountDrive('Z', R"(\Device\Harddisk0\Partition5)")) {
    DbgPrint("[ERROR]: Mounting error: Could not mount drive Z\n");
    return FALSE;
  }
  return TRUE;
}

static void ListADir() {
  WIN32_FIND_DATA find_data;

  DbgPrint("Listing contents of \\Device\\CdRom0\\:");
  HANDLE h = FindFirstFile(R"(D:\*)", &find_data);
  if (h != INVALID_HANDLE_VALUE) {
    do {
      if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
        printf("Test\n");
        DbgPrint("Dir: %s\n", find_data.cFileName);
      } else {
        LARGE_INTEGER filesize;
        filesize.LowPart = find_data.nFileSizeLow;
        filesize.HighPart = find_data.nFileSizeHigh;

        DbgPrint("File: %s - %lld\n", find_data.cFileName, filesize.QuadPart);
      }
    } while (FindNextFile(h, &find_data));

    CloseHandle(h);
  }
}

static void PrintLaunchInfo(const PLAUNCH_DATA_PAGE launch_info) {
  DbgPrint("Launch info addr is now: 0x%X", launch_info);

  const LAUNCH_DATA_HEADER &header = launch_info->Header;
  DbgPrint("Launch Data Type: 0x%X", header.dwLaunchDataType);
  DbgPrint("Flags: 0x%X", header.dwFlags);
  DbgPrint("TitleID: 0x%X", header.dwTitleId);
  DbgPrint("Launch Path: %s", header.szLaunchPath);

  DbgPrint("Data: %x", *(DWORD *)launch_info->LaunchData);
  //  DWORD launchDataType = LaunchDataPage->Header.dwLaunchDataType;
  //  DbgPrint("Launch data type: 0x%X", launchDataType);
}

static void dump_mem(unsigned char *addr, DWORD len, std::string &out_mem,
                     std::string &out_char) {
  char buf[4] = {0};
  out_mem.clear();
  out_char.clear();

  for (DWORD i = 0; i < len; ++i) {
    unsigned char value = addr[i];
    sprintf(buf, "%2.2x ", value);
    out_mem += buf;

    if (value >= 0x20 && value <= 0x7E) {
      out_char.push_back((char)value);
    } else {
      out_char.push_back('.');
    }
  }
}

static void pretty_dump_mem(unsigned char *addr, DWORD len) {
  int lines = (ceil((double)len / 16.0));

  unsigned char *base = addr;
  std::string hexbuf;
  std::string charbuf;

  for (int i = 0; i < lines; ++i, base += 16) {
    dump_mem(base, 16, hexbuf, charbuf);
    DbgPrint("%p: %s %s", base, hexbuf.c_str(), charbuf.c_str());
  }
}

static void DumpText(const PIMAGE_NT_HEADERS32 pe_header,
                     const IMAGE_SECTION_HEADER &section) {
  DbgPrint("FOUND .text");
  const char *section_addr = (const char *)pe_header->OptionalHeader.ImageBase +
                             section.VirtualAddress;
  DbgPrint("Virtual address: %p", section.VirtualAddress);
  DbgPrint("Section content at %p", section_addr);
  DbgPrint("Virtual size: %d", section.Misc.VirtualSize);
  DbgPrint("Raw size: %d", section.Misc.VirtualSize);

  DbgPrint(".text page:\n");
  pretty_dump_mem((unsigned char *)section_addr, section.SizeOfRawData);
}

static void DumpSticky(const PIMAGE_NT_HEADERS32 pe_header,
                       const IMAGE_SECTION_HEADER &section) {
  DbgPrint("FOUND STICKY SECTION!");
  const char *sticky_addr = (const char *)pe_header->OptionalHeader.ImageBase +
                            section.VirtualAddress;
  DbgPrint("Virtual address: %p", section.VirtualAddress);
  DbgPrint("Section content at %p", sticky_addr);
  DbgPrint("Virtual size: %d", section.Misc.VirtualSize);
  DbgPrint("Raw size: %d", section.Misc.VirtualSize);
  DbgPrint("End addr: %p", sticky_addr + section.Misc.VirtualSize);

  char *pre_set = (char *)malloc(section.SizeOfRawData);
  memcpy(pre_set, sticky_addr, section.SizeOfRawData);

  char *temp = (char *)MmAllocateContiguousMemory(32);
  strcpy(temp, "ERIKERIK");
  MmPersistContiguousMemory(temp, 32, TRUE);
  DbgPrint("Wrote persistent memory at %p", temp);

  int status = memcmp(pre_set, sticky_addr, section.SizeOfRawData);
  DbgPrint("Memory change status: %d", status);
  free(pre_set);

  DbgPrint("STICKY page:\n");
  pretty_dump_mem((unsigned char *)sticky_addr, section.SizeOfRawData);
}

static PIMAGE_EXPORT_DIRECTORY find_edataxb(void) {
  //  DWORD num_sections = CURRENT_XBE_HEADER->NumberOfSections;
  //  PXBE_SECTION_HEADER section_header_addr =
  //  CURRENT_XBE_HEADER->PointerToSectionTable;
  //
  //  for (DWORD i = 0; i < num_sections; i++) {
  //    DbgPrint("SECTION %d: %s", i, section_header_addr[i].SectionName);
  ////    if (memcmp(section_header_addr[i].SectionName, ".edataxb", 8) == 0) {
  ////      return
  ///(PIMAGE_EXPORT_DIRECTORY)section_header_addr[i].VirtualAddress; /    }
  //  }

  BYTE *header_base = (BYTE *)(0x80000000 + XBE_DEFAULT_BASE);
  PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)header_base;
  assert(dos_header->e_magic == IMAGE_DOS_SIGNATURE);

  PIMAGE_NT_HEADERS32 pe_header =
      (PIMAGE_NT_HEADERS32)(header_base + dos_header->e_lfanew);
  assert(pe_header->Signature == IMAGE_NT_SIGNATURE);
  DWORD num_sections = pe_header->FileHeader.NumberOfSections;

  PIMAGE_SECTION_HEADER kernel_sections =
      (PIMAGE_SECTION_HEADER)((BYTE *)&pe_header->OptionalHeader +
                              pe_header->FileHeader.SizeOfOptionalHeader);

  for (DWORD i = 0; i < num_sections; ++i) {
    DbgPrint("SECTION %d: %s", i, kernel_sections[i].Name);
    IMAGE_SECTION_HEADER &section = kernel_sections[i];

//    if (!memcmp(section.Name, "STICKY", 6)) {
//      DumpSticky(pe_header, section);
//      continue;
//    }

    //    if (!memcmp(section.Name, ".text", 5)) {
    //      DumpText(pe_header, section);
    //      continue;
    //    }
  }

  return NULL;
}

int main() {
  DbgPrint("MmGlobalData: 0x%x", MmGlobalData);
  DbgPrint("KdDebuggerEnabled: 0x%x", KdDebuggerEnabled);
  DbgPrint("KdDebuggerNotPresent: 0x%x", KdDebuggerNotPresent);
  DbgPrint("XeImageFileName: 0x%x", XeImageFileName);
  XBOX_KRNL_VERSION kver = XboxKrnlVersion;
  DbgPrint("KVER: %d.%d.%d %d", kver.Major, kver.Minor, kver.Build, kver.Qfe);
  DbgPrint("LANKEY: %x", XboxLANKey);

  XBOX_HARDWARE_INFO hwinfo = XboxHardwareInfo;
  DbgPrint("HWInfo: FLAGS: 0x%x, GPU: %d, MCP: %d", hwinfo.Flags,
           hwinfo.GpuRevision, hwinfo.McpRevision);

  DWORD num_sections = CURRENT_XBE_HEADER->NumberOfSections;
  PXBE_SECTION_HEADER section_header_addr =
      CURRENT_XBE_HEADER->PointerToSectionTable;

  for (DWORD i = 0; i < num_sections; i++) {
    DbgPrint("Section: %s", section_header_addr[i].SectionName);
    //    if (memcmp(section_header_addr[i].SectionName, ".edataxb", 8) == 0) {
    //      return
    //      (PIMAGE_EXPORT_DIRECTORY)section_header_addr[i].VirtualAddress;
    //    }
  }

  PLAUNCH_DATA_PAGE ld = (PLAUNCH_DATA_PAGE)&LaunchDataPage;
  DbgPrint("Address of LaunchDataPage: %p", ld);
  DbgPrint("Value of LaunchDataPage: %p", LaunchDataPage);

  //  const UCHAR *persisted_load_data = (const UCHAR *)0x83eb2000;
  //  PrintLaunchInfo((PLAUNCH_DATA_PAGE)persisted_load_data);

  //  PVOID temp = MmAllocateContiguousMemory(0x1000);
  //  DWORD_PTR base = (DWORD_PTR)0x83fdf000;
  //  DWORD_PTR real = MmGetPhysicalAddress((PVOID)base);
  //  MEMORY_BASIC_INFORMATION info;
  //
  //  for (int i = 0; i < 100; ++i) {
  //    NTSTATUS status = NtQueryVirtualMemory((PVOID)base, &info);
  //    if (!SUCCEEDED(status)) {
  //      DbgPrint("Failed to dump memory info for addr %x: %x", base, status);
  //      break;
  //    }
  //    Sleep(1);
  //  }

  //  DbgPrint("Loading sticky section.");
  //  UCHAR foo[1024] = "STICKY";
  //  XBEIMAGE_SECTION sticky_section;
  //  memset(&sticky_section, 0, sizeof(sticky_section));
  //  sticky_section.SectionName = foo;
  //  XeLoadSection(&sticky_section);
  //
  PIMAGE_EXPORT_DIRECTORY exportdir = find_edataxb();
  //  if (!exportdir) {
  //    SetLastError(ERROR_PROC_NOT_FOUND);
  //    return NULL;
  //  }

  //  for (DWORD i = 0; i < exportdir->NumberOfNames; i++) {
  //    const char **nametable = (const char **)(exportdir->AddressOfNames +
  //    XBE_DEFAULT_BASE); const char *name_addr = (const char *)(nametable[i] +
  //    XBE_DEFAULT_BASE);
  //
  ////    if (strcmp(lpProcName, name_addr) == 0) {
  ////      // Found a matching name and its index. This index is not valid for
  /// the address table, that index needs to be looked up in the ordinal table!
  ////      WORD *ordtable = (WORD *)(exportdir->AddressOfNameOrdinals +
  /// XBE_DEFAULT_BASE); /      BYTE **proctable = (BYTE
  ///**)(exportdir->AddressOfFunctions + XBE_DEFAULT_BASE); /      return
  ///(FARPROC)proctable[ordtable[i]] + XBE_DEFAULT_BASE; /    }
  //  }

  //  if (LaunchDataPage == nullptr) {
  //    LaunchDataPage =
  //        static_cast<PLAUNCH_DATA_PAGE>(MmAllocateContiguousMemory(0x1000));
  //    DbgPrint("Allocated LaunchDataPage at: 0x%X", LaunchDataPage);
  //  }
  //  PrintLaunchInfo(LaunchDataPage);

  XVideoSetMode(640, 480, 32, REFRESH_DEFAULT);

  BOOL pbk_started = pb_init() == 0;
  if (!pbk_started) {
    DbgPrint("pbkit init failed\n");
    return 1;
  }
  pb_show_front_screen();

  for (int frame = 0; frame < 120; ++frame) {
    pb_wait_for_vbl();
    pb_target_back_buffer();
    pb_reset();
    pb_fill(0, 0, 640, 480, 0xFF003E3E);
    pb_erase_text_screen();

    pb_print("LaunchDataPage at %p\n", LaunchDataPage);

    PLAUNCH_DATA_PAGE ld = (PLAUNCH_DATA_PAGE)&LaunchDataPage;
    pb_print("Address of LaunchDataPage: %p", ld);

//    std::string buf;
//    for (int i = 0; i < 4; ++i) {
//      dump_mem((unsigned char *)sticky_section + (16 * i), 16, buf);
//      pb_print("%s\n", buf.c_str());
//    }

    pb_draw_text_screen();
    while (pb_busy())
      ;
    while (pb_finished())
      ;
  }

  //  DbgPrint("Sleeping for 10 minutes and rebooting.");
  //  XReboot();
  if (pbk_started) {
    pb_kill();
  }

  //  if (!mount_drives()) {
  //    return ERROR_GEN_FAILURE;
  //  }
  //
  //  ListADir();

  CHAR targetPath[MAX_PATH];
  nxGetCurrentXbeNtPath(targetPath);
  CHAR *last_slash = std::strrchr(targetPath, '\\');
  strcpy(last_slash + 1, R"(sub_process.xbe)");

  UCHAR launchData[sizeof(LaunchDataPage->LaunchData)] = {0};
  memset(launchData, 0xEA, 0x10);
  memset(launchData + 0x10, 0x42, 0x10);
  strcpy(reinterpret_cast<char *>(launchData + 0x20), "ERIK ABAIR");

  const int wait_seconds = 2;
  DbgPrint("Waiting %d seconds and launching sub_process.xbe", wait_seconds);
  Sleep(wait_seconds * 1000);

  DbgPrint("Launching subprocess '%s'", targetPath);

  XLaunchXBEEx(targetPath, launchData);

  DbgPrint("Launching failed!");

  return 0;
}
