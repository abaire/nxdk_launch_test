#include <hal/video.h>
#include <hal/xbox.h>
#include <nxdk/mount.h>
#include <nxdk/path.h>
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

static void PrintLaunchInfo(PLAUNCH_DATA_PAGE launch_info) {
  DbgPrint("Launch info addr is now: 0x%X", launch_info);
  //  DWORD launchDataType = LaunchDataPage->Header.dwLaunchDataType;
  //  DbgPrint("Launch data type: 0x%X", launchDataType);
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

  DbgPrint("Loading sticky section.");
  UCHAR foo[1024] = "STICKY";
  XBEIMAGE_SECTION sticky_section;
  memset(&sticky_section, 0, sizeof(sticky_section));
  sticky_section.SectionName = foo;
  XeLoadSection(&sticky_section);

//  DbgPrint("LaunchDataPage: 0x%X", LaunchDataPage);
//  if (LaunchDataPage == NULL) {
//    LaunchDataPage =
//        static_cast<PLAUNCH_DATA_PAGE>(MmAllocateContiguousMemory(0x1000));
//  }
//  PrintLaunchInfo(LaunchDataPage);

//  XVideoSetMode(640, 480, 32, REFRESH_DEFAULT);
//  if (!mount_drives()) {
//    return ERROR_GEN_FAILURE;
//  }
//
//  ListADir();

  CHAR targetPath[MAX_PATH];
//  nxGetCurrentXbeNtPath(targetPath);
//  CHAR *last_slash = std::strrchr(targetPath, '\\');
//  strcpy(last_slash + 1, R"(sub_process.xbe)");
  strcpy(targetPath, "C:\\evoxdash.xbe");

  DbgPrint("Launching subprocess '%s'", targetPath);
//  memset(LaunchDataPage->LaunchData, 0xEA, 0x100);
//  memset(LaunchDataPage->LaunchData + 0x100, 0x42, 0x10);
  XLaunchXBE(targetPath);

  DbgPrint("Launching failed!");

  return 0;
}
