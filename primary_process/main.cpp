#include <hal/video.h>
#include <hal/xbox.h>
#include <nxdk/mount.h>
#include <nxdk/path.h>
#include <xboxkrnl/xboxkrnl.h>
#include <windows.h>

#include <cassert>
#include <cstring>

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

static void PrintLaunchInfo(PLAUNCH_DATA_PAGE launch_info) {
  DbgPrint("Launch info addr: 0x%X", launch_info);
  //  DWORD launchDataType = LaunchDataPage->Header.dwLaunchDataType;
//  DbgPrint("Launch data type: 0x%X", launchDataType);

}

int main() {
  void *test = (void *)0x80000000;
  PrintLaunchInfo(static_cast<PLAUNCH_DATA_PAGE>(test));
  DbgPrint("LaunchDataPage: 0x%X", LaunchDataPage);
  if (LaunchDataPage == NULL) {
    LaunchDataPage = static_cast<PLAUNCH_DATA_PAGE>(MmAllocateContiguousMemory(0x1000));
  }
  PrintLaunchInfo(LaunchDataPage);

  // XLaunchXBE("")

  XVideoSetMode(640, 480, 32, REFRESH_DEFAULT);

  if (!mount_drives()) {
    return ERROR_GEN_FAILURE;
  }

  Sleep(10 * 1000);
  XReboot();

  return 0;
}
