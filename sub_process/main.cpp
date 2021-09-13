#include <hal/video.h>
#include <hal/xbox.h>
#include <nxdk/mount.h>
#include <nxdk/path.h>
#include <xboxkrnl/xboxkrnl.h>
#include <windows.h>

#include <cassert>
#include <cstring>

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

  DbgPrint("Sleeping and rebooting.");
  Sleep(10 * 1000);
  XReboot();

  return 0;
}
