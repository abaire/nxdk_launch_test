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

int main() {
  PLAUNCH_DATA_PAGE ld = (PLAUNCH_DATA_PAGE)&LaunchDataPage;
  DbgPrint("Address of LaunchDataPage: %p", ld);
  DbgPrint("Value of LaunchDataPage: %p", LaunchDataPage);

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

  // Seems like failing to explicitly kill before the launch causes a hangup
  // sometimes.
  pb_kill();

  // Fails.
//  CHAR targetPath[MAX_PATH] = R"(D:\sub_process.xbe)";

  // Works.
//  CHAR targetPath[MAX_PATH] = R"(\Device\CdRom0\sub_process.xbe)";
  // Works.
  CHAR targetPath[MAX_PATH] = R"(sub_process.xbe)";

  // Works.
//  CHAR targetPath[MAX_PATH] = R"(e:\DEVKIT\boxplorer\default.xbe)";

#if 1
  UCHAR launchData[sizeof(LaunchDataPage->LaunchData)] = {0};
  memset(launchData, 0xEA, 0x10);
  memset(launchData + 0x10, 0x42, 0x10);
  strcpy(reinterpret_cast<char *>(launchData + 0x20), "TEST LAUNCHER");

  DbgPrint("Launching subprocess '%s'", targetPath);
  XLaunchXBEEx(targetPath, launchData);
#else
  // Works, launches the dashboard.
  XLaunchXBE(nullptr);
#endif
  DbgPrint("Launching failed!");

  return 0;
}
