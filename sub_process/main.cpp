#include <SDL.h>
#include <hal/video.h>
#include <hal/xbox.h>
#include <pbkit/pbkit.h>
#include <windows.h>
#include <xboxkrnl/xboxkrnl.h>

#include <cassert>
#include <cstring>
#include <string>

static void PrintLaunchInfo(const PLAUNCH_DATA_PAGE launch_info) {
  DbgPrint("Launch info addr is now: 0x%X", launch_info);

  const LAUNCH_DATA_HEADER &header = launch_info->Header;
  DbgPrint("Launch Data Type: 0x%X", header.dwLaunchDataType);
  DbgPrint("Flags: 0x%X", header.dwFlags);
  DbgPrint("TitleID: 0x%X", header.dwTitleId);
  DbgPrint("Launch Path: %s", header.szLaunchPath);

  DbgPrint("Data: %x", *(DWORD *)launch_info->LaunchData);
}

static void dump_mem(const unsigned char *addr, DWORD len, std::string &out_mem,
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

int main() {
  DbgPrint("LaunchDataPage: 0x%X", LaunchDataPage);
  DWORD launch_data_type;
  const BYTE *launch_data;
  XGetLaunchInfo(&launch_data_type, &launch_data);

  XVideoSetMode(640, 480, 32, REFRESH_DEFAULT);

  BOOL pbk_started = pb_init() == 0;
  if (!pbk_started) {
    DbgPrint("pbkit init failed\n");
    return 1;
  }
  pb_show_front_screen();

  const int target_frames = 60 * 60;
  for (int frame = 0; frame < target_frames; ++frame) {
    pb_wait_for_vbl();
    pb_target_back_buffer();
    pb_reset();
    pb_fill(0, 0, 640, 480, 0xFF3E003E);
    pb_erase_text_screen();

    pb_print("LaunchDataPage at %p\n", LaunchDataPage);
    pb_print("Launch type: %d\n", launch_data_type);
    pb_print("LaunchData at %p\n", launch_data);

    if (launch_data) {
      std::string buf;
      std::string _char_buf;
      const unsigned char *data = launch_data;
      for (int i = 0; i < 4; ++i, data += 16) {
        dump_mem(data, 16, buf, _char_buf);
        pb_print("%s\n", buf.c_str());
      }
    }

    pb_print("\n\nSleeping before rebooting\n");

    pb_draw_text_screen();
    while (pb_busy())
      ;
    while (pb_finished())
      ;
  }

  Sleep(1 * 60 * 1000);

  if (pbk_started) {
    pb_kill();
  }

  XReboot();

  return 0;
}
