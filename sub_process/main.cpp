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
  //  DWORD launchDataType = LaunchDataPage->Header.dwLaunchDataType;
  //  DbgPrint("Launch data type: 0x%X", launchDataType);
}

static PIMAGE_EXPORT_DIRECTORY find_edataxb(void) {
  DWORD num_sections = CURRENT_XBE_HEADER->NumberOfSections;
  PXBE_SECTION_HEADER section_header_addr =
      CURRENT_XBE_HEADER->PointerToSectionTable;

  for (DWORD i = 0; i < num_sections; i++) {
    if (memcmp(section_header_addr[i].SectionName, ".edataxb", 8) == 0) {
      return (PIMAGE_EXPORT_DIRECTORY)section_header_addr[i].VirtualAddress;
    }
  }

  return NULL;
}

static void *find_sticky_section(PIMAGE_SECTION_HEADER sticky_header) {
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
    if (!memcmp(kernel_sections[i].Name, "STICKY", 6)) {
      DbgPrint("FOUND STICKY SECTION!");
      const char *sticky_addr = (const char *)pe_header->OptionalHeader.ImageBase + kernel_sections[i].VirtualAddress;
      DbgPrint("Section content at %p", sticky_addr);
      memcpy(sticky_header, &kernel_sections[i], sizeof(*sticky_header));
      return (void *)sticky_addr;
    }
  }

  return NULL;
}

static void dump_mem(unsigned char *addr, DWORD len, std::string &out) {
  char buf[4] = {0};
  out.clear();

  for (DWORD i = 0; i < len; ++i) {
    sprintf(buf, "%2.2x", (unsigned char)addr[i]);
    out += buf;
  }
}


int main() {
  IMAGE_SECTION_HEADER sticky_section_header;
  void *sticky_section = find_sticky_section(&sticky_section_header);
  DbgPrint("LaunchDataPage: 0x%X", LaunchDataPage);

  XVideoSetMode(640, 480, 32, REFRESH_DEFAULT);

  BOOL pbk_started = pb_init() == 0;
  if (!pbk_started) {
    DbgPrint("pbkit init failed\n");
    return 1;
  }
  pb_show_front_screen();

  while (1) {
    pb_wait_for_vbl();
    pb_target_back_buffer();
    pb_reset();
    pb_fill(0, 0, 640, 480, 0xFF3E003E);
    pb_erase_text_screen();

    pb_print("STICKY at %p\n", sticky_section);
    pb_print("STICKY SIZE %d\n", sticky_section_header.SizeOfRawData);
    pb_print("LaunchDataPage at %p\n", LaunchDataPage);

    PLAUNCH_DATA_PAGE ld = (PLAUNCH_DATA_PAGE)&LaunchDataPage;
    pb_print("Address of LaunchDataPage: %p\n", ld);

    std::string buf;
    for (int i = 0; i < 4; ++i) {
      dump_mem((unsigned char *)LaunchDataPage->LaunchData + (16 * i), 16, buf);
      pb_print("%s\n", buf.c_str());
    }

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

  return 0;
}
