#include <SDL.h>
#include <hal/video.h>
#include <hal/xbox.h>
#include <windows.h>
#include <xboxkrnl/xboxkrnl.h>

#include <cassert>
#include <cstring>

static void PrintLaunchInfo(PLAUNCH_DATA_PAGE launch_info) {
  DbgPrint("Launch info addr: 0x%X", launch_info);
  //  DWORD launchDataType = LaunchDataPage->Header.dwLaunchDataType;
  //  DbgPrint("Launch data type: 0x%X", launchDataType);
}

int main() {
  XVideoSetMode(640, 480, 32, REFRESH_DEFAULT);

  VIDEO_MODE xmode = XVideoGetMode();
  SDL_Window *window = SDL_CreateWindow("Subprocess", SDL_WINDOWPOS_UNDEFINED,
                                        SDL_WINDOWPOS_UNDEFINED, xmode.width,
                                        xmode.height, SDL_WINDOW_SHOWN);
  if (window == nullptr) {
    return 1;
  }

  SDL_Renderer *renderer = SDL_CreateRenderer(window, -1, 0);
  if (renderer == nullptr) {
    return 2;
  }

  SDL_SetRenderDrawBlendMode(renderer, SDL_BLENDMODE_BLEND);
  SDL_SetRenderDrawColor(renderer, 0x3F, 0x00, 0x3F, 0xFF);
  SDL_RenderClear(renderer);
  SDL_RenderPresent(renderer);

  DbgPrint("LaunchDataPage: 0x%X", LaunchDataPage);
  if (LaunchDataPage == NULL) {
    DbgPrint("Allocating launch data page");
    LaunchDataPage =
        static_cast<PLAUNCH_DATA_PAGE>(MmAllocateContiguousMemory(0x1000));
  }
  PrintLaunchInfo(LaunchDataPage);

  DbgPrint("Sleeping and rebooting.");
  Sleep(10 * 1000);
  XReboot();

  return 0;
}
