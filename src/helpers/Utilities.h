#include <string>
#include <windows.h>

namespace utils
{
PWSTR AllocateComString(const std::wstring& str);
}
