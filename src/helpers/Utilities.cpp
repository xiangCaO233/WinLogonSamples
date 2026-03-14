#include "Utilities.h"

namespace utils
{
// 专门负责把 std::wstring 转换为 Windows 需要的 COM 字符串
PWSTR AllocateComString(const std::wstring& str)
{
    if (str.empty())
        return nullptr;
    size_t size = (str.length() + 1) * sizeof(wchar_t);
    PWSTR  p    = (PWSTR)CoTaskMemAlloc(size);
    if (p)
    {
        wcscpy_s(p, str.length() + 1, str.c_str());
    }
    return p;
}
}  // namespace utils