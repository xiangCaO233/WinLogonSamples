#include <Windows.h>
#include <sspi.h>
#include "PrepareProfile.hpp"
#include "Utils.hpp"

static LARGE_INTEGER InfiniteFuture()
{
    LARGE_INTEGER val;
    val.LowPart  = 0xFFFFFFFF;
    val.HighPart = 0x7FFFFFFF;
    return val;
}

static LARGE_INTEGER CurrentTime()
{
    FILETIME time{};
    GetSystemTimeAsFileTime(&time);
    LARGE_INTEGER ret;
    ret.LowPart  = time.dwLowDateTime;
    ret.HighPart = (LONG)time.dwHighDateTime;
    return ret;
}

// 转换wstring逻辑
static std::wstring ToWString(const UNICODE_STRING& uniStr)
{
    if (uniStr.Buffer == nullptr || uniStr.Length == 0)
    {
        return L"";
    }

    // Length 是字节数，wchar_t 通常是 2 字节，所以字符数 = Length / 2
    // 直接使用 (wchar_t*) 强转，因为 UNICODE_STRING 的 Buffer 本质上就是 PWSTR (wchar_t*)
    size_t charCount = uniStr.Length / sizeof(wchar_t);

    return std::wstring(uniStr.Buffer, charCount);
}

ULONG GetProfileBufferSize(const std::wstring&             computername,
                           const MSV1_0_INTERACTIVE_LOGON& logonInfo)
{
    return sizeof(MSV1_0_INTERACTIVE_PROFILE) + logonInfo.UserName.Length +
           (ULONG)(2 * computername.size());
}

std::vector<BYTE> PrepareProfileBuffer(const std::wstring&             computername,
                                       const MSV1_0_INTERACTIVE_LOGON& logonInfo,
                                       BYTE*                           hostProfileAddress)
{
    std::vector<BYTE> profileBuffer(GetProfileBufferSize(computername, logonInfo), (BYTE)0);
    auto*             profile = (MSV1_0_INTERACTIVE_PROFILE*)profileBuffer.data();
    size_t            offset  = sizeof(MSV1_0_INTERACTIVE_PROFILE);  // offset to string parameters

    profile->MessageType              = MsV1_0InteractiveProfile;
    profile->LogonCount               = 0;  // unknown
    profile->BadPasswordCount         = 0;
    profile->LogonTime                = CurrentTime();
    profile->LogoffTime               = InfiniteFuture();  // logoff reminder
    profile->KickOffTime              = InfiniteFuture();  // forced logoff
    profile->PasswordLastSet.QuadPart = 0;                 // 1. January 1601
    profile->PasswordCanChange        = InfiniteFuture();  // password change reminder
    profile->PasswordMustChange       = InfiniteFuture();  // password change required
    profile->LogonScript;                                  // observed to be empty
    profile->HomeDirectory;                                // observed to be empty
    {
        // set "UserName"
        memcpy(/*dst*/ profileBuffer.data() + offset,
               /*src*/ logonInfo.UserName.Buffer,
               logonInfo.UserName.MaximumLength);

        LSA_UNICODE_STRING tmp;
        tmp.Length        = logonInfo.UserName.Length;
        tmp.MaximumLength = logonInfo.UserName.MaximumLength;
        tmp.Buffer        = (wchar_t*)(hostProfileAddress + offset);
        profile->FullName = tmp;

        offset += profile->FullName.MaximumLength;
    }
    profile->ProfilePath;         // observed to be empty
    profile->HomeDirectoryDrive;  // observed to be empty
    {
        // set "LogonServer"
        memcpy(/*dst*/ profileBuffer.data() + offset,
               /*src*/ computername.data(),
               computername.size());

        LSA_UNICODE_STRING tmp;
        tmp.Length        = (USHORT)(2 * computername.size());
        tmp.MaximumLength = (USHORT)(2 * computername.size());
        tmp.Buffer        = (wchar_t*)(hostProfileAddress + offset);

        profile->LogonServer = tmp;

        offset += profile->LogonServer.MaximumLength;
    }
    profile->UserFlags = 0;

    return profileBuffer;
}
