/**
 * @file helpers.cpp
 * @brief 凭据提供程序辅助函数实现。
 *
 * 本文件包含了用于处理 Windows 登录凭据包的关键逻辑。
 * 核心功能包括：
 * 1. 内存管理（COM 内存与普通堆内存）。
 * 2. 凭据打包（将指针结构转换为偏移量结构，用于跨进程传递给 LSASS）。
 * 3. 安全处理（密码加密与内存抹除）。
 * 4. 身份验证包交互（与 LSA 系统连接）。
 */

#include "helpers.h"
#include <intsafe.h>
#include <wincred.h>
#include <windows.h>
#include <lm.h>
#include <sddl.h>

void WriteLog(const std::wstring& message)
{
    // 使用简单的 C 风格文件操作，兼容性最强
    // 写入到 C:\Windows\Temp，因为 LogonUI (SYSTEM权限) 肯定有权写这里
    FILE* fp = nullptr;
    if (_wfopen_s(&fp, L"C:\\Windows\\Temp\\CP_Debug.log", L"a+, ccs=UTF-16LE") == 0)
    {
        fwprintf(fp, L"%ls\n", message.c_str());
        fclose(fp);
    }
    OutputDebugStringW((L"[SampleCP] " + message + L"\n").c_str());
}

// 获取系统中所有正常用户的 [用户名 -> SID] 映射
std::map<std::wstring, std::wstring> GetLocalUserSidMap()
{
    std::map<std::wstring, std::wstring> userMap;
    USER_INFO_0*                         pBuf           = NULL;
    DWORD                                dwEntriesRead  = 0;
    DWORD                                dwTotalEntries = 0;

    // 1. 枚举本地普通用户
    NET_API_STATUS nStatus = NetUserEnum(NULL,
                                         0,
                                         FILTER_NORMAL_ACCOUNT,
                                         (LPBYTE*)&pBuf,
                                         MAX_PREFERRED_LENGTH,
                                         &dwEntriesRead,
                                         &dwTotalEntries,
                                         NULL);

    if (nStatus == NERR_Success)
    {
        for (DWORD i = 0; i < dwEntriesRead; i++)
        {
            std::wstring username = pBuf[i].usri0_name;

            // 跳过一些系统内置的特殊账户（可选，根据需要增加）
            if (username == L"WDAGUtilityAccount")
                continue;

            // 2. 根据用户名查询 SID
            DWORD        cbSid    = 0;
            DWORD        cbDomain = 0;
            SID_NAME_USE snu;
            LookupAccountNameW(NULL, username.c_str(), NULL, &cbSid, NULL, &cbDomain, &snu);

            if (cbSid > 0)
            {
                PSID   pSid     = (PSID)malloc(cbSid);
                LPWSTR szDomain = (LPWSTR)malloc(cbDomain * sizeof(WCHAR));

                if (LookupAccountNameW(
                        NULL, username.c_str(), pSid, &cbSid, szDomain, &cbDomain, &snu))
                {
                    LPWSTR szStringSid = NULL;
                    // 3. 将二进制 SID 转换为字符串格式
                    if (ConvertSidToStringSidW(pSid, &szStringSid))
                    {
                        userMap[username] = szStringSid;
                        LocalFree(szStringSid);
                    }
                }
                free(pSid);
                free(szDomain);
            }
        }
        NetApiBufferFree(pBuf);
    }

    // 过滤掉系统自带用户
    userMap.erase(L"Administrator");
    userMap.erase(L"Guest");
    userMap.erase(L"DefaultAccount");
    return userMap;
}

// 专门负责把 std::wstring 转换为 Windows 需要的 COM 字符串
// 修改逻辑：传入指向指针的地址，内部申请内存
HRESULT AllocateComString(const std::wstring& str, PWSTR* ppout)
{
    if (ppout == nullptr)
        return E_POINTER;
    *ppout = nullptr;

    // 即使 str 为空，通常也建议分配一个包含空终止符的内存块
    size_t charCount = str.length() + 1;
    size_t byteCount = charCount * sizeof(wchar_t);

    // 必须使用 CoTaskMemAlloc！！
    // 这样 Windows 收到后才能用 CoTaskMemFree 释放它
    PWSTR pDest = (PWSTR)CoTaskMemAlloc(byteCount);

    if (pDest == nullptr)
    {
        return E_OUTOFMEMORY;
    }

    // 安全拷贝
    wcscpy_s(pDest, charCount, str.c_str());

    // 将申请好的内存地址“交给”传进来的指针
    *ppout = pDest;

    return S_OK;
}

/**
 * @brief 深度拷贝一个字段描述符，并使用 CoTaskMemAlloc 分配内存。
 *
 * @details 凭据提供程序需要向 Windows 系统（LogonUI）提供 UI
 * 字段描述。由于这些描述 是跨 COM 接口传递的，因此必须使用 COM
 * 内存管理器分配内存，以确保系统能正确释放。
 *
 * @param[in]  rcpfd  源字段描述符结构体引用。
 * @param[out] ppcpfd 指向目标的指针的指针。成功时指向新分配的内存。
 *
 * @return HRESULT 成功返回 S_OK，内存不足返回 E_OUTOFMEMORY。
 */
HRESULT FieldDescriptorCoAllocCopy(__in const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR&   rcpfd,
                                   __deref_out CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd)
{
    HRESULT hr;
    DWORD   cbStruct = sizeof(**ppcpfd);  // 计算结构体本身的大小

    // 1. 分配结构体内存。必须用 CoTaskMemAlloc，因为这是给 Windows
    // 系统的接口使用的
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* pcpfd =
        (CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*)CoTaskMemAlloc(cbStruct);

    if (pcpfd)
    {
        // 2. 复制非指针型成员（ID 和 字段类型）
        pcpfd->dwFieldID = rcpfd.dwFieldID;
        pcpfd->cpft      = rcpfd.cpft;

        // 3. 处理标签字符串（如 "用户名:"）。字符串也必须是新分配的副本。
        if (rcpfd.pszLabel)
        {
            // SHStrDupW 内部会调用 CoTaskMemAlloc 分配内存并拷贝字符串
            hr = SHStrDupW(rcpfd.pszLabel, &pcpfd->pszLabel);
        }
        else
        {
            pcpfd->pszLabel = NULL;
            hr              = S_OK;
        }
    }
    else
    {
        hr = E_OUTOFMEMORY;
    }

    // 4. 如果中间步骤失败，清理已分配的内存，防止泄漏
    if (SUCCEEDED(hr))
    {
        *ppcpfd = pcpfd;
    }
    else
    {
        CoTaskMemFree(pcpfd);
        *ppcpfd = NULL;
    }

    return hr;
}

/**
 * @brief 拷贝字段描述符到预分配的缓冲区。
 *
 * @param[in]  rcpfd  源描述符。
 * @param[out] pcpfd  目标描述符指针（假设其结构体空间已由调用者分配）。
 *
 * @return HRESULT。
 */
HRESULT
FieldDescriptorCopy(__in const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR&  rcpfd,
                    __deref_out CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* pcpfd)
{
    HRESULT                              hr;
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR cpfd;

    cpfd.dwFieldID = rcpfd.dwFieldID;
    cpfd.cpft      = rcpfd.cpft;

    // 虽然结构体本身不是动态分配的，但其中的 pszLabel 必须是独立的副本
    if (rcpfd.pszLabel)
    {
        hr = SHStrDupW(rcpfd.pszLabel, &cpfd.pszLabel);
    }
    else
    {
        cpfd.pszLabel = NULL;
        hr            = S_OK;
    }

    if (SUCCEEDED(hr))
    {
        *pcpfd = cpfd;
    }

    return hr;
}

/**
 * @brief 初始化 UNICODE_STRING 结构体。
 *
 * @details 这是一个受限的辅助函数，主要用于序列化。它执行**浅拷贝**。
 * 它不分配内存，只是让 UNICODE_STRING 指向 pwz。
 *
 * @param[in]  pwz 原始宽字符串。
 * @param[out] pus 初始化的 UNICODE_STRING 结构。
 *
 * @return HRESULT。
 */
HRESULT UnicodeStringInitWithString(__in PWSTR pwz, __deref_out UNICODE_STRING* pus)
{
    HRESULT hr;
    if (pwz)
    {
        size_t lenString = lstrlenW(pwz);  // 获取字符数
        USHORT usCharCount;

        // 1. 安全转换：检查字符数是否超过了 USHORT（UNICODE_STRING 的上限）
        hr = SizeTToUShort(lenString, &usCharCount);
        if (SUCCEEDED(hr))
        {
            USHORT usSize;
            hr = SizeTToUShort(sizeof(WCHAR), &usSize);
            if (SUCCEEDED(hr))
            {
                // 2. 计算字节长度。注意：UNICODE_STRING 的 Length 不包含 NULL 终止符。
                hr = UShortMult(usCharCount, usSize, &(pus->Length));
                if (SUCCEEDED(hr))
                {
                    // 3. 设置 Buffer。只是弱引用，指向原内存。
                    pus->MaximumLength = pus->Length;
                    pus->Buffer        = pwz;
                    hr                 = S_OK;
                }
                else
                {
                    hr = HRESULT_FROM_WIN32(ERROR_ARITHMETIC_OVERFLOW);  // 算术溢出
                }
            }
        }
    }
    else
    {
        hr = E_INVALIDARG;
    }
    return hr;
}

/**
 * @brief 将 UNICODE_STRING 的数据拷贝到指定的打包缓冲区中。
 *
 * @param[in]  rus       源 UNICODE_STRING（包含真实地址指针）。
 * @param[in]  pwzBuffer 打包缓冲区中的目标物理地址。
 * @param[out] pus       目标 UNICODE_STRING。
 */
static void _UnicodeStringPackedUnicodeStringCopy(__in const UNICODE_STRING& rus,
                                                  __in PWSTR pwzBuffer, __out UNICODE_STRING* pus)
{
    pus->Length        = rus.Length;
    pus->MaximumLength = rus.Length;
    pus->Buffer        = pwzBuffer;  // 此时还是真实地址

    // 物理拷贝字符串内容
    CopyMemory(pus->Buffer, rus.Buffer, pus->Length);
}

/**
 * @brief 初始化用于 Kerberos 身份验证的结构体。
 *
 * @details 准备一个 KERB_INTERACTIVE_UNLOCK_LOGON 结构，它是 Windows
 * 标准的登录凭据载体。
 *
 * @param[in]  pwzDomain   域名。
 * @param[in]  pwzUsername 用户名。
 * @param[in]  pwzPassword 密码（可能是已加密的）。
 * @param[in]  cpus        当前场景（登录、解锁或 CredUI）。
 * @param[out] pkiul       返回初始化好的结构。
 */
HRESULT
KerbInteractiveUnlockLogonInit(__in PWSTR pwzDomain, __in PWSTR pwzUsername, __in PWSTR pwzPassword,
                               __in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
                               __out KERB_INTERACTIVE_UNLOCK_LOGON*    pkiul)
{
    KERB_INTERACTIVE_UNLOCK_LOGON kiul;
    ZeroMemory(&kiul, sizeof(kiul));

    KERB_INTERACTIVE_LOGON* pkil = &kiul.Logon;

    // 1. 分别初始化域名、用户名和密码的描述符（弱引用）
    HRESULT hr = UnicodeStringInitWithString(pwzDomain, &pkil->LogonDomainName);
    if (SUCCEEDED(hr))
    {
        hr = UnicodeStringInitWithString(pwzUsername, &pkil->UserName);
        if (SUCCEEDED(hr))
        {
            hr = UnicodeStringInitWithString(pwzPassword, &pkil->Password);
            if (SUCCEEDED(hr))
            {
                // 2. 根据场景选择 MessageType。这是告诉 LSA
                // 该执行登录还是解锁操作的核心标志。
                switch (cpus)
                {
                case CPUS_UNLOCK_WORKSTATION:
                    pkil->MessageType = KerbWorkstationUnlockLogon;
                    hr                = S_OK;
                    break;

                case CPUS_LOGON:
                    pkil->MessageType = KerbInteractiveLogon;
                    hr                = S_OK;
                    break;

                case CPUS_CREDUI:
                    pkil->MessageType = (KERB_LOGON_SUBMIT_TYPE)0;  // CredUI 不需要消息类型
                    hr                = S_OK;
                    break;

                default:
                    hr = E_FAIL;
                    break;
                }

                if (SUCCEEDED(hr))
                {
                    // 3. 执行结构体内存拷贝
                    CopyMemory(pkiul, &kiul, sizeof(*pkiul));
                }
            }
        }
    }

    return hr;
}

/**
 * @brief 将凭据结构体打包成二进制流（序列化）。
 *
 * @details
 * **重要原理：** LSASS 进程无法直接访问 LogonUI 进程的内存。
 * 因此，结构体中的 `Buffer`
 * 指针不能存放真实地址，必须改为“相对于结构体起始位置的偏移量”。
 *
 * @param[in]  rkiulIn 已经填充好真实字符串指针的源结构。
 * @param[out] prgb    输出参数：新分配的连续二进制块地址。
 * @param[out] pcb     输出参数：二进制块的总字节数。
 */
HRESULT KerbInteractiveUnlockLogonPack(__in const KERB_INTERACTIVE_UNLOCK_LOGON& rkiulIn,
                                       __deref_out_bcount(*pcb) BYTE** prgb, __out DWORD* pcb)
{
    HRESULT                       hr;
    const KERB_INTERACTIVE_LOGON* pkilIn = &rkiulIn.Logon;

    // 1. 计算总大小：基础结构体大小 + 所有字符串数据的字节长度
    DWORD cb = sizeof(rkiulIn) + pkilIn->LogonDomainName.Length + pkilIn->UserName.Length +
               pkilIn->Password.Length;

    // 2. 分配整块连续内存
    KERB_INTERACTIVE_UNLOCK_LOGON* pkiulOut = (KERB_INTERACTIVE_UNLOCK_LOGON*)CoTaskMemAlloc(cb);

    if (pkiulOut)
    {
        ZeroMemory(&pkiulOut->LogonId, sizeof(pkiulOut->LogonId));

        // pbBuffer 指向结构体末尾之后，即存放字符串数据的开始位置
        BYTE*                   pbBuffer = (BYTE*)pkiulOut + sizeof(*pkiulOut);
        KERB_INTERACTIVE_LOGON* pkilOut  = &pkiulOut->Logon;

        pkilOut->MessageType = pkilIn->MessageType;

        // 3. 打包域名字符串
        _UnicodeStringPackedUnicodeStringCopy(
            pkilIn->LogonDomainName, (PWSTR)pbBuffer, &pkilOut->LogonDomainName);
        // 核心转换：将真实的内存地址改为“相对偏移量”
        pkilOut->LogonDomainName.Buffer = (PWSTR)(pbBuffer - (BYTE*)pkiulOut);
        pbBuffer += pkilOut->LogonDomainName.Length;

        // 4. 打包用户名
        _UnicodeStringPackedUnicodeStringCopy(
            pkilIn->UserName, (PWSTR)pbBuffer, &pkilOut->UserName);
        pkilOut->UserName.Buffer = (PWSTR)(pbBuffer - (BYTE*)pkiulOut);
        pbBuffer += pkilOut->UserName.Length;

        // 5. 打包密码
        _UnicodeStringPackedUnicodeStringCopy(
            pkilIn->Password, (PWSTR)pbBuffer, &pkilOut->Password);
        pkilOut->Password.Buffer = (PWSTR)(pbBuffer - (BYTE*)pkiulOut);

        *prgb = (BYTE*)pkiulOut;
        *pcb  = cb;

        hr = S_OK;
    }
    else
    {
        hr = E_OUTOFMEMORY;
    }

    return hr;
}

/**
 * @brief 为 LSA 交互初始化 ANSI 字符串结构体。
 */
static HRESULT _LsaInitString(__out PSTRING pszDestinationString, __in PCSTR pszSourceString)
{
    size_t  cchLength = lstrlenA(pszSourceString);
    USHORT  usLength;
    HRESULT hr = SizeTToUShort(cchLength, &usLength);
    if (SUCCEEDED(hr))
    {
        pszDestinationString->Buffer        = (PCHAR)pszSourceString;
        pszDestinationString->Length        = usLength;
        pszDestinationString->MaximumLength = pszDestinationString->Length + 1;
        hr                                  = S_OK;
    }
    return hr;
}

/**
 * @brief 从 LSA 获取“Negotiate”身份验证包的 ID。
 *
 * @details Negotiate 包是 Windows 的混合验证包，会自动在 Kerberos 和 NTLM
 * 之间切换。
 */
HRESULT RetrieveNegotiateAuthPackage(__out ULONG* pulAuthPackage)
{
    HRESULT hr;
    HANDLE  hLsa;

    // 1. 建立 LSA 连接（非受信任模式即可）
    NTSTATUS status = LsaConnectUntrusted(&hLsa);
    if (SUCCEEDED(HRESULT_FROM_NT(status)))
    {
        ULONG      ulAuthPackage;
        LSA_STRING lsaszKerberosName;
        // 初始化包名称字符串为 "Negotiate"
        _LsaInitString(&lsaszKerberosName, NEGOSSP_NAME_A);

        // 2. 查找包的内部 ID
        status = LsaLookupAuthenticationPackage(hLsa, &lsaszKerberosName, &ulAuthPackage);
        if (SUCCEEDED(HRESULT_FROM_NT(status)))
        {
            *pulAuthPackage = ulAuthPackage;
            hr              = S_OK;
        }
        else
        {
            hr = HRESULT_FROM_NT(status);
        }
        LsaDeregisterLogonProcess(hLsa);
    }
    else
    {
        hr = HRESULT_FROM_NT(status);
    }

    return hr;
}

/**
 * @brief 使用 CredProtect API 加密密码字符串。
 *
 * @details
 * 为了防止内存中存在明文密码，必须使用 DPAPI 级别的保护。
 * 加密后的数据只有 LSASS 进程（作为本地系统环境）能解密。
 *
 * @param[in]  pwzToProtect  明文密码。
 * @param[out] ppwzProtected 加密后的结果副本。
 */
static HRESULT _ProtectAndCopyString(__in PCWSTR pwzToProtect, __deref_out PWSTR* ppwzProtected)
{
    *ppwzProtected = NULL;

    PWSTR pwzToProtectCopy;
    // SHStrDupW 必须先生成一个非 const 的缓冲区，因为 CredProtect
    // 可能在原位置操作或计算
    HRESULT hr = SHStrDupW(pwzToProtect, &pwzToProtectCopy);
    if (SUCCEEDED(hr))
    {
        DWORD cchProtected = 0;
        // 1. 第一次调用：查询加密后所需的缓冲区大小。传 NULL 触发错误获取大小。
        if (!CredProtectW(FALSE,
                          pwzToProtectCopy,
                          (DWORD)wcslen(pwzToProtectCopy) + 1,
                          NULL,
                          &cchProtected,
                          NULL))
        {
            DWORD dwErr = GetLastError();

            if ((ERROR_INSUFFICIENT_BUFFER == dwErr) && (0 < cchProtected))
            {
                // 2. 分配加密后的内存
                PWSTR pwzProtected = (PWSTR)CoTaskMemAlloc(cchProtected * sizeof(WCHAR));
                if (pwzProtected)
                {
                    // 3. 第二次调用：执行真正的加密操作
                    if (CredProtectW(FALSE,
                                     pwzToProtectCopy,
                                     (DWORD)wcslen(pwzToProtectCopy) + 1,
                                     pwzProtected,
                                     &cchProtected,
                                     NULL))
                    {
                        *ppwzProtected = pwzProtected;
                        hr             = S_OK;
                    }
                    else
                    {
                        CoTaskMemFree(pwzProtected);
                        hr = HRESULT_FROM_WIN32(GetLastError());
                    }
                }
                else
                {
                    hr = E_OUTOFMEMORY;
                }
            }
            else
            {
                hr = HRESULT_FROM_WIN32(dwErr);
            }
        }
        CoTaskMemFree(pwzToProtectCopy);
    }

    return hr;
}

/**
 * @brief 决定是否需要对密码进行加密并生成拷贝。
 *
 * @details
 * - CPUS_CREDUI（应用提权弹窗）场景不加密，因为调用者可能不理解加密。
 * - 登录/解锁场景如果密码尚未加密，则必须加密。
 */
HRESULT
ProtectIfNecessaryAndCopyPassword(__in PCWSTR                             pwzPassword,
                                  __in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
                                  __deref_out PWSTR*                      ppwzProtectedPassword)
{
    *ppwzProtectedPassword = NULL;
    HRESULT hr;

    if (pwzPassword && *pwzPassword)
    {
        PWSTR pwzPasswordCopy;
        hr = SHStrDupW(pwzPassword, &pwzPasswordCopy);
        if (SUCCEEDED(hr))
        {
            bool                 bCredAlreadyEncrypted = false;
            CRED_PROTECTION_TYPE protectionType;

            // 1. 检查密码是否已经是加密状态（可能来自 RDP 或之前的序列化）
            if (CredIsProtectedW(pwzPasswordCopy, &protectionType))
            {
                if (CredUnprotected != protectionType)
                {
                    bCredAlreadyEncrypted = true;
                }
            }

            // 2. 逻辑判断：CredUI 或者 已经加密过，就不再重复加密
            if (CPUS_CREDUI == cpus || bCredAlreadyEncrypted)
            {
                hr = SHStrDupW(pwzPasswordCopy, ppwzProtectedPassword);
            }
            else
            {
                // 否则进行 DPAPI 加密
                hr = _ProtectAndCopyString(pwzPasswordCopy, ppwzProtectedPassword);
            }

            CoTaskMemFree(pwzPasswordCopy);
        }
    }
    else
    {
        // 空密码直接拷贝
        hr = SHStrDupW(L"", ppwzProtectedPassword);
    }

    return hr;
}

/**
 * @brief 原位解包：将二进制块中的“偏移量”重新转换回“真实地址指针”。
 *
 * @details
 * 仅用于本地解析已经序列化的缓冲区。注意这会使该结构体无法再次跨进程发送。
 */
void KerbInteractiveUnlockLogonUnpackInPlace(__inout_bcount(cb)
                                                 KERB_INTERACTIVE_UNLOCK_LOGON* pkiul,
                                             __in DWORD                         cb)
{
    if (sizeof(*pkiul) <= cb)
    {
        KERB_INTERACTIVE_LOGON* pkil = &pkiul->Logon;

        // 安全检查：防止恶意的缓冲区溢出攻击（检查偏移量是否超出总长度）
        if (((ULONG_PTR)pkil->LogonDomainName.Buffer + pkil->LogonDomainName.MaximumLength <= cb) &&
            ((ULONG_PTR)pkil->UserName.Buffer + pkil->UserName.MaximumLength <= cb) &&
            ((ULONG_PTR)pkil->Password.Buffer + pkil->Password.MaximumLength <= cb))
        {

            // 指针 = 结构体基地址 + 缓冲区中存储的偏移量
            pkil->LogonDomainName.Buffer =
                pkil->LogonDomainName.Buffer
                    ? (PWSTR)((BYTE*)pkiul + (ULONG_PTR)pkil->LogonDomainName.Buffer)
                    : NULL;

            pkil->UserName.Buffer = pkil->UserName.Buffer
                                        ? (PWSTR)((BYTE*)pkiul + (ULONG_PTR)pkil->UserName.Buffer)
                                        : NULL;

            pkil->Password.Buffer = pkil->Password.Buffer
                                        ? (PWSTR)((BYTE*)pkiul + (ULONG_PTR)pkil->Password.Buffer)
                                        : NULL;
        }
    }
}

/**
 * @brief WOW64 兼容性处理。将 32 位凭据重新打包为 64 位。
 *
 * @details 当 32 位进程试图在 64
 * 位系统上通过凭据提供程序登录时，数据结构对齐会出错。 此函数利用系统提供的
 * CredPack/Unpack API 来抹除架构差异。
 */
HRESULT KerbInteractiveUnlockLogonRepackNative(__in_bcount(cbWow) BYTE* rgbWow, __in DWORD cbWow,
                                               __deref_out_bcount(*pcbNative) BYTE** prgbNative,
                                               __out DWORD*                          pcbNative)
{
    HRESULT hr                = E_OUTOFMEMORY;
    PWSTR   pszDomainUsername = NULL;
    DWORD   cchDomainUsername = 0;
    PWSTR   pszPassword       = NULL;
    DWORD   cchPassword       = 0;

    *prgbNative = NULL;
    *pcbNative  = 0;

    // 1. 解包 32 位（WOW）结构体，获取明文数据
    CredUnPackAuthenticationBufferW(CRED_PACK_WOW_BUFFER,
                                    rgbWow,
                                    cbWow,
                                    pszDomainUsername,
                                    &cchDomainUsername,
                                    NULL,
                                    NULL,
                                    pszPassword,
                                    &cchPassword);
    if (ERROR_INSUFFICIENT_BUFFER == GetLastError())
    {
        pszDomainUsername = (PWSTR)LocalAlloc(0, cchDomainUsername * sizeof(WCHAR));
        if (pszDomainUsername)
        {
            pszPassword = (PWSTR)LocalAlloc(0, cchPassword * sizeof(WCHAR));
            if (pszPassword)
            {
                if (CredUnPackAuthenticationBufferW(CRED_PACK_WOW_BUFFER,
                                                    rgbWow,
                                                    cbWow,
                                                    pszDomainUsername,
                                                    &cchDomainUsername,
                                                    NULL,
                                                    NULL,
                                                    pszPassword,
                                                    &cchPassword))
                {
                    hr = S_OK;
                }
                else
                {
                    hr = GetLastError();
                }
            }
        }
    }

    // 2. 将明文数据以“原生（Native）”即 64 位格式重新打包
    if (SUCCEEDED(hr))
    {
        hr = E_OUTOFMEMORY;
        CredPackAuthenticationBufferW(0, pszDomainUsername, pszPassword, *prgbNative, pcbNative);
        if (ERROR_INSUFFICIENT_BUFFER == GetLastError())
        {
            *prgbNative = (BYTE*)LocalAlloc(LMEM_ZEROINIT, *pcbNative);
            if (*prgbNative)
            {
                if (CredPackAuthenticationBufferW(
                        0, pszDomainUsername, pszPassword, *prgbNative, pcbNative))
                {
                    hr = S_OK;
                }
                else
                {
                    LocalFree(*prgbNative);
                }
            }
        }
    }

    // 3. 安全清理：解包过程中产生的临时密码必须从内存抹除
    LocalFree(pszDomainUsername);
    if (pszPassword)
    {
        SecureZeroMemory(pszPassword, cchPassword * sizeof(WCHAR));  // 抹除敏感信息
        LocalFree(pszPassword);
    }
    return hr;
}

/**
 * @brief 拼接域名和用户名，生成 "DOMAIN\Username" 格式。
 *
 * @param[in]  pwszDomain   域名。
 * @param[in]  pwszUsername 用户名。
 * @param[out] ppwszDomainUsername 分配并返回拼接后的字符串。
 *
 * @return HRESULT。
 */
HRESULT DomainUsernameStringAlloc(__in PCWSTR pwszDomain, __in PCWSTR pwszUsername,
                                  __deref_out PWSTR* ppwszDomainUsername)
{
    HRESULT hr;
    size_t  cchDomain   = lstrlenW(pwszDomain);
    size_t  cchUsername = lstrlenW(pwszUsername);

    // 长度计算：域名 + 1('\') + 用户名 + 1(NULL)
    size_t cbLen = sizeof(WCHAR) * (cchDomain + 1 + cchUsername + 1);

    // 使用当前进程堆分配
    PWSTR pwszDest = (PWSTR)HeapAlloc(GetProcessHeap(), 0, cbLen);
    if (pwszDest)
    {
        // 安全格式化，防止溢出
        hr = StringCbPrintfW(pwszDest, cbLen, L"%s\\%s", pwszDomain, pwszUsername);
        if (SUCCEEDED(hr))
        {
            *ppwszDomainUsername = pwszDest;
        }
        else
        {
            HeapFree(GetProcessHeap(), 0, pwszDest);
        }
    }
    else
    {
        hr = E_OUTOFMEMORY;
    }

    return hr;
}