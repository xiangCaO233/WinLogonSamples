/**
 * @file helpers.h
 * @brief Windows 凭据提供程序 (Credential Provider) 辅助函数集合
 *
 * 本文件提供了一系列底层工具函数，用于处理内存分配、字符串转换以及
 * 将用户输入的凭据序列化为 LSA (Local Security Authority)
 * 能够理解的二进制格式。
 *
 * 在 Windows 登录架构中，凭据提供程序运行在 LogonUI.exe
 * 进程中，而真正的身份验证 是在 LSASS.exe 进程中通过调用身份验证包（如 Kerberos
 * 或 NTLM）完成的。 这些函数确保了数据在这两个进程间传递时的格式正确性。
 *
 * @copyright Copyright (c) Microsoft Corporation. All rights reserved.
 */

#pragma once
#include <credentialprovider.h>
#include <ntsecapi.h>
#define SECURITY_WIN32
#include <intsafe.h>
#include <security.h>

#include <strsafe.h>
#include <windows.h>

#pragma warning(push)
#pragma warning(disable : 4995)
#include <shlwapi.h>
#pragma warning(pop)

#include <map>
#include <string>

void WriteLog(const std::wstring& message);

std::map<std::wstring, std::wstring> GetLocalUserSidMap();

// 专门负责把 std::wstring 转换为 Windows 需要的 COM 字符串
HRESULT AllocateComString(const std::wstring& str, PWSTR* ppout);

/**
 * @brief 使用 CoTaskMemAlloc 分配内存并拷贝字段描述符。
 *
 * @details 凭据提供程序通过 ICredentialProvider::GetFieldDescriptorCount
 * 返回界面布局。 Windows 壳层要求这些描述符必须通过 COM 内存管理器
 * (CoTaskMemAlloc) 分配， 以便系统在读取完数据后能够使用 CoTaskMemFree
 * 安全地跨进程释放内存。
 *
 * @param[in]  rcpfd  源字段描述符结构体（引用）。
 * @param[out] ppcpfd
 * 指向目的描述符指针的指针。执行成功后，此处将存放新分配的内存地址。
 * @return HRESULT S_OK 表示成功，E_OUTOFMEMORY 表示内存不足。
 */
HRESULT FieldDescriptorCoAllocCopy(__in const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR&   rcpfd,
                                   __deref_out CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd);

/**
 * @brief 在本地堆上拷贝字段描述符。
 *
 * @details 与 CoAllocCopy 不同，此函数用于提供程序内部的逻辑处理，不涉及与系统
 * shell 的内存移交。
 *
 * @param[in]  rcpfd  源字段描述符。
 * @param[out] pcpfd  指向预先分配好的目的描述符结构体的指针。
 * @return HRESULT 状态码。
 */
HRESULT
FieldDescriptorCopy(__in const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR&  rcpfd,
                    __deref_out CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* pcpfd);

/**
 * @brief 将标准的空字符结尾字符串 (PWSTR) 转换为 NT 内核使用的 UNICODE_STRING
 * 结构。
 *
 * @details UNICODE_STRING 是 Windows 内核及安全子系统 (LSA)
 * 使用的标准字符串格式， 它不依赖于 NULL 终止符，而是通过 Length 和
 * MaximumLength 显式记录长度。
 * 这是为了提高安全性，防止因缺少终止符导致的缓冲区溢出。
 *
 * @param[in]  pwz  输入的以 NULL 结尾的 Unicode 字符串。
 * @param[out] pus  指向要初始化的 UNICODE_STRING 结构体的指针。
 * @return HRESULT 状态码。
 */
HRESULT UnicodeStringInitWithString(__in PWSTR pwz, __out UNICODE_STRING* pus);

/**
 * @brief 初始化 KERB_INTERACTIVE_UNLOCK_LOGON 结构体。
 *
 * @details 这是最重要的结构体之一，专门用于交互式登录或解锁工作站。
 * 此函数执行“浅拷贝”初始化：它设置 UNICODE_STRING 的 Buffer
 * 指针指向传入的字符串， 但并不分配新的内存。这种初始化通常是为随后的“Pack
 * (打包)”过程做准备。
 *
 * @param[in]  pwzDomain   域名字符串（可选）。
 * @param[in]  pwzUsername 用户名字符串。
 * @param[in]  pwzPassword 密码字符串。
 * @param[in]  cpus        凭据使用场景（如：登录、修改密码、解锁）。
 * @param[out] pkiul       指向要初始化的结构体的指针。
 * @return HRESULT 状态码。
 */
HRESULT
KerbInteractiveUnlockLogonInit(__in PWSTR pwzDomain, __in PWSTR pwzUsername, __in PWSTR pwzPassword,
                               __in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
                               __out KERB_INTERACTIVE_UNLOCK_LOGON*    pkiul);

/**
 * @brief 将凭据打包成系统预期的序列化缓冲区。
 *
 * @details 关键逻辑：
 * 1.
 * 测量总长度：计算结构体本身加上所有动态字符串（用户名、域名、密码）所需的总内存。
 * 2. 内存对齐：确保数据在内存中按照对齐规则排列。
 * 3. 偏移量转换：结构体内部的 UNICODE_STRING.Buffer 本来是内存指针，
 *    但在“打包”后，它会被修改为相对于缓冲区起始位置的“字节偏移量”。
 *
 * 这样做是因为 LSASS
 * 进程收到这块内存后，其地址空间与当前进程不同，直接传指针无效。
 *
 * @param[in]  rkiulIn  已经初始化好数据的输入结构体。
 * @param[out] prgb     指向输出字节缓冲区的指针。系统会通过 CoTaskMemAlloc
 * 分配这块空间。
 * @param[out] pcb      返回分配的缓冲区总字节数。
 * @return HRESULT 状态码。
 */
HRESULT KerbInteractiveUnlockLogonPack(__in const KERB_INTERACTIVE_UNLOCK_LOGON& rkiulIn,
                                       __deref_out_bcount(*pcb) BYTE** prgb, __out DWORD* pcb);

/**
 * @brief 获取执行身份验证所需的“Negotiate”包 ID。
 *
 * @details 身份验证包 (Authentication Package) 是 LSASS 中的 DLL。
 * "Negotiate" 是一个复合包，它会根据当前环境自动协商选择 Kerberos 或 NTLM。
 * 系统通过 LsaLookupAuthenticationPackage 函数获取该包的索引号。
 *
 * @param[out] pulAuthPackage 接收返回的身份验证包 ID。
 * @return HRESULT 状态码。
 */
HRESULT RetrieveNegotiateAuthPackage(__out ULONG* pulAuthPackage);

/**
 * @brief 根据需要对密码进行加密保护并拷贝。
 *
 * @details
 * - 在某些场景（如 CPUS_CREDUI）下，密码必须通过 CredProtectW 进行加密，
 *   以防止密码在内存中以明文形式长时间存在，降低被恶意 dump 内存窃取的风险。
 * - 此函数会判断当前场景是否需要保护，如果需要，调用
 * CredProtectW；否则仅执行简单的拷贝。
 *
 * @param[in]  pwzPassword           输入的原始密码。
 * @param[in]  cpus                  当前的凭据场景。
 * @param[out] ppwzProtectedPassword 返回处理后的密码字符串指针（需后续释放）。
 * @return HRESULT 状态码。
 */
HRESULT
ProtectIfNecessaryAndCopyPassword(__in PCWSTR                             pwzPassword,
                                  __in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
                                  __deref_out PWSTR*                      ppwzProtectedPassword);

/**
 * @brief 处理 32 位与 64 位兼容性的原生重包装。
 *
 * @details 这是一个高级函数，用于处理“魔改”的 WoW64 场景。
 * 如果一个 32 位的凭据提供程序运行在 64
 * 位系统上，其生成的结构体布局（由于指针对齐） 可能与 64
 * 位系统内核预期的布局不同。此函数将 32 位格式转换为原生 64 位格式。
 *
 * @param[in]  rgbWow      32 位环境生成的原始缓冲区。
 * @param[in]  cbWow       原始缓冲区长度。
 * @param[out] prgbNative  重新打包后的原生缓冲区指针。
 * @param[out] pcbNative   原生缓冲区长度。
 * @return HRESULT 状态码。
 */
HRESULT KerbInteractiveUnlockLogonRepackNative(__in_bcount(cbWow) BYTE* rgbWow, __in DWORD cbWow,
                                               __deref_out_bcount(*pcbNative) BYTE** prgbNative,
                                               __out DWORD*                          pcbNative);

/**
 * @brief 原位解包序列化后的凭据。
 *
 * @details 这是 Pack 操作的逆过程。它接收一个“扁平”的缓冲区，并将结构体内部的
 * “偏移量”重新转换回“真实的内存指针”。
 * “InPlace” 意味着它直接在传入的内存块上修改数据，不创建副本。
 *
 * @param[in,out] pkiul 待解包的结构体及缓冲区指针。
 * @param[in]     cb    缓冲区总长度。
 */
void KerbInteractiveUnlockLogonUnpackInPlace(__inout_bcount(cb)
                                                 KERB_INTERACTIVE_UNLOCK_LOGON* pkiul,
                                             __in DWORD                         cb);

/**
 * @brief 将域名和用户名拼接为标准的 "DOMAIN\Username" 格式。
 *
 * @details
 * 1. 计算 "域名" + "\" + "用户名" + "\0" 的总长度。
 * 2. 分配足够的内存。
 * 3. 使用安全字符串函数 StringCchCopy/Cat 拼接。
 * 这是为了方便某些旧版 API 的调用，或者在 UI 上显示完整的用户信息。
 *
 * @param[in]  pwszDomain          域名字符串。
 * @param[in]  pwszUsername        用户名字符串。
 * @param[out] ppwszDomainUsername 拼接后的结果指针。
 * @return HRESULT 状态码。
 */
HRESULT DomainUsernameStringAlloc(__in PCWSTR pwszDomain, __in PCWSTR pwszUsername,
                                  __deref_out PWSTR* ppwszDomainUsername);