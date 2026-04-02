#include "PrepareToken.hpp"
#include "PrepareProfile.hpp"
#include "Utils.hpp"
#include "LSASecFuncTableImpl.h"

// exported symbols
#pragma comment(linker, "/export:SpLsaModeInitialize")

LSA_SECPKG_FUNCTION_TABLE FunctionTable;


NTSTATUS NTAPI SpInitialize(_In_ ULONG_PTR PackageId, _In_ SECPKG_PARAMETERS* Parameters,
                            _In_ LSA_SECPKG_FUNCTION_TABLE* functionTable)
{
    LogMessage("SpInitialize Called");

    LogMessage("  PackageId: %u", PackageId);
    LogMessage("  Version: %u", Parameters->Version);
    {
        ULONG state = Parameters->MachineState;
        LogMessage("  MachineState:");
        if (state & SECPKG_STATE_ENCRYPTION_PERMITTED)
        {
            state &= ~SECPKG_STATE_ENCRYPTION_PERMITTED;
            LogMessage("  - ENCRYPTION_PERMITTED");
        }
        if (state & SECPKG_STATE_STRONG_ENCRYPTION_PERMITTED)
        {
            state &= ~SECPKG_STATE_STRONG_ENCRYPTION_PERMITTED;
            LogMessage("  - STRONG_ENCRYPTION_PERMITTED");
        }
        if (state & SECPKG_STATE_DOMAIN_CONTROLLER)
        {
            state &= ~SECPKG_STATE_DOMAIN_CONTROLLER;
            LogMessage("  - DOMAIN_CONTROLLER");
        }
        if (state & SECPKG_STATE_WORKSTATION)
        {
            state &= ~SECPKG_STATE_WORKSTATION;
            LogMessage("  - WORKSTATION");
        }
        if (state & SECPKG_STATE_STANDALONE)
        {
            state &= ~SECPKG_STATE_STANDALONE;
            LogMessage("  - STANDALONE");
        }
        if (state)
        {
            // print resudual flags not already covered
            LogMessage("  * Unknown flags: 0x%X", state);
        }
    }
    LogMessage("  SetupMode: %u", Parameters->SetupMode);
    // parameters not logged
    Parameters->DomainSid;
    Parameters->DomainName;
    Parameters->DnsDomainName;
    Parameters->DomainGuid;

    FunctionTable = *functionTable;  // copy function pointer table

    LogMessage("  return STATUS_SUCCESS");
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI SpShutDown()
{
    LogMessage("SpShutDown");
    LogMessage("  return STATUS_SUCCESS");
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI SpGetInfo(_Out_ SecPkgInfoW* PackageInfo)
{
    LogMessage("SpGetInfo");

    // return security package metadata
    PackageInfo->fCapabilities = SECPKG_FLAG_LOGON           //  supports LsaLogonUser
                                 | SECPKG_FLAG_CLIENT_ONLY;  // no server auth support
    PackageInfo->wVersion   = SECURITY_SUPPORT_PROVIDER_INTERFACE_VERSION;
    PackageInfo->wRPCID     = SECPKG_ID_NONE;  // no DCE/RPC support
    PackageInfo->cbMaxToken = 0;
    PackageInfo->Name       = (wchar_t*)L"NoPasswordAuthPkg";
    PackageInfo->Comment    = (wchar_t*)L"Custom authentication package for testing";

    LogMessage("  return STATUS_SUCCESS");
    return STATUS_SUCCESS;
}


/* Authenticate a user logon attempt.
   Returns STATUS_SUCCESS if the login attempt succeeded. */
NTSTATUS LsaApLogonUser(_In_ PLSA_CLIENT_REQUEST ClientRequest, _In_ SECURITY_LOGON_TYPE LogonType,
                        _In_reads_bytes_(SubmitBufferSize) VOID* ProtocolSubmitBuffer,
                        _In_ VOID* ClientBufferBase, _In_ ULONG SubmitBufferSize,
                        _Outptr_result_bytebuffer_(*ProfileBufferSize) VOID** ProfileBuffer,
                        _Out_ ULONG* ProfileBufferSize, _Out_ LUID* LogonId,
                        _Out_ NTSTATUS*                   SubStatus,
                        _Out_ LSA_TOKEN_INFORMATION_TYPE* TokenInformationType,
                        _Outptr_ VOID** TokenInformation, _Out_ LSA_UNICODE_STRING** AccountName,
                        _Out_ LSA_UNICODE_STRING** AuthenticatingAuthority)
{
    LogMessage("LsaApLogonUser Called");

    // 1. 初始化/清理输出参数
    {
        *ProfileBuffer        = nullptr;
        *ProfileBufferSize    = 0;
        *LogonId              = {};
        *SubStatus            = 0;
        *TokenInformationType = {};
        *TokenInformation     = nullptr;
        *AccountName          = nullptr;
        if (AuthenticatingAuthority)
            *AuthenticatingAuthority = nullptr;
    }

    // 2. 校验登录类型
    if ((LogonType != Interactive) && (LogonType != RemoteInteractive))
    {
        LogMessage("  return STATUS_NOT_IMPLEMENTED (unsupported LogonType: %i)", LogonType);
        return STATUS_NOT_IMPLEMENTED;
    }

    // 3. 校验输入缓冲区
    if (SubmitBufferSize < sizeof(MSV1_0_INTERACTIVE_LOGON))
    {
        LogMessage("  ERROR: SubmitBufferSize too small");
        return STATUS_INVALID_PARAMETER;
    }

    // =========================================================================
    // 关键修复点：不要直接在 ProtocolSubmitBuffer 上改！
    // 我们创建一个本地副本，处理副本里的指针，这样 LSA 原始缓冲区里的相对偏移就不会被破坏
    // =========================================================================
    auto logonInfoRaw = *(MSV1_0_INTERACTIVE_LOGON*)ProtocolSubmitBuffer;

    // 将副本中的相对偏移转换为绝对指针，方便我们函数内部使用
    logonInfoRaw.LogonDomainName.Buffer =
        (wchar_t*)((BYTE*)ProtocolSubmitBuffer + (ULONG_PTR)logonInfoRaw.LogonDomainName.Buffer);
    logonInfoRaw.UserName.Buffer =
        (wchar_t*)((BYTE*)ProtocolSubmitBuffer + (ULONG_PTR)logonInfoRaw.UserName.Buffer);
    logonInfoRaw.Password.Buffer =
        (wchar_t*)((BYTE*)ProtocolSubmitBuffer + (ULONG_PTR)logonInfoRaw.Password.Buffer);

    LogMessage("  Attempting logon for User: %ls , Domain: %ls, Passwd: %ls",
               logonInfoRaw.UserName.Buffer,
               logonInfoRaw.LogonDomainName.Buffer,
               logonInfoRaw.Password.Buffer);

    // 获取计算机名
    wchar_t computerName[MAX_COMPUTERNAME_LENGTH + 1] = {};
    DWORD   computerNameSize                          = ARRAYSIZE(computerName);
    if (!GetComputerNameW(computerName, &computerNameSize))
    {
        LogMessage("  return STATUS_INTERNAL_ERROR (GetComputerNameW failed)");
        return STATUS_INTERNAL_ERROR;
    }

    // 4. 分配并准备 ProfileBuffer
    *ProfileBufferSize = GetProfileBufferSize(computerName, logonInfoRaw);
    NTSTATUS allocStatus =
        FunctionTable.AllocateClientBuffer(ClientRequest, *ProfileBufferSize, ProfileBuffer);
    if (allocStatus != STATUS_SUCCESS)
    {
        LogMessage("  ERROR: AllocateClientBuffer failed: 0x%x", allocStatus);
        return allocStatus;
    }

    std::vector<BYTE> profileData =
        PrepareProfileBuffer(computerName, logonInfoRaw, (BYTE*)*ProfileBuffer);
    FunctionTable.CopyToClientBuffer(
        ClientRequest, (ULONG)profileData.size(), *ProfileBuffer, profileData.data());

    // 5. 分配 LogonId 并创建会话
    if (!AllocateLocallyUniqueId(LogonId))
    {
        LogMessage("  ERROR: AllocateLocallyUniqueId failed");
        return STATUS_FAIL_FAST_EXCEPTION;
    }

    NTSTATUS sessionStatus = FunctionTable.CreateLogonSession(LogonId);
    if (sessionStatus != STATUS_SUCCESS)
    {
        LogMessage("  ERROR: CreateLogonSession failed: 0x%x", sessionStatus);
        return sessionStatus;
    }
    LogMessage("  LogonSession Created: 0x%x:%08x", LogonId->HighPart, LogonId->LowPart);

    // 6. 将用户名转换为 Token (关键步骤)
    {
        LSA_TOKEN_INFORMATION_V1* tokenInfo = nullptr;
        NTSTATUS                  subStatus = 0;

        // 使用副本里的用户名
        NTSTATUS tokenStatus =
            UserNameToToken(&logonInfoRaw.UserName, LogonId, &tokenInfo, &subStatus);

        if (tokenStatus != STATUS_SUCCESS)
        {
            LogMessage("  ERROR: UserNameToToken failed: 0x%x", tokenStatus);
            *SubStatus = subStatus;
            return tokenStatus;
        }

        *TokenInformationType = LsaTokenInformationV1;
        *TokenInformation     = tokenInfo;
    }

    // 7. 设置 AccountName (必须从 LSA 堆分配)
    *AccountName =
        CreateLsaUnicodeString(logonInfoRaw.UserName.Buffer, logonInfoRaw.UserName.Length);

    // 8. 设置 AuthenticatingAuthority (解决注销崩溃/二次登录失败)
    if (AuthenticatingAuthority)
    {
        LogMessage("  Setting AuthenticatingAuthority to: %ls", computerName);
        *AuthenticatingAuthority =
            CreateLsaUnicodeString(computerName, (USHORT)(wcslen(computerName) * sizeof(wchar_t)));
    }

    *SubStatus = STATUS_SUCCESS;
    LogMessage("  LsaApLogonUser Success");
    return STATUS_SUCCESS;
}

void LsaApLogonTerminated(_In_ LUID* LogonId)
{
    LogMessage("LsaApLogonTerminated");
    LogMessage("  LogonId: High=0x%x , Low=0x%x", LogonId->HighPart, LogonId->LowPart);
    LogMessage("  return");
}

SECPKG_FUNCTION_TABLE SecurityPackageFunctionTable = {};

/** LSA calls SpLsaModeInitialize() when loading SSP/AP DLLs. */
extern "C" NTSTATUS NTAPI SpLsaModeInitialize(_In_ ULONG LsaVersion, _Out_ ULONG* PackageVersion,
                                              _Out_ SECPKG_FUNCTION_TABLE** ppTables,
                                              _Out_ ULONG*                  pcTables)
{
    LogMessage("SpLsaModeInitialize");
    LogMessage("  LsaVersion %u", LsaVersion);

    // --- 新增的代码：手动填充函数表 ---
    // 这种方式不会受 AddCredentialsW 宏的影响，也不会报错 C7559
    ZeroMemory(&SecurityPackageFunctionTable, sizeof(SecurityPackageFunctionTable));

    // 2. 使用 decltype 动态获取结构体成员的类型进行强制转换
    // 这种方法不依赖 PSpInitializeFn 等别名，兼容所有 SDK 版本
    SecurityPackageFunctionTable.Initialize =
        reinterpret_cast<decltype(SecurityPackageFunctionTable.Initialize)>(SpInitialize);

    SecurityPackageFunctionTable.Shutdown =
        reinterpret_cast<decltype(SecurityPackageFunctionTable.Shutdown)>(SpShutDown);

    SecurityPackageFunctionTable.GetInfo =
        reinterpret_cast<decltype(SecurityPackageFunctionTable.GetInfo)>(SpGetInfo);

    SecurityPackageFunctionTable.LogonUser =
        reinterpret_cast<decltype(SecurityPackageFunctionTable.LogonUser)>(LsaApLogonUser);

    SecurityPackageFunctionTable.LogonTerminated =
        reinterpret_cast<decltype(SecurityPackageFunctionTable.LogonTerminated)>(
            LsaApLogonTerminated);

    // === 以下是所有其他须填的回调函数 ===

    // SecurityPackageFunctionTable.InitializePackage =
    //     reinterpret_cast<decltype(SecurityPackageFunctionTable.InitializePackage)>(
    //         LsaApInitializePackage);

    SecurityPackageFunctionTable.CallPackage =
        reinterpret_cast<decltype(SecurityPackageFunctionTable.CallPackage)>(LsaApCallPackage);

    SecurityPackageFunctionTable.CallPackageUntrusted =
        reinterpret_cast<decltype(SecurityPackageFunctionTable.CallPackageUntrusted)>(
            LsaApCallPackageUntrusted);

    SecurityPackageFunctionTable.CallPackagePassthrough =
        reinterpret_cast<decltype(SecurityPackageFunctionTable.CallPackagePassthrough)>(
            LsaApCallPackagePassthrough);

    SecurityPackageFunctionTable.PreLogonUserSurrogate =
        reinterpret_cast<decltype(SecurityPackageFunctionTable.PreLogonUserSurrogate)>(
            LsaApPreLogonUserSurrogate);

    SecurityPackageFunctionTable.PostLogonUserSurrogate =
        reinterpret_cast<decltype(SecurityPackageFunctionTable.PostLogonUserSurrogate)>(
            LsaApPostLogonUserSurrogate);

    SecurityPackageFunctionTable.PostLogonUser =
        reinterpret_cast<decltype(SecurityPackageFunctionTable.PostLogonUser)>(LsaApPostLogonUser);

    SecurityPackageFunctionTable.AcceptCredentials =
        reinterpret_cast<decltype(SecurityPackageFunctionTable.AcceptCredentials)>(
            SpAcceptCredentials);

    SecurityPackageFunctionTable.AcquireCredentialsHandle =
        reinterpret_cast<decltype(SecurityPackageFunctionTable.AcquireCredentialsHandle)>(
            SpAcquireCredentialsHandle);

    SecurityPackageFunctionTable.QueryCredentialsAttributes =
        reinterpret_cast<decltype(SecurityPackageFunctionTable.QueryCredentialsAttributes)>(
            SpQueryCredentialsAttributes);

    SecurityPackageFunctionTable.FreeCredentialsHandle =
        reinterpret_cast<decltype(SecurityPackageFunctionTable.FreeCredentialsHandle)>(
            SpFreeCredentialsHandle);

    SecurityPackageFunctionTable.SaveCredentials =
        reinterpret_cast<decltype(SecurityPackageFunctionTable.SaveCredentials)>(SpSaveCredentials);

    SecurityPackageFunctionTable.GetCredentials =
        reinterpret_cast<decltype(SecurityPackageFunctionTable.GetCredentials)>(SpGetCredentials);

    SecurityPackageFunctionTable.DeleteCredentials =
        reinterpret_cast<decltype(SecurityPackageFunctionTable.DeleteCredentials)>(
            SpDeleteCredentials);

    SecurityPackageFunctionTable.InitLsaModeContext =
        reinterpret_cast<decltype(SecurityPackageFunctionTable.InitLsaModeContext)>(
            SpInitLsaModeContext);

    SecurityPackageFunctionTable.AcceptLsaModeContext =
        reinterpret_cast<decltype(SecurityPackageFunctionTable.AcceptLsaModeContext)>(
            SpAcceptLsaModeContext);

    SecurityPackageFunctionTable.DeleteContext =
        reinterpret_cast<decltype(SecurityPackageFunctionTable.DeleteContext)>(SpDeleteContext);

    SecurityPackageFunctionTable.ApplyControlToken =
        reinterpret_cast<decltype(SecurityPackageFunctionTable.ApplyControlToken)>(
            SpApplyControlToken);

    SecurityPackageFunctionTable.GetUserInfo =
        reinterpret_cast<decltype(SecurityPackageFunctionTable.GetUserInfo)>(SpGetUserInfo);

    SecurityPackageFunctionTable.GetExtendedInformation =
        reinterpret_cast<decltype(SecurityPackageFunctionTable.GetExtendedInformation)>(
            SpGetExtendedInformation);

    SecurityPackageFunctionTable.QueryContextAttributes =
        reinterpret_cast<decltype(SecurityPackageFunctionTable.QueryContextAttributes)>(
            SpQueryContextAttributes);

    SecurityPackageFunctionTable.AddCredentials =
        reinterpret_cast<decltype(SecurityPackageFunctionTable.AddCredentials)>(SpAddCredentials);

    SecurityPackageFunctionTable.SetExtendedInformation =
        reinterpret_cast<decltype(SecurityPackageFunctionTable.SetExtendedInformation)>(
            SpSetExtendedInformation);

    SecurityPackageFunctionTable.SetContextAttributes =
        reinterpret_cast<decltype(SecurityPackageFunctionTable.SetContextAttributes)>(
            SpSetContextAttributes);

    SecurityPackageFunctionTable.SetCredentialsAttributes =
        reinterpret_cast<decltype(SecurityPackageFunctionTable.SetCredentialsAttributes)>(
            SpSetCredentialsAttributes);

    SecurityPackageFunctionTable.ChangeAccountPassword =
        reinterpret_cast<decltype(SecurityPackageFunctionTable.ChangeAccountPassword)>(
            SpChangeAccountPassword);

    SecurityPackageFunctionTable.QueryMetaData =
        reinterpret_cast<decltype(SecurityPackageFunctionTable.QueryMetaData)>(SpQueryMetaData);

    SecurityPackageFunctionTable.ExchangeMetaData =
        reinterpret_cast<decltype(SecurityPackageFunctionTable.ExchangeMetaData)>(
            SpExchangeMetaData);

    SecurityPackageFunctionTable.GetCredUIContext =
        reinterpret_cast<decltype(SecurityPackageFunctionTable.GetCredUIContext)>(
            SpGetCredUIContext);

    SecurityPackageFunctionTable.UpdateCredentials =
        reinterpret_cast<decltype(SecurityPackageFunctionTable.UpdateCredentials)>(
            SpUpdateCredentials);

    SecurityPackageFunctionTable.ValidateTargetInfo =
        reinterpret_cast<decltype(SecurityPackageFunctionTable.ValidateTargetInfo)>(
            SpValidateTargetInfo);

    SecurityPackageFunctionTable.GetRemoteCredGuardLogonBuffer =
        reinterpret_cast<decltype(SecurityPackageFunctionTable.GetRemoteCredGuardLogonBuffer)>(
            SpGetRemoteCredGuardLogonBuffer);

    SecurityPackageFunctionTable.GetRemoteCredGuardSupplementalCreds = reinterpret_cast<
        decltype(SecurityPackageFunctionTable.GetRemoteCredGuardSupplementalCreds)>(
        SpGetRemoteCredGuardSupplementalCreds);

    SecurityPackageFunctionTable.GetTbalSupplementalCreds =
        reinterpret_cast<decltype(SecurityPackageFunctionTable.GetTbalSupplementalCreds)>(
            SpGetTbalSupplementalCreds);

    SecurityPackageFunctionTable.ExtractTargetInfo =
        reinterpret_cast<decltype(SecurityPackageFunctionTable.ExtractTargetInfo)>(
            SpExtractTargetInfo);

    // --------------------------------

    *PackageVersion = SECPKG_INTERFACE_VERSION;
    *ppTables       = &SecurityPackageFunctionTable;
    *pcTables       = 1;

    LogMessage("  return STATUS_SUCCESS");
    return STATUS_SUCCESS;
}
