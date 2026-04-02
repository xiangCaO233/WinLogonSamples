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
    LogMessage("LsaApLogonUser");

    {
        // clear output arguments first in case of failure
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

    // input arguments
    LogMessage("  LogonType: %i", LogonType);  // Interactive=2, RemoteInteractive=10
    ClientBufferBase;
    LogMessage("  ProtocolSubmitBuffer size: %i", SubmitBufferSize);

    // deliberately restrict supported logontypes
    if ((LogonType != Interactive) && (LogonType != RemoteInteractive))
    {
        LogMessage("  return STATUS_NOT_IMPLEMENTED (unsupported LogonType)");
        return STATUS_NOT_IMPLEMENTED;
    }

    // authentication credentials passed by client
    auto* logonInfo = (MSV1_0_INTERACTIVE_LOGON*)ProtocolSubmitBuffer;
    {
        if (SubmitBufferSize < sizeof(MSV1_0_INTERACTIVE_LOGON))
        {
            LogMessage("  ERROR: SubmitBufferSize too small");
            return STATUS_INVALID_PARAMETER;
        }

        // make relative pointers absolute to ease later access
        logonInfo->LogonDomainName.Buffer =
            (wchar_t*)((BYTE*)logonInfo + (size_t)logonInfo->LogonDomainName.Buffer);
        logonInfo->UserName.Buffer =
            (wchar_t*)((BYTE*)logonInfo + (size_t)logonInfo->UserName.Buffer);
        logonInfo->Password.Buffer =
            (wchar_t*)((BYTE*)logonInfo + (size_t)logonInfo->Password.Buffer);
    }

    // assign output arguments


    wchar_t computerName[MAX_COMPUTERNAME_LENGTH + 1] = {};
    DWORD   computerNameSize                          = ARRAYSIZE(computerName);
    if (!GetComputerNameW(computerName, &computerNameSize))
    {
        LogMessage("  return STATUS_INTERNAL_ERROR (GetComputerNameW failed)");
        return STATUS_INTERNAL_ERROR;
    }

    // assign "ProfileBuffer" output argument
    *ProfileBufferSize = GetProfileBufferSize(computerName, *logonInfo);
    FunctionTable.AllocateClientBuffer(
        ClientRequest, *ProfileBufferSize, ProfileBuffer);  // will update *ProfileBuffer

    std::vector<BYTE> profileBuffer =
        PrepareProfileBuffer(computerName, *logonInfo, (BYTE*)*ProfileBuffer);
    FunctionTable.CopyToClientBuffer(ClientRequest,
                                     (ULONG)profileBuffer.size(),
                                     *ProfileBuffer,
                                     profileBuffer.data());  // copy to caller process


    {
        // assign "LogonId" output argument
        if (!AllocateLocallyUniqueId(LogonId))
        {
            LogMessage("  ERROR: AllocateLocallyUniqueId failed");
            return STATUS_FAIL_FAST_EXCEPTION;
        }
        NTSTATUS status = FunctionTable.CreateLogonSession(LogonId);
        if (status != STATUS_SUCCESS)
        {
            LogMessage("  ERROR: CreateLogonSession failed with err: 0x%x", status);
            return status;
        }

        LogMessage("  LogonId: High=0x%x , Low=0x%x", LogonId->HighPart, LogonId->LowPart);
    }

    *SubStatus = STATUS_SUCCESS;  // reason for error

    {
        // Assign "TokenInformation" output argument
        LSA_TOKEN_INFORMATION_V1* tokenInfo = nullptr;
        NTSTATUS                  subStatus = 0;

        // 关键修改：传入 &LogonId
        NTSTATUS status = UserNameToToken(
            &logonInfo->UserName, LogonId, (LSA_TOKEN_INFORMATION_V1**)&tokenInfo, &subStatus);

        if (status != STATUS_SUCCESS)
        {
            LogMessage("ERROR: UserNameToToken failed with err: 0x%x", status);
            *SubStatus = subStatus;
            return status;
        }

        *TokenInformationType = LsaTokenInformationV1;
        *TokenInformation     = tokenInfo;
    }

    {
        // assign "AccountName" output argument
        LogMessage("  AccountName: %ls", ToWstring(logonInfo->UserName).c_str());
        *AccountName = CreateLsaUnicodeString(logonInfo->UserName.Buffer,
                                              logonInfo->UserName.Length);  // mandatory
    }

    // 8. 设置 AccountName（必须从 LSA 堆分配）
    *AccountName = CreateLsaUnicodeString(logonInfo->UserName.Buffer, logonInfo->UserName.Length);

    // 9. 设置 AuthenticatingAuthority (解决注销崩溃的关键！)
    if (AuthenticatingAuthority)
    {
        // 核心修改点：对于本地账户，这个值必须是计算机名。
        // 如果设置为 "." 或空，第二次登录时 ProfSvc 会因为 SID 校验失败而崩溃。
        LogMessage("  Setting AuthenticatingAuthority to: %ls", computerName);
        *AuthenticatingAuthority =
            CreateLsaUnicodeString(computerName, (USHORT)(wcslen(computerName) * sizeof(wchar_t)));
    }

    LogMessage("  return STATUS_SUCCESS");
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
