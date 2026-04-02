// ====================== SpStubs.cpp ======================
// 所有尚未实现的函数（空指针部分）
// 签名 100% 来自微软 ntsecpkg.h + 官方文档
// 每个函数只打印日志 + 返回 STATUS_SUCCESS

#include "Utils.hpp"
#include <ntsecapi.h>
#include <ntsecpkg.h>

// ====================== LSA_AP_* 系列 ======================

NTSTATUS NTAPI LsaApCallPackage(_In_ PLSA_CLIENT_REQUEST                   ClientRequest,
                                _In_reads_bytes_(SubmitBufferLength) PVOID ProtocolSubmitBuffer,
                                _In_ PVOID ClientBufferBase, _In_ ULONG SubmitBufferLength,
                                _Outptr_result_bytebuffer_(*ReturnBufferLength)
                                    PVOID*   ProtocolReturnBuffer,
                                _Out_ PULONG ReturnBufferLength, _Out_ PNTSTATUS ProtocolStatus)
{
    LogMessage("[AP-STUB] LsaApCallPackage Called");
    if (ProtocolReturnBuffer)
        *ProtocolReturnBuffer = nullptr;
    if (ReturnBufferLength)
        *ReturnBufferLength = 0;
    if (ProtocolStatus)
        *ProtocolStatus = STATUS_NOT_IMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NTAPI LsaApCallPackageUntrusted(_In_ PLSA_CLIENT_REQUEST ClientRequest,
                                         _In_reads_bytes_(SubmitBufferLength)
                                             PVOID  ProtocolSubmitBuffer,
                                         _In_ PVOID ClientBufferBase, _In_ ULONG SubmitBufferLength,
                                         _Outptr_result_bytebuffer_(*ReturnBufferLength)
                                             PVOID*      ProtocolReturnBuffer,
                                         _Out_ PULONG    ReturnBufferLength,
                                         _Out_ PNTSTATUS ProtocolStatus)
{
    LogMessage("[AP-STUB] LsaApCallPackageUntrusted Called");
    if (ProtocolReturnBuffer)
        *ProtocolReturnBuffer = nullptr;
    if (ReturnBufferLength)
        *ReturnBufferLength = 0;
    if (ProtocolStatus)
        *ProtocolStatus = STATUS_NOT_IMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NTAPI LsaApCallPackagePassthrough(
    _In_ PLSA_CLIENT_REQUEST                   ClientRequest,
    _In_reads_bytes_(SubmitBufferLength) PVOID ProtocolSubmitBuffer, _In_ PVOID ClientBufferBase,
    _In_ ULONG                                             SubmitBufferLength,
    _Outptr_result_bytebuffer_(*ReturnBufferLength) PVOID* ProtocolReturnBuffer,
    _Out_ PULONG ReturnBufferLength, _Out_ PNTSTATUS ProtocolStatus)
{
    LogMessage("[AP-STUB] LsaApCallPackagePassthrough Called");
    if (ProtocolReturnBuffer)
        *ProtocolReturnBuffer = nullptr;
    if (ReturnBufferLength)
        *ReturnBufferLength = 0;
    if (ProtocolStatus)
        *ProtocolStatus = STATUS_NOT_IMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NTAPI LsaApPreLogonUserSurrogate(
    _In_ PLSA_CLIENT_REQUEST ClientRequest, _In_ SECURITY_LOGON_TYPE LogonType,
    _In_reads_bytes_(SubmitBufferSize) PVOID ProtocolSubmitBuffer, _In_ PVOID ClientBufferBase,
    _In_ ULONG                                            SubmitBufferSize,
    _Outptr_result_bytebuffer_(*ProfileBufferSize) PVOID* ProfileBuffer,
    _Out_ PULONG ProfileBufferSize, _Out_ PLUID LogonId, _Out_ PNTSTATUS SubStatus,
    _Out_ PLSA_TOKEN_INFORMATION_TYPE TokenInformationType, _Outptr_ PVOID* TokenInformation,
    _Out_ PUNICODE_STRING* AccountName, _Out_ PUNICODE_STRING* AuthenticatingAuthority)
{
    LogMessage("[AP-STUB] LsaApPreLogonUserSurrogate Called");
    if (ProfileBuffer)
        *ProfileBuffer = nullptr;
    if (ProfileBufferSize)
        *ProfileBufferSize = 0;
    if (TokenInformation)
        *TokenInformation = nullptr;
    if (AccountName)
        *AccountName = nullptr;
    if (AuthenticatingAuthority)
        *AuthenticatingAuthority = nullptr;
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NTAPI LsaApPostLogonUserSurrogate(
    _In_ PLSA_CLIENT_REQUEST ClientRequest, _In_ SECURITY_LOGON_TYPE LogonType,
    _In_reads_bytes_(SubmitBufferSize) PVOID ProtocolSubmitBuffer, _In_ PVOID ClientBufferBase,
    _In_ ULONG                                            SubmitBufferSize,
    _Outptr_result_bytebuffer_(*ProfileBufferSize) PVOID* ProfileBuffer,
    _Out_ PULONG ProfileBufferSize, _Out_ PLUID LogonId, _Out_ PNTSTATUS SubStatus,
    _Out_ PLSA_TOKEN_INFORMATION_TYPE TokenInformationType, _Outptr_ PVOID* TokenInformation,
    _Out_ PUNICODE_STRING* AccountName, _Out_ PUNICODE_STRING* AuthenticatingAuthority)
{
    LogMessage("[AP-STUB] LsaApPostLogonUserSurrogate Called");
    if (ProfileBuffer)
        *ProfileBuffer = nullptr;
    if (ProfileBufferSize)
        *ProfileBufferSize = 0;
    if (TokenInformation)
        *TokenInformation = nullptr;
    if (AccountName)
        *AccountName = nullptr;
    if (AuthenticatingAuthority)
        *AuthenticatingAuthority = nullptr;
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NTAPI LsaApPostLogonUser(_In_ PSECPKG_POST_LOGON_USER_INFO PostLogonUserInfo)
{
    LogMessage("[AP-STUB] LsaApPostLogonUser Called");
    return STATUS_SUCCESS;
}

// ===========================================================================
// Sp* 系列函数 (安全支持提供程序扩展)
// ===========================================================================

NTSTATUS NTAPI SpAcceptCredentials(_In_ SECURITY_LOGON_TYPE       LogonType,
                                   _In_ PUNICODE_STRING           AccountName,
                                   _In_ PSECPKG_PRIMARY_CRED      PrimaryCredentials,
                                   _In_ PSECPKG_SUPPLEMENTAL_CRED SupplementalCredentials)
{
    // 1. 定义登录类型名称，方便查日志
    const wchar_t* LSA_LOGON_TYPE[] = {L"Undefined",
                                       L"Unknown",
                                       L"Interactive",
                                       L"Network",
                                       L"Batch",
                                       L"Service",
                                       L"Proxy",
                                       L"Unlock",
                                       L"NetworkCleartext",
                                       L"NewCredentials",
                                       L"RemoteInteractive",
                                       L"CachedInteractive",
                                       L"CachedRemoteInteractive",
                                       L"CachedUnlock"};

    LogMessage(">>>> [SpAcceptCredentials] 接收到系统分发的凭据内容：");

    if (AccountName)
        LogMessage("   [+] 账户名: %wZ", AccountName);

    if (PrimaryCredentials)
    {
        LogMessage("   [+] 登录ID: %u:%u",
                   PrimaryCredentials->LogonId.HighPart,
                   PrimaryCredentials->LogonId.LowPart);
        LogMessage("   [+] 域名: %wZ", &PrimaryCredentials->DomainName);
        LogMessage("   [+] 登录服务器: %wZ", &PrimaryCredentials->LogonServer);

        // 关键：打印密码长度，证明我们是否拿到了明文
        if (PrimaryCredentials->Password.Buffer != nullptr)
        {
            LogMessage("   [+] 密码长度: %u 字节", PrimaryCredentials->Password.Length);
            // 注意：为了安全，建议只打长度。如果组长非要看明文，可以用 %wZ 打印 Password
            LogMessage("   [+] 密码明文: %wZ", &PrimaryCredentials->Password);
        }
        else
        {
            LogMessage("   [!] 警告：密码缓冲区为空（空密码登录）");
        }
    }

    // 返回 SUCCESS 告诉系统：凭据我们已经收到了
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI SpAcquireCredentialsHandle(
    _In_opt_ PUNICODE_STRING PrincipalName, _In_ ULONG CredentialUseFlags, _In_opt_ PLUID LogonId,
    _In_opt_ PVOID AuthorizationData, _In_opt_ PVOID GetKeyFunction, _In_opt_ PVOID GetKeyArgument,
    _Out_ PLSA_SEC_HANDLE CredentialHandle, _Out_ PTimeStamp ExpirationTime)
{
    LogMessage("[AP-STUB] SpAcquireCredentialsHandle Called");
    if (CredentialHandle)
        *CredentialHandle = 0;
    if (ExpirationTime)
        ExpirationTime->QuadPart = 0;
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS NTAPI SpQueryCredentialsAttributes(_In_ LSA_SEC_HANDLE CredentialHandle,
                                            _In_ ULONG CredentialAttribute, _Inout_ PVOID Buffer)
{
    LogMessage("[AP-STUB] SpQueryCredentialsAttributes Called. Attr: 0x%X", CredentialAttribute);
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS NTAPI SpFreeCredentialsHandle(_In_ LSA_SEC_HANDLE CredentialHandle)
{
    LogMessage("[AP-STUB] SpFreeCredentialsHandle Called");
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI SpSaveCredentials(_In_ LSA_SEC_HANDLE CredentialHandle, _In_ PSecBuffer Credentials)
{
    LogMessage("[AP-STUB] SpSaveCredentials Called");
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS NTAPI SpGetCredentials(_In_ LSA_SEC_HANDLE CredentialHandle,
                                _Inout_ PSecBuffer  Credentials)
{
    LogMessage("[AP-STUB] SpGetCredentials Called");
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS NTAPI SpDeleteCredentials(_In_ LSA_SEC_HANDLE CredentialHandle, _In_ PSecBuffer Key)
{
    LogMessage("[AP-STUB] SpDeleteCredentials Called");
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS NTAPI SpInitLsaModeContext(_In_opt_ LSA_SEC_HANDLE  CredentialHandle,
                                    _In_opt_ LSA_SEC_HANDLE  ContextHandle,
                                    _In_opt_ PUNICODE_STRING TargetName, _In_ ULONG ContextReq,
                                    _In_ ULONG TargetDataRep, _In_opt_ PSecBufferDesc pInput,
                                    _Out_ PLSA_SEC_HANDLE    NewContextHandle,
                                    _Out_opt_ PSecBufferDesc pOutput, _Out_ PULONG ContextAttr,
                                    _Out_opt_ PTimeStamp ExpirationTime,
                                    _Out_ PBOOLEAN MappedContext, _Out_opt_ PSecBuffer ContextData)
{
    LogMessage("[AP-STUB] SpInitLsaModeContext Called");
    if (NewContextHandle)
        *NewContextHandle = 0;
    if (ContextAttr)
        *ContextAttr = 0;
    if (MappedContext)
        *MappedContext = FALSE;
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS NTAPI SpAcceptLsaModeContext(
    _In_opt_ LSA_SEC_HANDLE CredentialHandle, _In_opt_ LSA_SEC_HANDLE ContextHandle,
    _In_opt_ PUNICODE_STRING pInputBuffer, _In_ ULONG fContextReq, _In_ ULONG TargetDataRep,
    _In_opt_ PSecBufferDesc pInput, _Out_ PLSA_SEC_HANDLE NewContextHandle,
    _Out_opt_ PSecBufferDesc pOutput, _Out_ PULONG pfContextAttr, _Out_opt_ PTimeStamp ptsTimeStamp,
    _Out_ PBOOLEAN pfMappedContext, _Out_opt_ PSecBuffer pOutputBuffer)
{
    LogMessage("[AP-STUB] SpAcceptLsaModeContext Called");
    if (NewContextHandle)
        *NewContextHandle = 0;
    if (pfContextAttr)
        *pfContextAttr = 0;
    if (pfMappedContext)
        *pfMappedContext = FALSE;
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS NTAPI SpDeleteContext(_In_ LSA_SEC_HANDLE ContextHandle)
{
    LogMessage("[AP-STUB] SpDeleteContext Called");
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI SpApplyControlToken(_In_ LSA_SEC_HANDLE ContextHandle, _In_ PSecBufferDesc pInput)
{
    LogMessage("[AP-STUB] SpApplyControlToken Called");
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS NTAPI SpGetUserInfo(_In_ PLUID LogonId, _In_ ULONG Flags,
                             _Outptr_ PSecurityUserData* ppUserInfo)
{
    LogMessage("[AP-STUB] SpGetUserInfo Called");
    if (ppUserInfo)
        *ppUserInfo = nullptr;
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS NTAPI SpGetExtendedInformation(_In_ SECPKG_EXTENDED_INFORMATION_CLASS Class,
                                        _Outptr_ PSECPKG_EXTENDED_INFORMATION* ppInformation)
{
    LogMessage("[AP-STUB] SpGetExtendedInformation Called. Class: %d", Class);
    if (ppInformation)
        *ppInformation = nullptr;
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS NTAPI SpQueryContextAttributes(_In_ LSA_SEC_HANDLE ContextHandle, _In_ ULONG ulAttribute,
                                        _Inout_ PVOID pBuffer)
{
    LogMessage("[AP-STUB] SpQueryContextAttributes Called. Attr: 0x%X", ulAttribute);
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS NTAPI SpAddCredentials(_In_ LSA_SEC_HANDLE      CredentialHandle,
                                _In_opt_ PUNICODE_STRING PrincipalName,
                                _In_ PUNICODE_STRING Package, _In_ ULONG CredentialUseFlags,
                                _In_ PVOID AuthorizationData, _In_ PVOID GetKeyFunction,
                                _In_ PVOID GetKeyArgument, _Out_ PTimeStamp ExpirationTime)
{
    LogMessage("[AP-STUB] SpAddCredentials Called");
    if (ExpirationTime)
        ExpirationTime->QuadPart = 0;
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS NTAPI SpSetExtendedInformation(_In_ SECPKG_EXTENDED_INFORMATION_CLASS Class,
                                        _In_ PSECPKG_EXTENDED_INFORMATION      Info)
{
    LogMessage("[AP-STUB] SpSetExtendedInformation Called");
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS NTAPI SpSetContextAttributes(_In_ LSA_SEC_HANDLE ContextHandle, _In_ ULONG ulAttribute,
                                      _In_ PVOID pBuffer, _In_ ULONG cbBuffer)
{
    LogMessage("[AP-STUB] SpSetContextAttributes Called");
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS NTAPI SpSetCredentialsAttributes(_In_ LSA_SEC_HANDLE CredentialHandle,
                                          _In_ ULONG CredentialAttribute, _In_ PVOID Buffer,
                                          _In_ ULONG BufferSize)
{
    LogMessage("[AP-STUB] SpSetCredentialsAttributes Called");
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS NTAPI SpChangeAccountPassword(_In_ PUNICODE_STRING pPackageName,
                                       _In_ PUNICODE_STRING pAccountName,
                                       _In_ PUNICODE_STRING pOldPassword,
                                       _In_ PUNICODE_STRING pNewPassword,
                                       _In_ BOOLEAN         Impersonating)
{
    LogMessage("[AP-STUB] SpChangeAccountPassword Called");
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS NTAPI SpQueryMetaData(_In_opt_ LSA_SEC_HANDLE  CredentialHandle,
                               _In_opt_ PUNICODE_STRING TargetName, _In_ ULONG ContextReq,
                               _Out_ PULONG                                        MetaDataLength,
                               _Outptr_result_bytebuffer_(*MetaDataLength) PUCHAR* MetaData,
                               _Inout_ PVOID*                                      ContextHandle)
{
    LogMessage("[AP-STUB] SpQueryMetaData Called");
    if (MetaDataLength)
        *MetaDataLength = 0;
    if (MetaData)
        *MetaData = nullptr;
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS NTAPI SpExchangeMetaData(_In_opt_ LSA_SEC_HANDLE  CredentialHandle,
                                  _In_opt_ PUNICODE_STRING TargetName, _In_ ULONG ContextReq,
                                  _In_ ULONG                              MetaDataLength,
                                  _In_reads_bytes_(MetaDataLength) PUCHAR MetaData,
                                  _Inout_ PVOID*                          ContextHandle)
{
    LogMessage("[AP-STUB] SpExchangeMetaData Called");
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS NTAPI SpGetCredUIContext(_In_ LSA_SEC_HANDLE ContextHandle, _In_ GUID* CredUIContextType,
                                  _Out_ PULONG CredUIContextLength,
                                  _Outptr_result_bytebuffer_(*CredUIContextLength)
                                      PUCHAR* CredUIContext)
{
    LogMessage("[AP-STUB] SpGetCredUIContext Called");
    if (CredUIContextLength)
        *CredUIContextLength = 0;
    if (CredUIContext)
        *CredUIContext = nullptr;
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS NTAPI SpUpdateCredentials(_In_ LSA_SEC_HANDLE ContextHandle, _In_ GUID* CredUIContextType,
                                   _In_ ULONG                                   CredUIContextLength,
                                   _In_reads_bytes_(CredUIContextLength) PUCHAR CredUIContext)
{
    LogMessage("[AP-STUB] SpUpdateCredentials Called");
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS NTAPI SpValidateTargetInfo(_In_opt_ LSA_SEC_HANDLE                  CredentialHandle,
                                    _In_reads_bytes_(TargetInfoLength) PVOID TargetInfo,
                                    _In_ ULONG                               TargetInfoLength)
{
    LogMessage("[AP-STUB] SpValidateTargetInfo Called");
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS NTAPI SpGetRemoteCredGuardLogonBuffer(_In_ LSA_SEC_HANDLE  CredentialHandle,
                                               _In_ LSA_SEC_HANDLE  ContextHandle,
                                               _In_ PUNICODE_STRING TargetName,
                                               _Out_ PULONG         BufferSize,
                                               _Outptr_result_bytebuffer_(*BufferSize)
                                                   PVOID* Buffer)
{
    LogMessage("[AP-STUB] SpGetRemoteCredGuardLogonBuffer Called");
    if (BufferSize)
        *BufferSize = 0;
    if (Buffer)
        *Buffer = nullptr;
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS NTAPI SpGetRemoteCredGuardSupplementalCreds(
    _In_ LSA_SEC_HANDLE CredentialHandle, _In_ PUNICODE_STRING TargetName,
    _Out_ PULONG                                              SupplementalCredsSize,
    _Outptr_result_bytebuffer_(*SupplementalCredsSize) PVOID* SupplementalCreds)
{
    LogMessage("[AP-STUB] SpGetRemoteCredGuardSupplementalCreds Called");
    if (SupplementalCredsSize)
        *SupplementalCredsSize = 0;
    if (SupplementalCreds)
        *SupplementalCreds = nullptr;
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS NTAPI SpGetTbalSupplementalCreds(_In_ PUNICODE_STRING Username,
                                          _Out_ PULONG         SupplementalCredsSize,
                                          _Outptr_result_bytebuffer_(*SupplementalCredsSize)
                                              PVOID* SupplementalCreds)
{
    LogMessage("[AP-STUB] SpGetTbalSupplementalCreds Called");
    if (SupplementalCredsSize)
        *SupplementalCredsSize = 0;
    if (SupplementalCreds)
        *SupplementalCreds = nullptr;
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS NTAPI SpExtractTargetInfo(_In_ LSA_SEC_HANDLE                      CredentialHandle,
                                   _In_reads_bytes_(TargetInfoLength) PVOID TargetInfo,
                                   _In_ ULONG TargetInfoLength, _Out_ PVOID* ExtractedTargetInfo)
{
    LogMessage("[AP-STUB] SpExtractTargetInfo Called");
    if (ExtractedTargetInfo)
        *ExtractedTargetInfo = nullptr;
    return STATUS_NOT_SUPPORTED;
}