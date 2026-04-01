#include "PrepareToken.hpp"
#include <Lm.h>
#include <accctrl.h>
#include <aclapi.h>
#include "Utils.hpp"

#pragma comment(lib, "Netapi32.lib")


static bool NameToSid(const wchar_t* username, PSID* userSid)
{
    DWORD        lengthSid               = 0;
    SID_NAME_USE Use                     = {};
    DWORD        referencedDomainNameLen = 0;
    BOOL         res                     = LookupAccountNameW(
        nullptr, username, nullptr, &lengthSid, nullptr, &referencedDomainNameLen, &Use);

    *userSid                      = (PSID)FunctionTable.AllocateLsaHeap(lengthSid);
    wchar_t* referencedDomainName = (wchar_t*)FunctionTable.AllocateLsaHeap(
        sizeof(wchar_t) * referencedDomainNameLen);  // throwaway string
    res = LookupAccountNameW(nullptr,
                             username,
                             *userSid,
                             &lengthSid,
                             referencedDomainName,
                             &referencedDomainNameLen,
                             &Use);
    if (!res)
    {
        DWORD err = GetLastError();
        LogMessage("  LookupAccountNameW failed (err %u)", err);
        return false;
    }

    FunctionTable.FreeLsaHeap(referencedDomainName);
    return true;
}

static void GetPrimaryGroupSidFromUserSid(PSID userSID, PSID* primaryGroupSID)
{
    // duplicate the user sid
    *primaryGroupSID = (PSID)FunctionTable.AllocateLsaHeap(GetLengthSid(userSID));
    CopySid(GetLengthSid(userSID), *primaryGroupSID, userSID);

    // replace the last subauthority by DOMAIN_GROUP_RID_USERS
    // https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers
    // (last SubAuthority = RID
    // https://learn.microsoft.com/nb-no/windows/win32/secauthz/well-known-sids
    UCHAR SubAuthorityCount = *GetSidSubAuthorityCount(*primaryGroupSID);
    *GetSidSubAuthority(*primaryGroupSID, SubAuthorityCount - 1) = DOMAIN_GROUP_RID_USERS;
}

static bool GetGroups(const wchar_t* UserName, GROUP_USERS_INFO_1** lpGroupInfo,
                      DWORD* pTotalEntries)
{
    DWORD NumberOfEntries = 0;
    DWORD status          = NetUserGetGroups(NULL,
                                    UserName,
                                    1,
                                    (BYTE**)lpGroupInfo,
                                    MAX_PREFERRED_LENGTH,
                                    &NumberOfEntries,
                                    pTotalEntries);
    if (status != NERR_Success)
    {
        LogMessage("ERROR: NetUserGetGroups failed with error %u", status);
        return false;
    }
    return true;
}

static bool GetLocalGroups(const wchar_t* UserName, GROUP_USERS_INFO_0** lpGroupInfo,
                           DWORD* pTotalEntries)
{
    DWORD NumberOfEntries = 0;
    DWORD status          = NetUserGetLocalGroups(NULL,
                                         UserName,
                                         0,
                                         0,
                                         (BYTE**)lpGroupInfo,
                                         MAX_PREFERRED_LENGTH,
                                         &NumberOfEntries,
                                         pTotalEntries);
    if (status != NERR_Success)
    {
        LogMessage("ERROR: NetUserGetLocalGroups failed with error %u", status);
        return false;
    }
    return true;
}

NTSTATUS UserNameToToken(__in LSA_UNICODE_STRING* AccountName,
                         __in LUID* LogonId,  // 必须传入 LsaApLogonUser 生成的 LogonId
                         __out LSA_TOKEN_INFORMATION_V1** Token, __out PNTSTATUS SubStatus)
{
    LARGE_INTEGER Forever;
    Forever.LowPart       = 0xFFFFFFFF;
    Forever.HighPart      = 0x7FFFFFFF;
    std::wstring username = ToWstring(*AccountName);

    auto* token =
        (LSA_TOKEN_INFORMATION_V1*)FunctionTable.AllocateLsaHeap(sizeof(LSA_TOKEN_INFORMATION_V1));
    if (!token)
        return STATUS_INSUFFICIENT_RESOURCES;

    token->ExpirationTime = Forever;

    // 1. 获取 User SID
    PSID userSid = nullptr;
    if (!NameToSid(username.c_str(), &userSid))
        return STATUS_FAIL_FAST_EXCEPTION;
    token->User.User.Sid        = userSid;
    token->User.User.Attributes = 0;

    // 2. 处理组信息 (关键：包含 Logon SID)
    {
        DWORD               NumberOfGroups = 0;
        GROUP_USERS_INFO_1* pGroupInfo     = nullptr;
        GetGroups(username.c_str(), &pGroupInfo, &NumberOfGroups);

        DWORD               NumberOfLocalGroups = 0;
        GROUP_USERS_INFO_0* pLocalGroupInfo     = nullptr;
        GetLocalGroups(username.c_str(), &pLocalGroupInfo, &NumberOfLocalGroups);

        // 我们现在需要 9 个额外组
        // 1-8: 你之前定义的那些
        // 9: Logon SID (S-1-5-5-X-Y)
        DWORD ExtraGroups = 9;
        DWORD TotalGroups = NumberOfGroups + NumberOfLocalGroups + ExtraGroups;

        TOKEN_GROUPS* tokenGroups = (TOKEN_GROUPS*)FunctionTable.AllocateLsaHeap(
            FIELD_OFFSET(TOKEN_GROUPS, Groups[TotalGroups]));
        if (!tokenGroups)
            return STATUS_INSUFFICIENT_RESOURCES;

        DWORD currentIdx = 0;

        // 拷贝本地和域组
        for (DWORD i = 0; i < NumberOfGroups; i++)
        {
            if (NameToSid(pGroupInfo[i].grui1_name, &tokenGroups->Groups[currentIdx].Sid))
            {
                tokenGroups->Groups[currentIdx].Attributes =
                    SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT;
                currentIdx++;
            }
        }
        for (DWORD i = 0; i < NumberOfLocalGroups; i++)
        {
            if (NameToSid(pLocalGroupInfo[i].grui0_name, &tokenGroups->Groups[currentIdx].Sid))
            {
                tokenGroups->Groups[currentIdx].Attributes =
                    SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT;
                currentIdx++;
            }
        }

        SID_IDENTIFIER_AUTHORITY ntAuth        = SECURITY_NT_AUTHORITY;
        SID_IDENTIFIER_AUTHORITY worldAuth     = SECURITY_WORLD_SID_AUTHORITY;
        SID_IDENTIFIER_AUTHORITY localAuth     = SECURITY_LOCAL_SID_AUTHORITY;
        SID_IDENTIFIER_AUTHORITY integrityAuth = SECURITY_MANDATORY_LABEL_AUTHORITY;

        auto AddWellKnownSid =
            [&](SID_IDENTIFIER_AUTHORITY& auth, BYTE subCount, DWORD rid1, DWORD rid2, DWORD attr)
        {
            PSID pSidTemp = nullptr;
            if (AllocateAndInitializeSid(&auth, subCount, rid1, rid2, 0, 0, 0, 0, 0, 0, &pSidTemp))
            {
                DWORD sidLen                        = GetLengthSid(pSidTemp);
                tokenGroups->Groups[currentIdx].Sid = FunctionTable.AllocateLsaHeap(sidLen);
                if (tokenGroups->Groups[currentIdx].Sid)
                {
                    CopySid(sidLen, tokenGroups->Groups[currentIdx].Sid, pSidTemp);
                    tokenGroups->Groups[currentIdx].Attributes = attr;
                    currentIdx++;
                }
                FreeSid(pSidTemp);
            }
        };

        // --- 添加 Logon SID (核心修复) ---
        // 格式：S-1-5-5-LogonIdHigh-LogonIdLow
        PSID pLogonSidTemp = nullptr;
        if (AllocateAndInitializeSid(&ntAuth,
                                     3,
                                     SECURITY_LOGON_IDS_RID,
                                     LogonId->HighPart,
                                     LogonId->LowPart,
                                     0,
                                     0,
                                     0,
                                     0,
                                     0,
                                     &pLogonSidTemp))
        {
            DWORD sidLen                        = GetLengthSid(pLogonSidTemp);
            tokenGroups->Groups[currentIdx].Sid = FunctionTable.AllocateLsaHeap(sidLen);
            if (tokenGroups->Groups[currentIdx].Sid)
            {
                CopySid(sidLen, tokenGroups->Groups[currentIdx].Sid, pLogonSidTemp);
                // Logon SID 必须具备 SE_GROUP_LOGON_ID 属性
                tokenGroups->Groups[currentIdx].Attributes = SE_GROUP_ENABLED |
                                                             SE_GROUP_ENABLED_BY_DEFAULT |
                                                             SE_GROUP_MANDATORY | SE_GROUP_LOGON_ID;
                currentIdx++;
            }
            FreeSid(pLogonSidTemp);
        }

        // 添加其他必要组
        AddWellKnownSid(ntAuth,
                        1,
                        SECURITY_AUTHENTICATED_USER_RID,
                        0,
                        SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY);
        AddWellKnownSid(worldAuth,
                        1,
                        SECURITY_WORLD_RID,
                        0,
                        SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY);
        AddWellKnownSid(ntAuth,
                        1,
                        SECURITY_INTERACTIVE_RID,
                        0,
                        SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY);
        AddWellKnownSid(localAuth,
                        1,
                        SECURITY_LOCAL_RID,
                        0,
                        SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY);
        AddWellKnownSid(ntAuth,
                        1,
                        SECURITY_THIS_ORGANIZATION_RID,
                        0,
                        SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY);
        AddWellKnownSid(
            ntAuth,
            1,
            113,
            0,
            SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY);  // Local Account
        AddWellKnownSid(integrityAuth,
                        1,
                        SECURITY_MANDATORY_MEDIUM_RID,
                        0,
                        SE_GROUP_INTEGRITY | SE_GROUP_INTEGRITY_ENABLED);
        AddWellKnownSid(ntAuth,
                        2,
                        SECURITY_BUILTIN_DOMAIN_RID,
                        DOMAIN_ALIAS_RID_USERS,
                        SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY);

        tokenGroups->GroupCount = currentIdx;
        token->Groups           = tokenGroups;
    }

    // 3. 设置 Primary Group (Users)
    GetPrimaryGroupSidFromUserSid(userSid, &token->PrimaryGroup.PrimaryGroup);

    // 4. 特权处理 (补全标准用户特权)
    {
        const wchar_t* privList[] = {L"SeChangeNotifyPrivilege",
                                     L"SeImpersonatePrivilege",
                                     L"SeIncreaseWorkingSetPrivilege",
                                     L"SeShutdownPrivilege",
                                     L"SeTimeZonePrivilege"};
        int            numPrivs   = ARRAYSIZE(privList);
        DWORD privSize = sizeof(TOKEN_PRIVILEGES) + (numPrivs - 1) * sizeof(LUID_AND_ATTRIBUTES);
        TOKEN_PRIVILEGES* pPrivs = (TOKEN_PRIVILEGES*)FunctionTable.AllocateLsaHeap(privSize);
        if (pPrivs)
        {
            pPrivs->PrivilegeCount = 0;
            for (int i = 0; i < numPrivs; i++)
            {
                if (LookupPrivilegeValueW(
                        nullptr, privList[i], &pPrivs->Privileges[pPrivs->PrivilegeCount].Luid))
                {
                    pPrivs->Privileges[pPrivs->PrivilegeCount].Attributes = SE_PRIVILEGE_ENABLED;
                    pPrivs->PrivilegeCount++;
                }
            }
            token->Privileges = pPrivs;
        }
    }

    // 5. 设置 Owner
    DWORD userSidLen   = GetLengthSid(userSid);
    token->Owner.Owner = (PSID)FunctionTable.AllocateLsaHeap(userSidLen);
    CopySid(userSidLen, token->Owner.Owner, userSid);

    // 6. 设置 Default DACL (核心修正：允许 Logon SID 访问)
    {
        // 我们需要 3 个 ACE: User, System, LogonSID
        PSID logonSid = nullptr;
        // 在 Groups 中找到刚才存进去的 Logon SID
        for (DWORD i = 0; i < token->Groups->GroupCount; i++)
        {
            if (token->Groups->Groups[i].Attributes & SE_GROUP_LOGON_ID)
            {
                logonSid = token->Groups->Groups[i].Sid;
                break;
            }
        }

        PACL             pDacl = NULL;
        EXPLICIT_ACCESSW ea[3] = {};

        // User
        ea[0].grfAccessPermissions = GENERIC_ALL;
        ea[0].grfAccessMode        = SET_ACCESS;
        ea[0].grfInheritance       = NO_INHERITANCE;
        ea[0].Trustee.TrusteeForm  = TRUSTEE_IS_SID;
        ea[0].Trustee.ptstrName    = (LPWSTR)userSid;

        // SYSTEM
        PSID                     sysSid = NULL;
        SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
        AllocateAndInitializeSid(
            &ntAuth, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &sysSid);
        ea[1].grfAccessPermissions = GENERIC_ALL;
        ea[1].grfAccessMode        = SET_ACCESS;
        ea[1].grfInheritance       = NO_INHERITANCE;
        ea[1].Trustee.TrusteeForm  = TRUSTEE_IS_SID;
        ea[1].Trustee.ptstrName    = (LPWSTR)sysSid;

        // Logon SID (至关重要)
        ea[2].grfAccessPermissions = GENERIC_ALL;
        ea[2].grfAccessMode        = SET_ACCESS;
        ea[2].grfInheritance       = NO_INHERITANCE;
        ea[2].Trustee.TrusteeForm  = TRUSTEE_IS_SID;
        ea[2].Trustee.ptstrName    = (LPWSTR)logonSid;

        SetEntriesInAclW(3, ea, NULL, &pDacl);

        DWORD daclSize                 = pDacl->AclSize;
        token->DefaultDacl.DefaultDacl = (PACL)FunctionTable.AllocateLsaHeap(daclSize);
        memcpy(token->DefaultDacl.DefaultDacl, pDacl, daclSize);

        LocalFree(pDacl);
        FreeSid(sysSid);
    }

    *Token     = token;
    *SubStatus = STATUS_SUCCESS;
    return STATUS_SUCCESS;
}