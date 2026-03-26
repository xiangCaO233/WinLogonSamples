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


NTSTATUS UserNameToToken(__in LSA_UNICODE_STRING*         AccountName,
                         __out LSA_TOKEN_INFORMATION_V1** Token, __out PNTSTATUS SubStatus)
{
    const LARGE_INTEGER Forever{
        .LowPart  = 0xFFFFFFFF,  // unsigned
        .HighPart = 0x7FFFFFFF,  // signed
    };

    // convert username to zero-terminated string
    std::wstring username = ToWstring(*AccountName);

    auto* token =
        (LSA_TOKEN_INFORMATION_V1*)FunctionTable.AllocateLsaHeap(sizeof(LSA_TOKEN_INFORMATION_V1));

    token->ExpirationTime = Forever;

    PSID userSid = nullptr;
    {
        // configure "User"
        if (!NameToSid(username.c_str(), &userSid))
            return STATUS_FAIL_FAST_EXCEPTION;

        LogMessage("  User.User: %ls", username.c_str());
        token->User.User = {
            .Sid        = userSid,
            .Attributes = 0,
        };
    }

    {
        // configure "Groups"
        DWORD               NumberOfGroups = 0;
        GROUP_USERS_INFO_1* pGroupInfo     = nullptr;
        if (!GetGroups(username.c_str(), &pGroupInfo, &NumberOfGroups))
        {
            return STATUS_FAIL_FAST_EXCEPTION;
        }
        LogMessage("  NumberOfGroups: %u", NumberOfGroups);

        DWORD               NumberOfLocalGroups = 0;
        GROUP_USERS_INFO_0* pLocalGroupInfo     = nullptr;
        if (!GetLocalGroups(username.c_str(), &pLocalGroupInfo, &NumberOfLocalGroups))
        {
            return STATUS_FAIL_FAST_EXCEPTION;
        }
        LogMessage("  NumberOfLocalGroups: %u", NumberOfLocalGroups);

        TOKEN_GROUPS* tokenGroups = (TOKEN_GROUPS*)FunctionTable.AllocateLsaHeap(
            FIELD_OFFSET(TOKEN_GROUPS, Groups[NumberOfGroups + NumberOfLocalGroups]));
        tokenGroups->GroupCount = NumberOfGroups + NumberOfLocalGroups;
        for (size_t i = 0; i < NumberOfGroups; i++)
        {
            NameToSid(pGroupInfo[i].grui1_name, &tokenGroups->Groups[i].Sid);

            tokenGroups->Groups[i].Attributes = pGroupInfo[i].grui1_attributes;
        }
        for (size_t i = 0; i < NumberOfLocalGroups; i++)
        {
            NameToSid(pLocalGroupInfo[i].grui0_name, &tokenGroups->Groups[NumberOfGroups + i].Sid);

            // get the attributes of group since pLocalGroupInfo doesn't contain attributes
            if (*GetSidSubAuthority(tokenGroups->Groups[NumberOfGroups + i].Sid, 0) !=
                SECURITY_BUILTIN_DOMAIN_RID)
                tokenGroups->Groups[NumberOfGroups + i].Attributes =
                    SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT;
            else
                tokenGroups->Groups[NumberOfGroups + i].Attributes = 0;
        }

        token->Groups = tokenGroups;
    }

    GetPrimaryGroupSidFromUserSid(userSid, &token->PrimaryGroup.PrimaryGroup);

    // --- 1. 特权处理 (独立分配内存) ---
    {
        LUID_AND_ATTRIBUTES requiredPrivs[2];
        bool                privOk = true;

        if (!LookupPrivilegeValueW(nullptr, L"SeChangeNotifyPrivilege", &requiredPrivs[0].Luid))
            privOk = false;
        if (!LookupPrivilegeValueW(nullptr, L"SeImpersonatePrivilege", &requiredPrivs[1].Luid))
            privOk = false;

        if (privOk)
        {
            requiredPrivs[0].Attributes = SE_PRIVILEGE_ENABLED;
            requiredPrivs[1].Attributes = SE_PRIVILEGE_ENABLED;

            // 分配内存：sizeof(TOKEN_PRIVILEGES) 已经包含了一个 LUID_AND_ATTRIBUTES
            DWORD privSize = sizeof(TOKEN_PRIVILEGES) + (2 - 1) * sizeof(LUID_AND_ATTRIBUTES);
            TOKEN_PRIVILEGES* pPrivs = (TOKEN_PRIVILEGES*)FunctionTable.AllocateLsaHeap(privSize);

            if (pPrivs)
            {
                pPrivs->PrivilegeCount = 2;
                memcpy(pPrivs->Privileges, requiredPrivs, sizeof(requiredPrivs));
                token->Privileges = pPrivs;
            }
        }
        else
        {
            LogMessage("Error: LookupPrivilegeValueW failed");
            token->Privileges = nullptr;
        }
    }

    // TOKEN_PRIVILEGES Privileges not currently configured
    // token->Privileges = nullptr;

    // --- 2. 所有者处理 (必须 Deep Copy，严禁直接赋值指针) ---
    {
        DWORD sidLen       = GetLengthSid(userSid);
        token->Owner.Owner = (PSID)FunctionTable.AllocateLsaHeap(sidLen);
        if (token->Owner.Owner)
        {
            CopySid(sidLen, token->Owner.Owner, userSid);
        }
    }
    // PSID Owner not currently configured
    // token->Owner.Owner = (PSID) nullptr;

    // 3. 设置 DefaultDacl (核心中的核心)
    // 这个 DACL 至少要允许用户自己拥有全权，允许系统 (SYSTEM) 拥有全权
    PACL             pDacl = NULL;
    EXPLICIT_ACCESSW ea[2] = {};

    // 允许用户自己
    ea[0].grfAccessPermissions = GENERIC_ALL;
    ea[0].grfAccessMode        = SET_ACCESS;
    ea[0].grfInheritance       = NO_INHERITANCE;
    ea[0].Trustee.TrusteeForm  = TRUSTEE_IS_SID;
    ea[0].Trustee.ptstrName    = (LPWSTR)userSid;

    // 允许 SYSTEM 组
    PSID                     systemSid = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuth    = SECURITY_NT_AUTHORITY;
    AllocateAndInitializeSid(
        &ntAuth, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &systemSid);

    ea[1].grfAccessPermissions = GENERIC_ALL;
    ea[1].grfAccessMode        = SET_ACCESS;
    ea[1].grfInheritance       = NO_INHERITANCE;
    ea[1].Trustee.TrusteeForm  = TRUSTEE_IS_SID;
    ea[1].Trustee.ptstrName    = (LPWSTR)systemSid;

    SetEntriesInAclW(2, ea, NULL, &pDacl);

    // 拷贝到 LSA 堆
    DWORD daclSize                 = pDacl->AclSize;
    token->DefaultDacl.DefaultDacl = (PACL)FunctionTable.AllocateLsaHeap(daclSize);
    memcpy(token->DefaultDacl.DefaultDacl, pDacl, daclSize);

    LocalFree(pDacl);
    FreeSid(systemSid);
    // PACL DefaultDacl not currently configured
    // token->DefaultDacl.DefaultDacl = nullptr;

    // assign outputs
    *Token     = token;
    *SubStatus = STATUS_SUCCESS;
    return STATUS_SUCCESS;
}
