#include "CSampleProviderFilter.h"

IFACEMETHODIMP CSampleFilter::Filter(__in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
                                     __in DWORD                              dwFlags,
                                     __in_ecount(cProviders) GUID*           rgclsidProviders,
                                     __inout_ecount(cProviders) BOOL*        rgbAllow,
                                     __in DWORD                              cProviders)
{
    for (DWORD i = 0; i < cProviders; i++)
    {
        // 屏蔽掉 Windows 原生的密码磁贴
        // 注意：不影响我们自己在 Provider 内部 CoCreateInstance 加载它！
        if (rgclsidProviders[i] == CLSID_PasswordCredentialProvider)
        {
            rgbAllow[i] = FALSE;
        }
    }
    return S_OK;
}