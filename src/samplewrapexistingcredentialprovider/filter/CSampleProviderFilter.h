#pragma once

#include <credentialprovider.h>

class CSampleFilter : public ICredentialProviderFilter
{
  public:
    IFACEMETHODIMP Filter(__in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, __in DWORD dwFlags,
                          __in_ecount(cProviders) GUID*    rgclsidProviders,
                          __inout_ecount(cProviders) BOOL* rgbAllow,
                          __in DWORD                       cProviders) override;

    // UpdateRemoteCredential 默认返回 E_NOTIMPL 即可
    IFACEMETHODIMP UpdateRemoteCredential(
        /* [annotation][in] */
        _In_ const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcsIn,
        /* [annotation][out] */
        _Out_ CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcsOut) override
    {
        return E_NOTIMPL;
    }
};