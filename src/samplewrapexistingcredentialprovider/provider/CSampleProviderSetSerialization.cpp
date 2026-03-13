#include "CSampleProvider.h"

/**
 * @brief 设置序列化数据（转发给内置提供程序）。
 */
HRESULT CSampleProvider::SetSerialization(
    __in const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs)
{
    HRESULT hr = E_UNEXPECTED;

    if (_pWrappedProvider != NULL)
    {
        // 直接转发，让内置程序去处理预填充的用户名或密码
        hr = _pWrappedProvider->SetSerialization(pcpcs);
    }

    return hr;
}
