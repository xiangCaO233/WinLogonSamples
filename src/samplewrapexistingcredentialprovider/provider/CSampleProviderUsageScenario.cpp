#include "CSampleProvider.h"

/**
 * @brief 设置使用场景。
 *
 * @details
 * 1. 使用 CoCreateInstance 加载内置的密码提供程序 (CLSID_PasswordCredentialProvider)。
 * 2. 将场景（登录、解锁等）和标志位转发给它。
 *
 * @param[in] cpus    使用场景（CPUS_LOGON 等）。
 * @param[in] dwFlags 场景标志位。
 * @return HRESULT。
 */
HRESULT CSampleProvider::SetUsageScenario(__in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
                                          __in DWORD                              dwFlags)
{
    HRESULT hr = S_OK;

    // 1. 如果还没有内置提供程序，则创建一个。
    // 我们包装的是系统的密码提供程序，它负责枚举本地或域用户。
    if (_pWrappedProvider == NULL)
    {
        hr = CoCreateInstance(
            CLSID_PasswordCredentialProvider, NULL, CLSCTX_ALL, IID_PPV_ARGS(&_pWrappedProvider));
    }

    // 2. 将场景信息转发给内置提供程序，让它也进入对应状态。
    if (SUCCEEDED(hr))
    {
        hr = _pWrappedProvider->SetUsageScenario(cpus, dwFlags);
    }

    // 3. 失败处理：如果初始化失败，立即释放
    if (FAILED(hr))
    {
        if (_pWrappedProvider != NULL)
        {
            _pWrappedProvider->Release();
            _pWrappedProvider = NULL;
        }
    }

    return hr;
}
