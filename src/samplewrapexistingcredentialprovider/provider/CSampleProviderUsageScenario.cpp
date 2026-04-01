#include "CSampleProvider.h"
#include "guid.h"
#include "helpers.h"

// 增加一个辅助函数来打印 GUID
std::wstring GuidToString(REFGUID guid)
{
    LPOLESTR szGuid = NULL;
    StringFromCLSID(guid, &szGuid);
    std::wstring res(szGuid);
    CoTaskMemFree(szGuid);
    return res;
}

// 1. 手动定义你在 Win7 注册表中看到的这个 PasswordProvider GUID
static const GUID CLSID_Win7_Real_PasswordProvider = {
    0x6f45dc1e, 0x5384, 0x457a, {0xbc, 0x13, 0x2c, 0xd8, 0x1b, 0x0d, 0x28, 0xed}};

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
    WriteLog(L"SetUsageScenario Start");
    HRESULT hr = S_OK;

    // 1. 如果还没有内置提供程序，则创建一个。
    // 我们包装的是系统的密码提供程序，它负责枚举本地或域用户。
    if (m_wrappedProvider == NULL)
    {
        hr = CoCreateInstance(
#ifdef BUILD_FOR_WIN7
            CLSID_V1PasswordCredentialProvider,
#else
            CLSID_PasswordCredentialProvider,
#endif
            NULL,
            CLSCTX_ALL,
            IID_PPV_ARGS(&m_wrappedProvider));
        if (FAILED(hr))
        {
            WriteLog(L"CoCreateInstance Failed! HR = 0x" + std::to_wstring(hr));
            // 关键：打印你到底在尝试创建哪一个 GUID
            WriteLog(L"Target Internal GUID: " + GuidToString(CLSID_V1PasswordCredentialProvider));
            // 如果类未注册，尝试在 Win7 下查找这个特定 GUID
            // {60b27930-1ead-40dc-ab10-73d13583607e}
        }
    }

    // 2. 将场景信息转发给内置提供程序，让它也进入对应状态。
    if (SUCCEEDED(hr))
    {

        hr = m_wrappedProvider->SetUsageScenario(cpus, dwFlags);
    }

    // 3. 失败处理：如果初始化失败，立即释放
    if (FAILED(hr))
    {
        if (m_wrappedProvider != NULL)
        {
            m_wrappedProvider->Release();
            m_wrappedProvider = NULL;
        }
    }

    WriteLog(L"SetUsageScenario End hr = " + std::to_wstring(hr));

    return hr;
}
