/**
 * @file CSampleProvider.cpp
 * @brief 示例凭据提供程序的管理器实现。
 *
 * @details
 * 该类实现了 ICredentialProvider。
 * 核心设计思想：包装（Wrap）内置的密码提供程序 (CLSID_PasswordCredentialProvider)。
 * 我们将几乎所有的请求都转发给内置提供程序，仅在处理我们自定义的控件字段时才介入。
 * 这样做的好处是：我们可以利用系统原有的用户枚举逻辑，同时添加自定义功能。
 */

#include <credentialprovider.h>
#include "CSampleProvider.h"
#include "guid.h"

/**
 * @brief 构造函数。
 * @details 初始化成员变量，并增加 DLL 全局引用计数，防止 DLL 被意外卸载。
 */
CSampleProvider::CSampleProvider()
    : _cRef(1)
    , m_wrappedCredentialCount(0)
    , m_wrappedProvider(nullptr)
    , m_wrappedDescriptorCount(0)
{
    DllAddRef();  // 增加 DLL 引用计数
}

/**
 * @brief 析构函数。
 * @details 负责释放所有分配的资源，包括创建的磁贴和内置提供程序实例。
 */
CSampleProvider::~CSampleProvider()
{
    CleanUpAllCredentials();  // 清理所有的磁贴实例

    if (m_wrappedProvider)
    {
        m_wrappedProvider->Release();  // 释放内置提供程序
    }

    DllRelease();  // 减少 DLL 引用计数
}

/**
 * @brief 清理所有凭据实例。
 * @details 遍历指针数组，释放每一个 ICredentialProviderCredential 对象。
 */
void CSampleProvider::CleanUpAllCredentials()
{
    m_sample_credentials.clear();
}

/**
 * @brief 供类工厂调用的全局实例创建函数。
 * @param[in]  riid 请求的接口 ID。
 * @param[out] ppv  接收实例指针。
 */
HRESULT CSample_CreateInstance(__in REFIID riid, __deref_out void** ppv)
{
    HRESULT hr;

    // 1. 创建 CSampleProvider 实例
    CSampleProvider* pProvider = new CSampleProvider();

    if (pProvider)
    {
        // 2. 查询请求的接口
        hr = pProvider->QueryInterface(riid, ppv);
        // 3. 释放构造函数中初始的引用计数（QueryInterface 会增加计数）
        pProvider->Release();
    }
    else
    {
        hr = E_OUTOFMEMORY;
    }

    return hr;
}