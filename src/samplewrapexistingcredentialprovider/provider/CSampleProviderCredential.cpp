#include "CSampleProvider.h"

/**
 * @brief 获取磁贴（Credential）数量并创建磁贴实例。
 *
 * @details
 * 逻辑：
 * 1. 询问内置提供程序有多少个用户（磁贴）。
 * 2. 为每一个用户创建一个我们的 CSampleCredential 实例。
 * 3. 将内置磁贴包装到我们的磁贴里。
 *
 * @param[out] pdwCount 磁贴总数。
 * @param[out] pdwDefault 默认选中的磁贴索引。
 * @param[out] pbAutoLogonWithDefault 是否自动登录。
 */
HRESULT CSampleProvider::GetCredentialCount(__out DWORD*                     pdwCount,
                                            __out_range(<, *pdwCount) DWORD* pdwDefault,
                                            __out BOOL*                      pbAutoLogonWithDefault)
{
    HRESULT hr                    = E_UNEXPECTED;
    DWORD   dwDefault             = 0;
    BOOL    bAutoLogonWithDefault = FALSE;

    if (m_wrappedProvider != NULL)
    {
        // 1. 如果之前已经分配过磁贴数组，先清理旧的。
        CleanUpAllCredentials();

        DWORD count;
        // 获取字段总数以确保后续初始化正确
        hr = GetFieldDescriptorCount(&(count));

        if (SUCCEEDED(hr))
        {
            // 2. 核心：获取内置提供程序的磁贴数量（例如：找到了 3 个用户）
            hr = m_wrappedProvider->GetCredentialCount(
                &(m_wrappedCredentialCount), &(dwDefault), &(bAutoLogonWithDefault));

            if (SUCCEEDED(hr))
            {
                // 3. 预先分配 vector 空间
                m_sample_credentials.reserve(m_wrappedCredentialCount);
                // 4. 循环为每个内置用户创建一个包装磁贴
                for (DWORD lcv = 0; SUCCEEDED(hr) && (lcv < m_wrappedCredentialCount); lcv++)
                {
                    ComPtr<CSampleCredential> pSampleCred;
                    // 注意：由于 CSampleCredential 构造函数将 _cRef 初始化为 1，
                    // 这里我们使用 Attach() 来接管这唯一的引用计数，防止内存泄漏。
                    pSampleCred.Attach(new (std::nothrow) CSampleCredential());

                    if (pSampleCred != nullptr)
                    {
                        // 5. 获取内置程序的第 lcv 个具体磁贴对象
                        ICredentialProviderCredential* pCredential = nullptr;
                        hr = m_wrappedProvider->GetCredentialAt(lcv, &(pCredential));

                        if (SUCCEEDED(hr))
                        {
                            // 6. 初始化包装类：
                            // 将内置磁贴指针 (pCredential) 传进去，并传入自定义的字段描述符和状态。
                            hr = pSampleCred->Initialize(s_rgCredProvFieldDescriptors,
                                                         s_rgFieldStatePairs,
                                                         pCredential,
                                                         m_wrappedDescriptorCount);

                            if (SUCCEEDED(hr))
                            {
                                m_sample_credentials.push_back(std::move(pSampleCred));
                            }

                            pCredential->Release();  // 释放本地引用的指针
                        }
                    }
                    else
                    {
                        hr = E_OUTOFMEMORY;
                    }
                }
                // 如果任何一步失败了，清空创建的内容
                if (FAILED(hr))
                {
                    CleanUpAllCredentials();
                }
            }
        }

        // 最终赋值输出参数
        if (SUCCEEDED(hr))
        {
            *pdwCount               = m_wrappedCredentialCount;
            *pdwDefault             = dwDefault;
            *pbAutoLogonWithDefault = bAutoLogonWithDefault;
            WriteLog(L"内置提供程序返回磁贴总数: " + std::to_wstring(m_wrappedCredentialCount));
        }
    }

    return hr;
}

/**
 * @brief 返回指定索引的磁贴实例。
 * @details LogonUI 会调用此函数来绘制每一个磁贴方块。
 */
HRESULT CSampleProvider::GetCredentialAt(__in DWORD                           dwIndex,
                                         __in ICredentialProviderCredential** ppcpc)
{
    // 1. 参数校验
    if (ppcpc == nullptr)
        return E_POINTER;
    *ppcpc = nullptr;

    if (dwIndex >= m_sample_credentials.size())
    {
        return E_INVALIDARG;
    }

    // 2. 从 vector 中取出 ComPtr 并复制给返回指针
    // CopyTo 内部会自动调用 AddRef()，并且要求转换为指定接口，这是 COM 函数返回指针的标准要求
    return m_sample_credentials[dwIndex].CopyTo(IID_ICredentialProviderCredential,
                                                reinterpret_cast<void**>(ppcpc));
}
