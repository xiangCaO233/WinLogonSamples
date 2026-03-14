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
    // // 1. 初始化输出参数
    // *pdwCount               = 0;
    // *pdwDefault             = 0;
    // *pbAutoLogonWithDefault = FALSE;

    // if (_pWrappedProvider == nullptr)
    //     return E_UNEXPECTED;

    // // 2. 清理旧数据：vector 的 clear 会自动调用内部 ComPtr 的 Release
    // m_sample_credentials.clear();

    // DWORD dwCount    = 0;
    // DWORD dwDefault  = 0;
    // BOOL  bAutoLogon = FALSE;

    // // 3. 获取内置提供程序的磁贴信息
    // HRESULT hr = _pWrappedProvider->GetCredentialCount(&dwCount, &dwDefault, &bAutoLogon);

    // if (SUCCEEDED(hr))
    // {
    //     // 预留空间，提高性能
    //     m_sample_credentials.reserve(dwCount);

    //     for (DWORD i = 0; i < dwCount; i++)
    //     {
    //         // 4. 创建我们的包装类实例
    //         // 注意：这里使用 new 创建，并立即交给 ComPtr 管理
    //         ComPtr<CSampleCredential> pMyCredential(new (std::nothrow) CSampleCredential());

    //         if (pMyCredential)
    //         {
    //             // 5. 获取对应的内置磁贴
    //             ComPtr<ICredentialProviderCredential> pWrappedCred;
    //             hr = _pWrappedProvider->GetCredentialAt(i, &pWrappedCred);

    //             if (SUCCEEDED(hr))
    //             {
    //                 // 6. 初始化我们的包装磁贴
    //                 hr = pMyCredential->Initialize(s_rgCredProvFieldDescriptors,
    //                                                s_rgFieldStatePairs,
    //                                                pWrappedCred.Get(),  // 获取原始指针传进去
    //                                                _dwWrappedDescriptorCount);

    //                 if (SUCCEEDED(hr))
    //                 {
    //                     // 7. 成功后存入 vector
    //                     m_sample_credentials.push_back(pMyCredential);
    //                 }
    //             }
    //         }
    //         else
    //         {
    //             hr = E_OUTOFMEMORY;
    //         }

    //         if (FAILED(hr))
    //             break;  // 如果其中一个失败，跳出循环
    //     }
    // }

    // // 8. 最终赋值
    // if (SUCCEEDED(hr))
    // {
    //     *pdwCount               = static_cast<DWORD>(m_sample_credentials.size());
    //     *pdwDefault             = dwDefault;
    //     *pbAutoLogonWithDefault = bAutoLogon;
    // }
    // else
    // {
    //     // 如果中间失败了，vector 析构时会自动清理已创建的对象
    //     m_sample_credentials.clear();
    // }

    // return hr;

    HRESULT hr                    = E_UNEXPECTED;
    DWORD   dwDefault             = 0;
    BOOL    bAutoLogonWithDefault = FALSE;

    if (_pWrappedProvider != NULL)
    {
        // 1. 如果之前已经分配过磁贴数组，先清理旧的。
        if (_rgpCredentials != NULL)
        {
            _CleanUpAllCredentials();
        }

        DWORD count;
        // 获取字段总数以确保后续初始化正确
        hr = GetFieldDescriptorCount(&(count));

        if (SUCCEEDED(hr))
        {
            // 2. 核心：获取内置提供程序的磁贴数量（例如：找到了 3 个用户）
            hr = _pWrappedProvider->GetCredentialCount(
                &(_dwCredentialCount), &(dwDefault), &(bAutoLogonWithDefault));

            if (SUCCEEDED(hr))
            {
                // 3. 为我们的包装类分配指针数组
                _rgpCredentials = new CSampleCredential*[_dwCredentialCount];
                if (_rgpCredentials != NULL)
                {
                    // 4. 循环为每个内置用户创建一个包装磁贴
                    for (DWORD lcv = 0; SUCCEEDED(hr) && (lcv < _dwCredentialCount); lcv++)
                    {
                        _rgpCredentials[lcv] = new CSampleCredential();
                        if (_rgpCredentials[lcv] != NULL)
                        {
                            // 5. 获取内置程序的第 lcv 个具体磁贴对象
                            ICredentialProviderCredential* pCredential;
                            hr = _pWrappedProvider->GetCredentialAt(lcv, &(pCredential));

                            if (SUCCEEDED(hr))
                            {
                                // 6. 初始化包装类：
                                // 将内置磁贴指针 (pCredential) 传进去，
                                // 并传入自定义的字段描述符和状态。
                                hr = _rgpCredentials[lcv]->Initialize(s_rgCredProvFieldDescriptors,
                                                                      s_rgFieldStatePairs,
                                                                      pCredential,
                                                                      _dwWrappedDescriptorCount);

                                // 失败清理逻辑
                                if (FAILED(hr))
                                {
                                    for (lcv = 0; lcv < _dwCredentialCount; lcv++)
                                    {
                                        if (_rgpCredentials[lcv] != NULL)
                                        {
                                            _rgpCredentials[lcv]->Release();
                                            _rgpCredentials[lcv] = NULL;
                                        }
                                    }
                                }
                                pCredential->Release();  // 释放本地引用的指针
                            }
                        }
                        else
                        {
                            hr = E_OUTOFMEMORY;
                        }
                    }
                }
                else
                {
                    hr = E_OUTOFMEMORY;
                }
            }
        }
    }

    // 最终赋值输出参数
    if (FAILED(hr))
    {
        if (_rgpCredentials != NULL)
        {
            delete _rgpCredentials;
            _rgpCredentials = NULL;
        }
    }
    else
    {
        *pdwCount               = _dwCredentialCount;
        *pdwDefault             = dwDefault;
        *pbAutoLogonWithDefault = bAutoLogonWithDefault;
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
    // // 1. 参数校验
    // if (ppcpc == nullptr)
    //     return E_POINTER;
    // *ppcpc = nullptr;

    // if (dwIndex >= m_sample_credentials.size())
    // {
    //     return E_INVALIDARG;
    // }

    // // 2. 从 vector 中取出 ComPtr 并复制给返回指针
    // // CopyTo 内部会自动调用 AddRef()，这是 COM 函数返回指针的标准要求
    // return m_sample_credentials[dwIndex].CopyTo(ppcpc);

    HRESULT hr;

    // 参数校验：索引必须在范围内，数组不能为空
    if ((dwIndex < _dwCredentialCount) && (ppcpc != NULL) && (_rgpCredentials != NULL) &&
        (_rgpCredentials[dwIndex] != NULL))
    {
        // 返回我们包装后的磁贴实例的接口指针
        hr = _rgpCredentials[dwIndex]->QueryInterface(IID_ICredentialProviderCredential,
                                                      reinterpret_cast<void**>(ppcpc));
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}
