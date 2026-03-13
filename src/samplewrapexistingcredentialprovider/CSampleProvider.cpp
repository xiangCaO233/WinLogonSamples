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
#include "CSampleCredential.h"
#include "guid.h"

/**
 * @brief 构造函数。
 * @details 初始化成员变量，并增加 DLL 全局引用计数，防止 DLL 被意外卸载。
 */
CSampleProvider::CSampleProvider()
    : _cRef(1)
{
    DllAddRef();  // 增加 DLL 引用计数

    _rgpCredentials    = NULL;  // 凭据实例数组指针
    _dwCredentialCount = 0;     // 磁贴数量

    _pWrappedProvider         = NULL;  // 指向内置密码提供程序的指针
    _dwWrappedDescriptorCount = 0;     // 内置提供程序的 UI 字段总数
}

/**
 * @brief 析构函数。
 * @details 负责释放所有分配的资源，包括创建的磁贴和内置提供程序实例。
 */
CSampleProvider::~CSampleProvider()
{
    _CleanUpAllCredentials();  // 清理所有的磁贴实例

    if (_pWrappedProvider)
    {
        _pWrappedProvider->Release();  // 释放内置提供程序
    }

    DllRelease();  // 减少 DLL 引用计数
}

/**
 * @brief 清理所有凭据实例。
 * @details 遍历指针数组，释放每一个 ICredentialProviderCredential 对象。
 */
void CSampleProvider::_CleanUpAllCredentials()
{
    if (_rgpCredentials != NULL)
    {
        for (DWORD lcv = 0; lcv < _dwCredentialCount; lcv++)
        {
            if (_rgpCredentials[lcv] != NULL)
            {
                _rgpCredentials[lcv]->Release();  // 调用磁贴对象的 Release
                _rgpCredentials[lcv] = NULL;
            }
        }
        delete[] _rgpCredentials;  // 释放指针数组本身
        _rgpCredentials = NULL;
    }
}

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

/**
 * @brief 注册事件回调。
 * @param[in] pcpe 事件接口指针。
 * @param[in] upAdviseContext 上下文 ID。
 */
HRESULT CSampleProvider::Advise(__in ICredentialProviderEvents* pcpe, __in UINT_PTR upAdviseContext)
{
    HRESULT hr = E_UNEXPECTED;
    if (_pWrappedProvider != NULL)
    {
        // 转发给内置提供程序，以便它能触发 UI 刷新（如用户切换等事件）
        hr = _pWrappedProvider->Advise(pcpe, upAdviseContext);
    }
    return hr;
}

/**
 * @brief 取消注册事件回调。
 */
HRESULT CSampleProvider::UnAdvise()
{
    HRESULT hr = E_UNEXPECTED;
    if (_pWrappedProvider != NULL)
    {
        hr = _pWrappedProvider->UnAdvise();
    }
    return hr;
}

/**
 * @brief 获取总的 UI 字段数量。
 *
 * @details
 * 总数量 = 内置密码程序的字段数 + 我们自定义的字段数 (SFI_NUM_FIELDS)。
 *
 * @param[out] pdwCount 返回总字段数。
 */
HRESULT CSampleProvider::GetFieldDescriptorCount(__out DWORD* pdwCount)
{
    HRESULT hr = E_UNEXPECTED;

    if (_pWrappedProvider != NULL)
    {
        // 1. 获取内置提供程序的字段数（通常是头像、用户名、密码、提交按钮等）
        hr = _pWrappedProvider->GetFieldDescriptorCount(&(_dwWrappedDescriptorCount));
        if (SUCCEEDED(hr))
        {
            // 2. 总数 = 内置数 + 2（我们在 common.h 定义的标签和下拉框）
            *pdwCount = _dwWrappedDescriptorCount + SFI_NUM_FIELDS;
        }
    }

    return hr;
}

/**
 * @brief 获取特定索引的字段描述符。
 *
 * @details
 * 本方法实现了 UI 控件的逻辑拼接。
 *
 * @param[in]  dwIndex 控件索引。
 * @param[out] ppcpfd  返回描述符。
 */
HRESULT CSampleProvider::GetFieldDescriptorAt(
    __in DWORD dwIndex, __deref_out CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd)
{
    HRESULT hr = E_UNEXPECTED;

    if (_pWrappedProvider != NULL && ppcpfd != NULL)
    {
        // A. 如果索引属于内置程序，直接转发请求
        if (dwIndex < _dwWrappedDescriptorCount)
        {
            hr = _pWrappedProvider->GetFieldDescriptorAt(dwIndex, ppcpfd);
        }
        // B. 如果索引超出了内置程序，说明是我们要自定义的控件
        else
        {
            // 1. 计算出在我们自定义数组中的相对索引
            dwIndex -= _dwWrappedDescriptorCount;

            if (dwIndex < SFI_NUM_FIELDS)
            {
                // 2. 从 common.h 定义的静态数组中拷贝描述符
                hr = FieldDescriptorCoAllocCopy(s_rgCredProvFieldDescriptors[dwIndex], ppcpfd);

                // 3. 关键：修正 FieldID。ID 必须是全局唯一的，所以要加上内置程序的偏移量。
                (*ppcpfd)->dwFieldID += _dwWrappedDescriptorCount;
            }
            else
            {
                hr = E_INVALIDARG;
            }
        }
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

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