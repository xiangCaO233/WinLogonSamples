/**
 * @file CSampleProvider.h
 * @brief 凭据提供程序管理器类定义。
 *
 * @details CSampleProvider 实现了 ICredentialProvider 接口。
 * 它是 Windows 登录 UI 加载 DLL 后创建的第一个对象。
 * 它的主要任务是：
 * 1. 响应系统的使用场景（登录、解锁、CredUI）。
 * 2. 告诉系统 UI 界面上有多少个控件（字段描述符）。
 * 3. 枚举并提供具体的凭据实例（磁贴）。
 */

#pragma once

#include <credentialprovider.h>
#include <windows.h>
#include <strsafe.h>

#include "../credential/CSampleCredential.h"  // 具体磁贴实例的类定义
#include "helpers.h"
// Windows 现代 COM 智能指针
#include <wrl/client.h>

using Microsoft::WRL::ComPtr;

/**
 * @class CSampleProvider
 * @brief 示例凭据提供程序的主控类。
 */
class CSampleProvider : public ICredentialProvider, public ICredentialProviderSetUserArray
{
  public:
    // --- IUnknown 接口实现 (COM 基础) ---
    // 负责管理对象的生命周期和接口查询

    /**
     * @brief 增加引用计数。
     * @return 增加后的计数。
     */
    IFACEMETHODIMP_(ULONG) AddRef() override
    {
        return ++_cRef;
    }

    /**
     * @brief 减少引用计数。
     * @details 当计数为 0 时，自我销毁。
     */
    IFACEMETHODIMP_(ULONG) Release() override
    {
        LONG cRef = --_cRef;
        if (!cRef)
        {
            delete this;
        }
        return cRef;
    }

    // 实现 ICredentialProviderSetUserArray
    IFACEMETHODIMP SetUserArray(__in ICredentialProviderUserArray* users) override
    {
        HRESULT hr = E_NOTIMPL;
        if (m_wrappedProvider != NULL)
        {
            // 尝试从内置 Provider 中查询该接口
            ICredentialProviderSetUserArray* pSetUserArray;
            hr = m_wrappedProvider->QueryInterface(IID_PPV_ARGS(&pSetUserArray));
            if (SUCCEEDED(hr))
            {
                // 关键：把系统给我们的用户列表，原封不动地转发给内置 Provider
                hr = pSetUserArray->SetUserArray(users);
                pSetUserArray->Release();

                WriteLog(L"成功将 UserArray 转发给内置 Provider");
            }
        }
        return hr;
    }
    /**
     * @brief 接口查询。
     * @details 系统通过此方法确认该对象是否支持 ICredentialProvider 接口。
     */
    IFACEMETHODIMP QueryInterface(__in REFIID riid, __deref_out void** ppv) override
    {
        static const QITAB qit[] = {
            QITABENT(CSampleProvider, ICredentialProvider),              // 暴露给系统的核心接口
            QITABENT(CSampleProvider, ICredentialProviderSetUserArray),  // 新增
            {0},
        };
        return QISearch(this, qit, riid, ppv);
    }

  public:
    // --- ICredentialProvider 核心接口方法 ---

    /**
     * @brief 设置使用场景。
     * @param[in] cpus    当前场景（登录、解锁、CredUI）。
     * @param[in] dwFlags 场景标志（如 CPUS_LOGON）。
     * @details 这是第一个被调用的方法。提供程序根据场景决定是否显示自己。
     */
    IFACEMETHODIMP SetUsageScenario(__in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
                                    __in DWORD                              dwFlags) override;

    /**
     * @brief 设置预填充数据。
     * @param[in] pcpcs 包含序列化凭据数据的指针。
     * @details 当系统从远程桌面（RDP）或其他地方收到凭据信息时，会调用此方法尝试自动填充 UI。
     */
    IFACEMETHODIMP SetSerialization(
        __in const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs) override;

    /**
     * @brief 注册事件回调。
     * @param[in] pcpe 事件处理接口。
     * @param[in] upAdviseContext 上下文标识。
     * @details 当提供程序需要通知系统“磁贴数量变了”或“UI 需要刷新”时，通过 pcpe 回调。
     */
    IFACEMETHODIMP Advise(__in ICredentialProviderEvents* pcpe,
                          __in UINT_PTR                   upAdviseContext) override;

    /**
     * @brief 取消注册事件回调。
     */
    IFACEMETHODIMP UnAdvise() override;

    /**
     * @brief 获取 UI 字段描述符的总数。
     * @param[out] pdwCount 接收字段数量。
     * @details 告诉系统：我的登录界面上有多少个控件（文本框、按钮、下拉框等）。
     */
    IFACEMETHODIMP GetFieldDescriptorCount(__out DWORD* pdwCount) override;

    /**
     * @brief 获取指定索引的字段描述符。
     * @param[in]  dwIndex 字段索引。
     * @param[out] ppcpfd  接收字段描述符结构体（包含控件类型、ID等）。
     */
    IFACEMETHODIMP GetFieldDescriptorAt(
        __in DWORD dwIndex, __deref_out CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd) override;

    /**
     * @brief 获取磁贴（Credential Tiles）的数量。
     * @param[out] pdwCount 磁贴总数。
     * @param[out] pdwDefault 默认选中的磁贴索引。
     * @param[out] pbAutoLogonWithDefault 是否使用默认磁贴尝试自动登录。
     */
    IFACEMETHODIMP GetCredentialCount(__out DWORD*                     pdwCount,
                                      __out_range(<, *pdwCount) DWORD* pdwDefault,
                                      __out BOOL* pbAutoLogonWithDefault) override;

    /**
     * @brief 获取具体的凭据实例（磁贴）。
     * @param[in]  dwIndex 磁贴索引。
     * @param[out] ppcpc   接收 ICredentialProviderCredential 接口指针。
     * @details 真正的 UI 交互和身份验证逻辑都封装在返回的 ppcpc 对象中。
     */
    IFACEMETHODIMP GetCredentialAt(__in DWORD                                  dwIndex,
                                   __deref_out ICredentialProviderCredential** ppcpc) override;

    /** @brief 友元函数，用于类工厂创建实例 */
    friend HRESULT CSample_CreateInstance(__in REFIID riid, __deref_out void** ppv);

  protected:
    CSampleProvider();
    __override ~CSampleProvider();

  private:
    /** @brief 清理所有已创建的凭据实例。 */
    void CleanUpAllCredentials();

  private:
    LONG _cRef;  ///< COM 引用计数。

    // 使用 vector 管理磁贴实例
    std::vector<ComPtr<CSampleCredential>> m_sample_credentials;

    /**
     * @brief 被包装的原始提供程序。
     * @details 这是一个 Wrapper 模式的体现。我们将标准的密码提供程序封装在内。
     */
    ICredentialProvider* m_wrappedProvider;

    /** @brief 被包装提供程序提供的凭据数量。 */
    DWORD m_wrappedCredentialCount;

    /** @brief 被包装提供程序的字段描述符数量。 */
    DWORD m_wrappedDescriptorCount;

    /** @brief 标识是否已经处理了 SetSerialization 调用。 */
    bool m_isEnumeratedSetSerialization;
};
