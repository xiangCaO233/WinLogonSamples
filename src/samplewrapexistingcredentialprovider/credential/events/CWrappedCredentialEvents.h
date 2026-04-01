/**
 * @file CWrappedCredentialEvents.h
 * @brief 凭据事件中继器类定义。
 *
 * @details
 * 该类实现了 ICredentialProviderCredentialEvents (ICPCE)。
 * 大多数凭据提供程序不需要实现此接口，但“包装型”提供程序必须实现。
 *
 * 核心逻辑：
 * 包装对象会将它的 "this" 指针传递给 ICPCE 的调用，但 LogonUI 无法识别该指针。
 * 本实现负责将“被包装的指针”翻译/替换为“包装层的指针”。
 */

#pragma once

#include <windows.h>
#include <strsafe.h>
#include <shlguid.h>
#include "helpers.h"
#include "Dll.h"
#include "resource.h"

class CWrappedCredentialEvents : public ICredentialProviderCredentialEvents
{
  public:
    // --- IUnknown 接口实现 (标准 COM 样板) ---
    IFACEMETHODIMP_(ULONG) AddRef() override
    {
        return ++_cRef;
    }

    IFACEMETHODIMP_(ULONG) Release() override
    {
        LONG cRef = --_cRef;
        if (!cRef)
        {
            delete this;
        }
        return cRef;
    }

    IFACEMETHODIMP QueryInterface(__in REFIID riid, __in void** ppv) override
    {
        static const QITAB qit[] = {
            QITABENT(CWrappedCredentialEvents, ICredentialProviderCredentialEvents),
            {0},
        };
        return QISearch(this, qit, riid, ppv);
    }

    // --- ICredentialProviderCredentialEvents 接口方法 ---
    // 这些方法由“被包装的凭据”调用，由我们拦截并转发。

    /** @brief 拦截字段状态更改事件。 */
    IFACEMETHODIMP SetFieldState(__in ICredentialProviderCredential* pcpc, __in DWORD dwFieldID,
                                 __in CREDENTIAL_PROVIDER_FIELD_STATE cpfs) override;

    /** @brief 拦截字段交互状态更改事件（如焦点切换）。 */
    IFACEMETHODIMP SetFieldInteractiveState(
        __in ICredentialProviderCredential* pcpc, __in DWORD dwFieldID,
        __in CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE cpfis) override;

    /** @brief 拦截字段字符串更改事件。 */
    IFACEMETHODIMP SetFieldString(__in ICredentialProviderCredential* pcpc, __in DWORD dwFieldID,
                                  __in PCWSTR psz) override;

    /** @brief 拦截复选框更改事件。 */
    IFACEMETHODIMP SetFieldCheckbox(__in ICredentialProviderCredential* pcpc, __in DWORD dwFieldID,
                                    __in BOOL bChecked, __in PCWSTR pszLabel) override;

    /** @brief 拦截位图/头像更改事件。 */
    IFACEMETHODIMP SetFieldBitmap(__in ICredentialProviderCredential* pcpc, __in DWORD dwFieldID,
                                  __in HBITMAP hbmp) override;

    /** @brief 拦截下拉框选中项更改事件。 */
    IFACEMETHODIMP SetFieldComboBoxSelectedItem(__in ICredentialProviderCredential* pcpc,
                                                __in DWORD                          dwFieldID,
                                                __in DWORD dwSelectedItem) override;

    /** @brief 拦截删除下拉框项目事件。 */
    IFACEMETHODIMP DeleteFieldComboBoxItem(__in ICredentialProviderCredential* pcpc,
                                           __in DWORD dwFieldID, __in DWORD dwItem) override;

    /** @brief 拦截添加下拉框项目事件。 */
    IFACEMETHODIMP AppendFieldComboBoxItem(__in ICredentialProviderCredential* pcpc,
                                           __in DWORD dwFieldID, __in PCWSTR pszItem) override;

    /** @brief 拦截提交按钮状态更改事件。 */
    IFACEMETHODIMP SetFieldSubmitButton(__in ICredentialProviderCredential* pcpc,
                                        __in DWORD dwFieldID, __in DWORD dwAdjacentTo) override;

    /** @brief 拦截窗口创建通知。 */
    IFACEMETHODIMP OnCreatingWindow(__out HWND* phwndOwner) override;

    // --- 本地辅助方法 ---

    CWrappedCredentialEvents();

    /**
     * @brief 初始化中继器。
     * @param pWrapperCredential 外部包装凭据的指针（真正的磁贴）。
     * @param pEvents 系统 LogonUI 的原始事件回调接口。
     */
    void Initialize(__in ICredentialProviderCredential*       pWrapperCredential,
                    __in ICredentialProviderCredentialEvents* pEvents);

    /** @brief 清理引用。 */
    void Uninitialize();

  private:
    LONG                                 _cRef;                ///< 引用计数
    ICredentialProviderCredential*       m_wrapperCredential;  ///< 弱引用：外层包装凭据
    ICredentialProviderCredentialEvents* m_uicallback_events;  ///< 弱引用：LogonUI 的回调
};