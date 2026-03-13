/**
 * @file CSampleCredential.h
 * @brief 凭据磁贴实例类定义。
 *
 * @details CSampleCredential 实现了 ICredentialProviderCredential 接口。
 * 它是 LogonUI（登录界面）与之交互的核心对象。
 * 其职责包括：
 * 1. 定义磁贴的 UI 表现（图片、文本、下拉框内容）。
 * 2. 接收用户的输入（SetStringValue, SetComboBoxSelectedValue）。
 * 3. 序列化凭据：将用户名、密码及自定义数据打包发送给 LSA 进行验证。
 */

#pragma once

#include <helpers.h>
#include "common.h"
#include "dll.h"
#include "resource.h"
#include "events/CWrappedCredentialEvents.h"  // 用于包装事件回调的转换器

class CSampleCredential : public ICredentialProviderCredential
{
  public:
    // --- IUnknown 接口实现 (COM 基础) ---

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

    IFACEMETHODIMP QueryInterface(__in REFIID riid, __deref_out void** ppv) override
    {
        static const QITAB qit[] = {
            QITABENT(CSampleCredential, ICredentialProviderCredential),
            {0},
        };
        return QISearch(this, qit, riid, ppv);
    }

  public:
    // --- ICredentialProviderCredential 核心接口方法 ---

    /**
     * @brief 注册磁贴事件回调。
     * @param[in] pcpce LogonUI 提供的事件接口。用于通知系统刷新 UI。
     */
    IFACEMETHODIMP Advise(__in ICredentialProviderCredentialEvents* pcpce) override;

    /**
     * @brief 取消注册事件回调。
     */
    IFACEMETHODIMP UnAdvise() override;

    /**
     * @brief 当用户点击选中此磁贴时调用。
     * @param[out] pbAutoLogon 是否尝试以此凭据自动登录。
     */
    IFACEMETHODIMP SetSelected(__out BOOL* pbAutoLogon) override;

    /**
     * @brief 当用户取消选择此磁贴（或点击了其他磁贴）时调用。
     */
    IFACEMETHODIMP SetDeselected() override;

    /**
     * @brief 获取指定字段的显示状态。
     * @param[in]  dwFieldID 字段 ID（包含包装偏移量）。
     * @param[out] pcpfs     返回显示状态（显示/隐藏）。
     * @param[out] pcpfis    返回交互状态（是否获得焦点）。
     */
    IFACEMETHODIMP GetFieldState(
        __in DWORD dwFieldID, __out CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
        __out CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis) override;

    /** @brief 获取字符串字段的值（如文本标签的内容）。 */
    IFACEMETHODIMP GetStringValue(__in DWORD dwFieldID, __deref_out PWSTR* ppwsz) override;

    /** @brief 获取图片字段的值（如磁贴头像）。 */
    IFACEMETHODIMP GetBitmapValue(__in DWORD dwFieldID, __out HBITMAP* phbmp) override;

    /** @brief 获取复选框的状态。 */
    IFACEMETHODIMP GetCheckboxValue(__in DWORD dwFieldID, __out BOOL* pbChecked,
                                    __deref_out PWSTR* ppwszLabel) override;

    /** @brief 获取组合框（下拉列表）的项目总数和当前选中项。 */
    IFACEMETHODIMP GetComboBoxValueCount(__in DWORD dwFieldID, __out DWORD* pcItems,
                                         __out_range(<, *pcItems) DWORD* pdwSelectedItem) override;

    /** @brief 获取组合框中指定索引的字符串内容。 */
    IFACEMETHODIMP GetComboBoxValueAt(__in DWORD dwItem, __in DWORD dwFieldID,
                                      __deref_out PWSTR* ppwszItem) override;

    /** @brief 获取提交按钮的布局位置。 */
    IFACEMETHODIMP GetSubmitButtonValue(__in DWORD dwFieldID, __out DWORD* pdwAdjacentTo) override;

    /** @brief 用户在文本框输入内容时，系统通过此方法更新数据。 */
    IFACEMETHODIMP SetStringValue(__in DWORD dwFieldID, __in PCWSTR pwz) override;

    /** @brief 用户点击复选框时调用。 */
    IFACEMETHODIMP SetCheckboxValue(__in DWORD dwFieldID, __in BOOL bChecked) override;

    /** @brief 用户选择下拉列表中的某一项时调用。 */
    IFACEMETHODIMP SetComboBoxSelectedValue(__in DWORD dwFieldID,
                                            __in DWORD dwSelectedItem) override;

    /** @brief 用户点击磁贴上的命令链接时调用。 */
    IFACEMETHODIMP CommandLinkClicked(__in DWORD dwFieldID) override;

    /**
     * @brief 身份验证的关键步骤：生成登录数据包。
     * @details 当用户点击“提交”按钮时调用。此方法需要收集用户名、密码、
     * 以及我们自定义的“数据库”索引，将其序列化为二进制流发送给内核。
     */
    IFACEMETHODIMP GetSerialization(
        __out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
        __out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*   pcpcs,
        __deref_out_opt PWSTR*                                ppwszOptionalStatusText,
        __out CREDENTIAL_PROVIDER_STATUS_ICON*                pcpsiOptionalStatusIcon) override;

    /**
     * @brief 报告身份验证结果。
     * @param[in] ntsStatus LSA 返回的身份验证状态。
     */
    IFACEMETHODIMP ReportResult(
        __in NTSTATUS ntsStatus, __in NTSTATUS ntsSubstatus,
        __deref_out_opt PWSTR*                 ppwszOptionalStatusText,
        __out CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon) override;

  public:
    /**
     * @brief 初始化磁贴。
     * @param rgcpfd 自定义字段描述符数组。
     * @param rgfsp  自定义字段状态表。
     * @param pWrappedCredential 被包装的内置磁贴对象。
     * @param dwWrappedDescriptorCount 内置磁贴拥有的字段数（用于 ID 偏移计算）。
     */
    HRESULT Initialize(__in const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* rgcpfd,
                       __in const FIELD_STATE_PAIR*                     rgfsp,
                       __in ICredentialProviderCredential*              pWrappedCredential,
                       __in DWORD                                       dwWrappedDescriptorCount);

    CSampleCredential();
    virtual ~CSampleCredential();

  private:
    /** @brief 判断给定的 FieldID 是否属于内置磁贴（还是属于我们自定义的部分）。 */
    BOOL _IsFieldInWrappedCredential(__in DWORD dwFieldID);

    /** @brief 查找自定义字段的显示状态对。 */
    FIELD_STATE_PAIR* _LookupLocalFieldStatePair(__in DWORD dwFieldID);

    /** @brief 释放事件回调对象。 */
    void _CleanupEvents();

  private:
    LONG _cRef;  ///< 引用计数。

    /** @brief 存储自定义字段的描述信息（如下拉框类型）。 */
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR _rgCredProvFieldDescriptors[SFI_NUM_FIELDS];

    /** @brief 存储自定义字段的初始显示状态（如在磁贴选中时显示）。 */
    FIELD_STATE_PAIR _rgFieldStatePairs[SFI_NUM_FIELDS];

    /** @brief 存储自定义字段的当前字符串内容（如文本标签的 L"I work in"）。 */
    PWSTR _rgFieldStrings[SFI_NUM_FIELDS];

    /**
     * @brief 事件中继器。
     * @details 这是一个关键设计。内置磁贴（Wrapped）会触发它自己的事件。
     * 我们需要拦截这些事件，通过这个对象转发给外层的 LogonUI，并修正 FieldID 偏移。
     */
    CWrappedCredentialEvents* _pWrappedCredentialEvents;

    /** @brief 指向 LogonUI 提供的事件处理接口。 */
    ICredentialProviderCredentialEvents* _pCredProvCredentialEvents;

    /** @brief 指向被包装的原始内置凭据磁贴（例如系统标准的密码磁贴）。 */
    ICredentialProviderCredential* _pWrappedCredential;

    /** @brief 内置磁贴占用的字段数。我们自定义字段的 ID 会在此基础上累加。 */
    DWORD _dwWrappedDescriptorCount;

    /** @brief 存储用户在下拉列表中选择的索引（如选择“Operations”）。 */
    DWORD _dwDatabaseIndex;

    PWSTR _pszUserEnteredAuthCode;
};