/**
 * @file CSampleCredential.cpp
 * @brief 磁贴实例的逻辑实现。
 *
 * @details
 * 该类实现了 ICredentialProviderCredential 接口。
 * 它的核心逻辑是将所有请求分发（Dispatch）：
 * 1. 如果请求的是原有的字段（如用户名、密码），则转发给被包装的凭据。
 * 2. 如果请求的是我们新增的字段（如部门下拉框），则由本类自行处理。
 */

#ifndef WIN32_NO_STATUS
#    include <ntstatus.h>
#    define WIN32_NO_STATUS
#endif
#include <unknwn.h>

#include "CSampleCredential.h"
#include "events/CWrappedCredentialEvents.h"
#include "guid.h"

/**
 * @brief 构造函数。
 * @details 初始化成员变量，清空字段描述符数组。
 */
CSampleCredential::CSampleCredential()
    : _cRef(1)
{
    DllAddRef();  // 增加 DLL 引用计数，防止使用中 DLL 被卸载

    // 清零所有本地存储数组
    ZeroMemory(_rgCredProvFieldDescriptors, sizeof(_rgCredProvFieldDescriptors));
    ZeroMemory(_rgFieldStatePairs, sizeof(_rgFieldStatePairs));
    ZeroMemory(_rgFieldStrings, sizeof(_rgFieldStrings));

    _pWrappedCredential        = NULL;  // 内部被包装的凭据
    _pWrappedCredentialEvents  = NULL;  // 用于拦截内部事件的中继器
    _pCredProvCredentialEvents = NULL;  // LogonUI 提供的原始事件接口

    _dwWrappedDescriptorCount = 0;  // 内部凭据占用的字段总数
    _dwDatabaseIndex          = 0;  // 下拉框默认选择第一项
}

/**
 * @brief 析构函数。
 * @details 释放所有动态分配的字符串内存和 COM 接口引用。
 */
CSampleCredential::~CSampleCredential()
{
    // 释放本地自定义字段使用的字符串内存
    for (int i = 0; i < ARRAYSIZE(_rgFieldStrings); i++)
    {
        CoTaskMemFree(_rgFieldStrings[i]);
        CoTaskMemFree(_rgCredProvFieldDescriptors[i].pszLabel);
    }

    _CleanupEvents();  // 清理事件回调关联

    if (_pWrappedCredential)
    {
        _pWrappedCredential->Release();
    }

    DllRelease();  // 减少 DLL 引用计数
}

/**
 * @brief 初始化磁贴。
 *
 * @param[in] rgcpfd 自定义字段描述符数组。
 * @param[in] rgfsp  自定义字段状态表。
 * @param[in] pWrappedCredential 指向被包装的原始凭据。
 * @param[in] dwWrappedDescriptorCount 原始凭据有多少个字段。
 *
 * @return HRESULT。
 */
HRESULT CSampleCredential::Initialize(__in const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* rgcpfd,
                                      __in const FIELD_STATE_PAIR*                     rgfsp,
                                      __in ICredentialProviderCredential* pWrappedCredential,
                                      __in DWORD                          dwWrappedDescriptorCount)
{
    HRESULT hr = S_OK;

    // 1. 保存并增加被包装凭据的引用计数
    if (_pWrappedCredential != NULL)
    {
        _pWrappedCredential->Release();
    }
    _pWrappedCredential = pWrappedCredential;
    _pWrappedCredential->AddRef();

    // 2. 记住偏移量：所有 ID 小于此值的请求都属于原始凭据
    _dwWrappedDescriptorCount = dwWrappedDescriptorCount;

    // 3. 拷贝自定义字段的描述符信息
    for (DWORD i = 0; SUCCEEDED(hr) && i < ARRAYSIZE(_rgCredProvFieldDescriptors); i++)
    {
        _rgFieldStatePairs[i] = rgfsp[i];
        // 深度拷贝字段描述符（包括内部字符串）
        hr = FieldDescriptorCopy(rgcpfd[i], &_rgCredProvFieldDescriptors[i]);
    }

    // 4. 初始化本地字段显示的文本内容
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"I Work In:", &_rgFieldStrings[SFI_I_WORK_IN_STATIC]);
    }
    if (SUCCEEDED(hr))
    {
        // 这里的 L"Database" 是程序内部标识，UI 显示内容在 GetComboBoxValueAt 中处理
        hr = SHStrDupW(L"Database", &_rgFieldStrings[SFI_DATABASE_COMBOBOX]);
    }

    return hr;
}

/**
 * @brief 注册事件通知。
 * @details 这是包装模式中最复杂的部分。内部凭据也需要发送事件（比如密码错误红字），
 * 但它只知道自己的 ID。我们必须通过 CWrappedCredentialEvents 将其“拦截”并“修正”后传给系统。
 */
HRESULT CSampleCredential::Advise(__in ICredentialProviderCredentialEvents* pcpce)
{
    HRESULT hr = S_OK;

    _CleanupEvents();

    // 1. 保存系统提供的事件接口指针（LogonUI）
    _pCredProvCredentialEvents = pcpce;
    _pCredProvCredentialEvents->AddRef();

    // 2. 创建一个“事件中继器”
    _pWrappedCredentialEvents = new CWrappedCredentialEvents();

    if (_pWrappedCredentialEvents != NULL)
    {
        // 3. 让中继器知道“我”是谁，以及“真正的系统回调”在哪
        _pWrappedCredentialEvents->Initialize(this, pcpce);

        if (_pWrappedCredential != NULL)
        {
            // 4. 关键：把我们的中继器骗给内部凭据，让它以为是在直接跟系统通讯
            hr = _pWrappedCredential->Advise(_pWrappedCredentialEvents);
        }
    }
    else
    {
        hr = E_OUTOFMEMORY;
    }

    return hr;
}

/**
 * @brief 停止事件通知。
 */
HRESULT CSampleCredential::UnAdvise()
{
    HRESULT hr = S_OK;

    if (_pWrappedCredential != NULL)
    {
        hr = _pWrappedCredential->UnAdvise();
    }

    _CleanupEvents();

    return hr;
}

//--- 以下 SetSelected/SetDeselected 方法简单转发给内部凭据即可 ---

HRESULT CSampleCredential::SetSelected(__out BOOL* pbAutoLogon)
{
    HRESULT hr = E_UNEXPECTED;
    if (_pWrappedCredential != NULL)
    {
        hr = _pWrappedCredential->SetSelected(pbAutoLogon);
    }
    return hr;
}

HRESULT CSampleCredential::SetDeselected()
{
    HRESULT hr = E_UNEXPECTED;
    if (_pWrappedCredential != NULL)
    {
        hr = _pWrappedCredential->SetDeselected();
    }
    return hr;
}

/**
 * @brief 获取字段状态（可见性/交互性）。
 *
 * @details 这是分发逻辑的典型：
 * - 如果 ID < _dwWrappedDescriptorCount：转发给原凭据。
 * - 如果 ID >= _dwWrappedDescriptorCount：查本地表。
 */
HRESULT CSampleCredential::GetFieldState(__in DWORD                             dwFieldID,
                                         __out CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
                                         __out CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis)
{
    HRESULT hr = E_UNEXPECTED;

    if (_pWrappedCredential != NULL && pcpfs != NULL && pcpfis != NULL)
    {
        if (_IsFieldInWrappedCredential(dwFieldID))
        {
            // 转发请求：询问内部凭据它的字段（如密码框）现在应该长啥样
            hr = _pWrappedCredential->GetFieldState(dwFieldID, pcpfs, pcpfis);
        }
        else
        {
            // 本地处理：查我们自己的 `s_rgFieldStatePairs` 表
            FIELD_STATE_PAIR* pfsp = _LookupLocalFieldStatePair(dwFieldID);
            if (pfsp != NULL)
            {
                *pcpfs  = pfsp->cpfs;
                *pcpfis = pfsp->cpfis;
                hr      = S_OK;
            }
            else
            {
                hr = E_INVALIDARG;
            }
        }
    }
    return hr;
}

/** @brief 获取字段显示的文本。逻辑同上：转发或本地返回。 */
HRESULT CSampleCredential::GetStringValue(__in DWORD dwFieldID, __deref_out PWSTR* ppwsz)
{

    HRESULT hr = E_UNEXPECTED;

    if (_pWrappedCredential != NULL)
    {
        if (_IsFieldInWrappedCredential(dwFieldID))
        {
            hr = _pWrappedCredential->GetStringValue(dwFieldID, ppwsz);
        }
        else
        {
            FIELD_STATE_PAIR* pfsp = _LookupLocalFieldStatePair(dwFieldID);
            if (pfsp != NULL)
            {
                // 这里的 SFI_I_WORK_IN_STATIC 实际上返回 "I Work In:" 标签
                hr = SHStrDupW(_rgFieldStrings[SFI_I_WORK_IN_STATIC], ppwsz);
            }
            else
            {
                hr = E_INVALIDARG;
            }
        }
    }
    return hr;
}

/** @brief 获取下拉框项目数和当前选中索引。 */
HRESULT CSampleCredential::GetComboBoxValueCount(__in DWORD dwFieldID, __out DWORD* pcItems,
                                                 __out_range(<, *pcItems) DWORD* pdwSelectedItem)
{
    HRESULT hr = E_UNEXPECTED;

    if (_pWrappedCredential != NULL)
    {
        if (_IsFieldInWrappedCredential(dwFieldID))
        {
            hr = _pWrappedCredential->GetComboBoxValueCount(dwFieldID, pcItems, pdwSelectedItem);
        }
        else
        {
            FIELD_STATE_PAIR* pfsp = _LookupLocalFieldStatePair(dwFieldID);
            if (pfsp != NULL)
            {
                // 返回在 common.h 中定义的部门数据库数组大小
                *pcItems = ARRAYSIZE(s_rgDatabases);
                // 返回本地存储的当前选择索引
                *pdwSelectedItem = _dwDatabaseIndex;
                hr               = S_OK;
            }
            else
            {
                hr = E_INVALIDARG;
            }
        }
    }

    return hr;
}

/** @brief 系统迭代调用此函数来填充下拉框的每一行文字。 */
HRESULT CSampleCredential::GetComboBoxValueAt(__in DWORD dwFieldID, __in DWORD dwItem,
                                              __deref_out PWSTR* ppwszItem)
{
    HRESULT hr = E_UNEXPECTED;

    if (_pWrappedCredential != NULL)
    {
        if (_IsFieldInWrappedCredential(dwFieldID))
        {
            hr = _pWrappedCredential->GetComboBoxValueAt(dwFieldID, dwItem, ppwszItem);
        }
        else
        {
            FIELD_STATE_PAIR* pfsp = _LookupLocalFieldStatePair(dwFieldID);
            if ((pfsp != NULL) && (dwItem < ARRAYSIZE(s_rgDatabases)))
            {
                // 从静态数组中取字符串并拷贝给系统
                hr = SHStrDupW(s_rgDatabases[dwItem], ppwszItem);
            }
            else
            {
                hr = E_INVALIDARG;
            }
        }
    }

    return hr;
}

/** @brief 当用户在 UI 上点击了下拉框的某一项时，系统回调此函数通知我们更新数据。 */
HRESULT CSampleCredential::SetComboBoxSelectedValue(__in DWORD dwFieldID, __in DWORD dwSelectedItem)
{
    HRESULT hr = E_UNEXPECTED;

    if (_pWrappedCredential != NULL)
    {
        if (_IsFieldInWrappedCredential(dwFieldID))
        {
            hr = _pWrappedCredential->SetComboBoxSelectedValue(dwFieldID, dwSelectedItem);
        }
        else
        {
            FIELD_STATE_PAIR* pfsp = _LookupLocalFieldStatePair(dwFieldID);
            if ((pfsp != NULL) && (dwSelectedItem < ARRAYSIZE(s_rgDatabases)))
            {
                // 更新本地状态，以便 GetSerialization 时使用
                _dwDatabaseIndex = dwSelectedItem;
                hr               = S_OK;
            }
            else
            {
                hr = E_INVALIDARG;
            }
        }
    }

    return hr;
}

//--- 以下方法本类未添加对应控件，故全部直接转发给内部凭据 ---

HRESULT CSampleCredential::GetBitmapValue(__in DWORD dwFieldID, __out HBITMAP* phbmp)
{
    HRESULT hr = E_UNEXPECTED;
    if (_pWrappedCredential != NULL)
        hr = _pWrappedCredential->GetBitmapValue(dwFieldID, phbmp);
    return hr;
}

HRESULT CSampleCredential::GetSubmitButtonValue(__in DWORD dwFieldID, __out DWORD* pdwAdjacentTo)
{
    HRESULT hr = E_UNEXPECTED;
    if (_pWrappedCredential != NULL)
        hr = _pWrappedCredential->GetSubmitButtonValue(dwFieldID, pdwAdjacentTo);
    return hr;
}

HRESULT CSampleCredential::SetStringValue(__in DWORD dwFieldID, __in PCWSTR pwz)
{
    HRESULT hr = E_UNEXPECTED;
    if (_pWrappedCredential != NULL)
        hr = _pWrappedCredential->SetStringValue(dwFieldID, pwz);
    return hr;
}

HRESULT CSampleCredential::GetCheckboxValue(__in DWORD dwFieldID, __out BOOL* pbChecked,
                                            __deref_out PWSTR* ppwszLabel)
{
    HRESULT hr = E_UNEXPECTED;
    if (_pWrappedCredential != NULL && _IsFieldInWrappedCredential(dwFieldID))
    {
        hr = _pWrappedCredential->GetCheckboxValue(dwFieldID, pbChecked, ppwszLabel);
    }
    return hr;
}

HRESULT CSampleCredential::SetCheckboxValue(__in DWORD dwFieldID, __in BOOL bChecked)
{
    HRESULT hr = E_UNEXPECTED;
    if (_pWrappedCredential != NULL)
        hr = _pWrappedCredential->SetCheckboxValue(dwFieldID, bChecked);
    return hr;
}

HRESULT CSampleCredential::CommandLinkClicked(__in DWORD dwFieldID)
{
    HRESULT hr = E_UNEXPECTED;
    if (_pWrappedCredential != NULL)
        hr = _pWrappedCredential->CommandLinkClicked(dwFieldID);
    return hr;
}

/**
 * @brief 序列化凭据：这是点击登录按钮后最重要的步骤。
 * @details
 * 在此示例中，我们只是单纯地调用内部凭据的序列化。
 * 每一行的意义：因为内部凭据已经处理了用户名和密码的加密和打包，
 * 我们直接使用它的结果，让系统完成登录流程。
 */
HRESULT CSampleCredential::GetSerialization(
    __out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
    __out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*   pcpcs,
    __deref_out_opt PWSTR*                                ppwszOptionalStatusText,
    __out CREDENTIAL_PROVIDER_STATUS_ICON*                pcpsiOptionalStatusIcon)
{
    HRESULT hr = E_UNEXPECTED;

    if (_pWrappedCredential != NULL)
    {
        // 转发请求：让标准的密码提供程序生成实际的凭据包
        hr = _pWrappedCredential->GetSerialization(
            pcpgsr, pcpcs, ppwszOptionalStatusText, pcpsiOptionalStatusIcon);
    }

    return hr;
}

/** @brief 报告登录结果（如：欢迎信息或错误提示）。简单转发。 */
HRESULT CSampleCredential::ReportResult(
    __in NTSTATUS ntsStatus, __in NTSTATUS ntsSubstatus,
    __deref_out_opt PWSTR*                 ppwszOptionalStatusText,
    __out CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
    HRESULT hr = E_UNEXPECTED;
    if (_pWrappedCredential != NULL)
    {
        hr = _pWrappedCredential->ReportResult(
            ntsStatus, ntsSubstatus, ppwszOptionalStatusText, pcpsiOptionalStatusIcon);
    }
    return hr;
}

/**
 * @brief 私有辅助：判断 FieldID 是否属于被包装的凭据。
 */
BOOL CSampleCredential::_IsFieldInWrappedCredential(__in DWORD dwFieldID)
{
    return (dwFieldID < _dwWrappedDescriptorCount);
}

/**
 * @brief 私有辅助：将全局 FieldID 映射到本地索引并查表。
 */
FIELD_STATE_PAIR* CSampleCredential::_LookupLocalFieldStatePair(__in DWORD dwFieldID)
{
    // 减去偏移量，得到相对索引
    dwFieldID -= _dwWrappedDescriptorCount;

    // 检查索引合法性
    if (dwFieldID < SFI_NUM_FIELDS)
    {
        return &(_rgFieldStatePairs[dwFieldID]);
    }

    return NULL;
}

/**
 * @brief 私有辅助：清理并销毁所有事件中继器。
 */
void CSampleCredential::_CleanupEvents()
{
    if (_pWrappedCredentialEvents != NULL)
    {
        _pWrappedCredentialEvents->Uninitialize();
        _pWrappedCredentialEvents->Release();
        _pWrappedCredentialEvents = NULL;
    }

    if (_pCredProvCredentialEvents != NULL)
    {
        _pCredProvCredentialEvents->Release();
        _pCredProvCredentialEvents = NULL;
    }
}