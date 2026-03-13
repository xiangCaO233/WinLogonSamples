/**
 * @file CWrappedCredentialEvents.cpp
 * @brief 凭据事件中继器实现。
 */

#include <unknwn.h>
#include "CWrappedCredentialEvents.h"

/**
 * @brief 处理设置字段状态。
 * @param pcpc 被包装磁贴传入的指针。
 * @param dwFieldID 字段 ID。
 * @param cpfs 状态。
 */
HRESULT CWrappedCredentialEvents::SetFieldState(__in ICredentialProviderCredential*  pcpc,
                                                __in DWORD                           dwFieldID,
                                                __in CREDENTIAL_PROVIDER_FIELD_STATE cpfs)
{
    // 关键：我们忽略 pcpc 参数（那是被包装磁贴的地址）。
    UNREFERENCED_PARAMETER(pcpc);

    HRESULT hr = E_FAIL;

    // 每一行的意义：
    // 我们改用 _pWrapperCredential（即外层包装磁贴的地址）作为调用参数发给系统。
    // 系统看到事件是从包装磁贴发出来的，才会正常处理。
    if (_pWrapperCredential && _pEvents)
    {
        hr = _pEvents->SetFieldState(_pWrapperCredential, dwFieldID, cpfs);
    }

    return hr;
}

// 以下所有方法的逻辑完全相同：
// 1. 拦截被包装对象的调用。
// 2. 丢弃被包装对象的 'this' 指针。
// 3. 用外层包装对象的 'this' 指针重定向调用发给 LogonUI。

HRESULT CWrappedCredentialEvents::SetFieldInteractiveState(
    __in ICredentialProviderCredential* pcpc, __in DWORD dwFieldID,
    __in CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE cpfis)
{
    UNREFERENCED_PARAMETER(pcpc);
    HRESULT hr = E_FAIL;
    if (_pWrapperCredential && _pEvents)
    {
        hr = _pEvents->SetFieldInteractiveState(_pWrapperCredential, dwFieldID, cpfis);
    }
    return hr;
}

HRESULT CWrappedCredentialEvents::SetFieldString(__in ICredentialProviderCredential* pcpc,
                                                 __in DWORD dwFieldID, __in PCWSTR psz)
{
    UNREFERENCED_PARAMETER(pcpc);
    HRESULT hr = E_FAIL;
    if (_pWrapperCredential && _pEvents)
    {
        hr = _pEvents->SetFieldString(_pWrapperCredential, dwFieldID, psz);
    }
    return hr;
}

HRESULT CWrappedCredentialEvents::SetFieldBitmap(__in ICredentialProviderCredential* pcpc,
                                                 __in DWORD dwFieldID, __in HBITMAP hbmp)
{
    UNREFERENCED_PARAMETER(pcpc);
    HRESULT hr = E_FAIL;
    if (_pWrapperCredential && _pEvents)
    {
        hr = _pEvents->SetFieldBitmap(_pWrapperCredential, dwFieldID, hbmp);
    }
    return hr;
}

HRESULT CWrappedCredentialEvents::SetFieldCheckbox(__in ICredentialProviderCredential* pcpc,
                                                   __in DWORD dwFieldID, __in BOOL bChecked,
                                                   __in PCWSTR pszLabel)
{
    UNREFERENCED_PARAMETER(pcpc);
    HRESULT hr = E_FAIL;
    if (_pWrapperCredential && _pEvents)
    {
        hr = _pEvents->SetFieldCheckbox(_pWrapperCredential, dwFieldID, bChecked, pszLabel);
    }
    return hr;
}

HRESULT CWrappedCredentialEvents::SetFieldComboBoxSelectedItem(
    __in ICredentialProviderCredential* pcpc, __in DWORD dwFieldID, __in DWORD dwSelectedItem)
{
    UNREFERENCED_PARAMETER(pcpc);
    HRESULT hr = E_FAIL;
    if (_pWrapperCredential && _pEvents)
    {
        hr = _pEvents->SetFieldComboBoxSelectedItem(_pWrapperCredential, dwFieldID, dwSelectedItem);
    }
    return hr;
}

HRESULT CWrappedCredentialEvents::DeleteFieldComboBoxItem(__in ICredentialProviderCredential* pcpc,
                                                          __in DWORD dwFieldID, __in DWORD dwItem)
{
    UNREFERENCED_PARAMETER(pcpc);
    HRESULT hr = E_FAIL;
    if (_pWrapperCredential && _pEvents)
    {
        hr = _pEvents->DeleteFieldComboBoxItem(_pWrapperCredential, dwFieldID, dwItem);
    }
    return hr;
}

HRESULT CWrappedCredentialEvents::AppendFieldComboBoxItem(__in ICredentialProviderCredential* pcpc,
                                                          __in DWORD dwFieldID, __in PCWSTR pszItem)
{
    UNREFERENCED_PARAMETER(pcpc);
    HRESULT hr = E_FAIL;
    if (_pWrapperCredential && _pEvents)
    {
        hr = _pEvents->AppendFieldComboBoxItem(_pWrapperCredential, dwFieldID, pszItem);
    }
    return hr;
}

HRESULT CWrappedCredentialEvents::SetFieldSubmitButton(__in ICredentialProviderCredential* pcpc,
                                                       __in DWORD dwFieldID,
                                                       __in DWORD dwAdjacentTo)
{
    UNREFERENCED_PARAMETER(pcpc);
    HRESULT hr = E_FAIL;
    if (_pWrapperCredential && _pEvents)
    {
        hr = _pEvents->SetFieldSubmitButton(_pWrapperCredential, dwFieldID, dwAdjacentTo);
    }
    return hr;
}

/**
 * @brief 系统询问父窗口句柄。
 * @details 此方法不涉及特定磁贴指针，直接转发即可。
 */
HRESULT CWrappedCredentialEvents::OnCreatingWindow(__out HWND* phwndOwner)
{
    HRESULT hr = E_FAIL;
    if (_pWrapperCredential && _pEvents)
    {
        hr = _pEvents->OnCreatingWindow(phwndOwner);
    }
    return hr;
}

/** @brief 构造函数。引用计数设为 1。 */
CWrappedCredentialEvents::CWrappedCredentialEvents()
    : _cRef(1)
    , _pWrapperCredential(NULL)
    , _pEvents(NULL)
{
}

/**
 * @brief 初始化弱引用。
 *
 * @details
 * **为什么是弱引用？**
 * 外层凭据（Wrapper）持有了内部凭据（Wrapped）的引用，
 * 内部凭据持有了本对象（Events）的引用。
 * 如果本对象再强引用（AddRef）外层凭据，就会形成**循环引用（Circular Reference）**，
 * 导致 DLL 永远无法卸载，内存永远无法释放。
 *
 * 因此，我们只是保存指针，不调用 AddRef。外层凭据负责在销毁前调用 Uninitialize。
 */
void CWrappedCredentialEvents::Initialize(__in ICredentialProviderCredential* pWrapperCredential,
                                          __in ICredentialProviderCredentialEvents* pEvents)
{
    _pWrapperCredential = pWrapperCredential;
    _pEvents            = pEvents;
}

/** @brief 清除弱引用。由外层凭据在析构或 UnAdvise 时调用。 */
void CWrappedCredentialEvents::Uninitialize()
{
    _pWrapperCredential = NULL;
    _pEvents            = NULL;
}