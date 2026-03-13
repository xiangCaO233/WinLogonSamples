#include "CSampleProvider.h"

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
