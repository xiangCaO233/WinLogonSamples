#include "CSampleProvider.h"

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
            // 先获取原生的描述符
            hr = _pWrappedProvider->GetFieldDescriptorAt(dwIndex, ppcpfd);

            if (SUCCEEDED(hr))
            {
                // 2. 关键拦截：判断这个字段是不是密码框
                // 通常原生的密码框 ID 是 2，或者你可以通过类型判断：
                if ((*ppcpfd)->cpft == CPFT_PASSWORD_TEXT)
                {
                    // 3. 修改标签内容
                    // 先释放原生分配给 "密码" 或 "Password" 的内存
                    CoTaskMemFree((*ppcpfd)->pszLabel);

                    // 重新分配你想要的标签名称
                    // 注意：必须使用 CoTaskMemAlloc 分配，或者使用 SHStrDupW
                    hr = SHStrDupW(L"授权码", &((*ppcpfd)->pszLabel));
                }
            }
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
