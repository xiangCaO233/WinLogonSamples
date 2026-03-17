#include "CSampleProvider.h"

/**
 * @brief 获取总的 UI 字段数量。
 *
 * @details
 * 总数量 = 内置密码程序的字段数 + 我们自定义的字段数 (SFI_NUM_FIELDS)。
 *
 * @param[out] pdwCount 返回总字段数。
 */
HRESULT CSampleProvider::GetFieldDescriptorCount(__out DWORD* outFieldCountPtr)
{
    HRESULT hr = E_UNEXPECTED;

    if (m_wrappedProvider != NULL)
    {
        // 1. 获取内置提供程序的字段数（通常是头像、用户名、密码、提交按钮等）
        hr = m_wrappedProvider->GetFieldDescriptorCount(&(m_wrappedDescriptorCount));
        if (SUCCEEDED(hr))
        {
            // 2. 总数 = 内置数 + 2（我们在 common.h 定义的标签和下拉框）
            *outFieldCountPtr = m_wrappedDescriptorCount + SFI_NUM_FIELDS;
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
    __in DWORD                                         inputIndex,
    __deref_out CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** outProviderFieldDescriptorPtr)
{
    HRESULT hr = E_UNEXPECTED;

    if (m_wrappedProvider != NULL && outProviderFieldDescriptorPtr != NULL)
    {
        // A. 如果索引属于内置程序，直接转发请求
        if (inputIndex < m_wrappedDescriptorCount)
        {
            // 先获取原生的描述符
            hr = m_wrappedProvider->GetFieldDescriptorAt(inputIndex, outProviderFieldDescriptorPtr);
        }
        // B. 如果索引超出了内置程序，说明是我们要自定义的控件
        else
        {
            // 1. 计算出在我们自定义数组中的相对索引
            inputIndex -= m_wrappedDescriptorCount;

            if (inputIndex < SFI_NUM_FIELDS)
            {
                // 2. 从 common.h 定义的静态数组中拷贝描述符
                hr = FieldDescriptorCoAllocCopy(s_rgCredProvFieldDescriptors[inputIndex],
                                                outProviderFieldDescriptorPtr);

                // 3. 关键：修正 FieldID。ID 必须是全局唯一的，所以要加上内置程序描述符数量。
                (**outProviderFieldDescriptorPtr).dwFieldID += m_wrappedDescriptorCount;
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
