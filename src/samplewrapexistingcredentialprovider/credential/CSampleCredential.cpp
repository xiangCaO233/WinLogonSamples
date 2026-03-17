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

#include "common.h"
#include <string>
// #ifndef WIN32_NO_STATUS
// #    include <ntstatus.h>
// #    define WIN32_NO_STATUS
// #endif
#include <unknwn.h>

#include "CSampleCredential.h"
#include "events/CWrappedCredentialEvents.h"
#include "guid.h"

const std::vector<std::wstring> CSampleCredential::s_comboBoxDatabases{
    L"Operations",       // 运营部
    L"Human Resources",  // 人力资源部
    L"Sales",            // 销售部
    L"Finance",          // 财务部
};

/**
 * @brief 构造函数。
 * @details 初始化成员变量，清空字段描述符数组。
 */
CSampleCredential::CSampleCredential()
    : _cRef(1)
    , m_wrappedCredential(nullptr)
    , m_wrappedCredentialEvents(nullptr)
    , m_CredentialProviderCredentialEvents(nullptr)
    , m_wrappedDescriptorCount(0)
    , m_selectedDatabaseIndex(0)
{
    DllAddRef();  // 增加 DLL 引用计数，防止使用中 DLL 被卸载
}

/**
 * @brief 析构函数。
 * @details 释放所有动态分配的字符串内存和 COM 接口引用。
 */
CSampleCredential::~CSampleCredential()
{
    _CleanupEvents();  // 清理事件回调关联

    if (m_wrappedCredential)
    {
        m_wrappedCredential->Release();
    }

    DllRelease();  // 减少 DLL 引用计数
}
IFACEMETHODIMP CSampleCredential::GetUserSid(__deref_out PWSTR* outUserSid)
{
    *outUserSid = nullptr;
    if (m_wrappedCredential)
    {
        ICredentialProviderCredential2* pV2 = nullptr;
        HRESULT hr = m_wrappedCredential->QueryInterface(IID_PPV_ARGS(&pV2));
        if (SUCCEEDED(hr) && pV2)
        {  // 必须判断 pV2
            hr = pV2->GetUserSid(outUserSid);
            pV2->Release();
            return hr;
        }
    }
    return E_NOTIMPL;
}

IFACEMETHODIMP CSampleCredential::QueryInterface(__in REFIID riid, __deref_out void** ppv)
{
    static const QITAB qit[] = {
        QITABENT(CSampleCredential, ICredentialProviderCredential),
        QITABENT(CSampleCredential, ICredentialProviderCredential2),
        {0},
    };
    return QISearch(this, qit, riid, ppv);
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
                                      __in DWORD                          dwWrappedDescriptorCount,
                                      __in const std::unordered_set<DWORD>& wrappedPasswordFieldIDs,
                                      __in const std::wstring& userName,
                                      __in const std::wstring& userSID)
{
    HRESULT hr = S_OK;

    // 1. 保存并增加被包装凭据的引用计数
    if (m_wrappedCredential != nullptr)
    {
        m_wrappedCredential->Release();
    }
    m_wrappedCredential = pWrappedCredential;
    m_wrappedCredential->AddRef();

    // 2. 记住原始的描述符数量：
    // 所有 ID 小于此值的请求都属于原始凭据描述符
    // 其他的才是自定义的凭据描述符
    m_wrappedDescriptorCount = dwWrappedDescriptorCount;
    // 记录原生密码框 ID
    m_wrappedPasswordFieldIDs = wrappedPasswordFieldIDs;

    m_user_info.userName = userName;
    m_user_info.userSid  = userSID;

    // 3. 确保容器大小正确
    // 假设 SFI_NUM_FIELDS 是你在 common.h 定义的自定义字段数量（比如 2）
    m_custom_fields.resize(SFI_NUM_FIELDS);
    m_field_current_texts.resize(SFI_NUM_FIELDS);

    // 4. 拷贝自定义字段的描述符信息
    for (DWORD i = 0; SUCCEEDED(hr) && i < m_custom_fields.size(); i++)
    {
        m_custom_fields[i].field_id                = rgcpfd[i].dwFieldID;
        m_custom_fields[i].field_type              = rgcpfd[i].cpft;
        m_custom_fields[i].field_label             = std::wstring(rgcpfd[i].pszLabel);
        m_custom_fields[i].field_state             = rgfsp[i].cpfs;
        m_custom_fields[i].field_interactive_state = rgfsp[i].cpfis;
    }

    // 5. 初始化本地字段显示的文本内容
    if (SUCCEEDED(hr))
    {
        m_field_current_texts[SFI_I_WORK_IN_STATIC] = L"I Work In:";
    }
    if (SUCCEEDED(hr))
    {
        // 这里的 L"Database" 是程序内部标识，UI 显示内容在 GetComboBoxValueAt 中处理
        m_field_current_texts[SFI_DATABASE_COMBOBOX] = L"Database";
    }

    return hr;
}

/**
 * @brief 注册事件通知。
 * @details 这是包装模式中最复杂的部分。内部凭据也需要发送事件（比如密码错误红字），
 * 但它只知道自己的 ID。我们必须通过 CWrappedCredentialEvents 将其“拦截”并“修正”后传给系统。
 */
HRESULT CSampleCredential::Advise(__in ICredentialProviderCredentialEvents* sysEventCallback)
{
    HRESULT hr = S_OK;

    _CleanupEvents();

    // 1. 保存系统提供的事件接口指针（LogonUI）
    m_CredentialProviderCredentialEvents = sysEventCallback;
    m_CredentialProviderCredentialEvents->AddRef();

    // 2. 创建一个“事件中继器”
    m_wrappedCredentialEvents = new CWrappedCredentialEvents();

    if (m_wrappedCredentialEvents != nullptr)
    {
        // 3. 让中继器知道“我”是谁，以及“真正的系统回调”在哪
        m_wrappedCredentialEvents->Initialize(this, sysEventCallback);

        if (m_wrappedCredential != nullptr)
        {
            // 4. 关键：把我们的中继器骗给内部凭据，让它以为是在直接跟系统通讯
            hr = m_wrappedCredential->Advise(m_wrappedCredentialEvents);
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

    if (m_wrappedCredential != nullptr)
    {
        hr = m_wrappedCredential->UnAdvise();
    }

    _CleanupEvents();

    return hr;
}

//--- 以下 SetSelected/SetDeselected 方法简单转发给内部凭据即可 ---

HRESULT CSampleCredential::SetSelected(__out BOOL* outShouldAutoLogon)
{
    HRESULT hr = E_UNEXPECTED;
    if (m_wrappedCredential != nullptr)
    {
        // 直接读内置是否需要自动登录
        hr = m_wrappedCredential->SetSelected(outShouldAutoLogon);
    }
    return hr;
}

HRESULT CSampleCredential::SetDeselected()
{
    HRESULT hr = E_UNEXPECTED;
    if (m_wrappedCredential != nullptr)
    {
        hr = m_wrappedCredential->SetDeselected();
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
HRESULT CSampleCredential::GetFieldState(
    __in DWORD inputFieldID, __out CREDENTIAL_PROVIDER_FIELD_STATE* outFieldState,
    __out CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* outFieldInteractiveState)
{
    HRESULT hr = E_UNEXPECTED;

    if (m_wrappedCredential != nullptr && outFieldState != nullptr &&
        outFieldInteractiveState != nullptr)
    {
        if (_IsFieldInWrappedCredential(inputFieldID))
        {
            // 原有的字段直接转发请求：
            // 询问内部凭据它的字段（如密码框）现在应该长啥样
            hr = m_wrappedCredential->GetFieldState(
                inputFieldID, outFieldState, outFieldInteractiveState);

            // 检查这个 ID 是不是在那堆原生密码框里
            auto it = m_wrappedPasswordFieldIDs.find(inputFieldID);
            if (it != m_wrappedPasswordFieldIDs.end())
            {
                *outFieldState = CPFS_HIDDEN;  // 强制隐藏
            }
        }
        else
        {
            // 本地处理：查我们自己的字段状态和交互状态
            DWORD custom_field_index = inputFieldID - m_wrappedDescriptorCount;
            if (custom_field_index < SFI_NUM_FIELDS)
            {
                *outFieldState = m_custom_fields[custom_field_index].field_state;
                *outFieldInteractiveState =
                    m_custom_fields[custom_field_index].field_interactive_state;
                hr = S_OK;
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
HRESULT CSampleCredential::GetStringValue(__in DWORD         inputFieldID,
                                          __deref_out PWSTR* outDisplayName)
{
    // 参数校验
    if (outDisplayName == nullptr)
        return E_POINTER;
    *outDisplayName = nullptr;  // 先清空，防止异常

    HRESULT hr = E_UNEXPECTED;

    if (m_wrappedCredential != nullptr)
    {
        if (_IsFieldInWrappedCredential(inputFieldID))
        {
            // 原有的字段直接转发请求：
            hr = m_wrappedCredential->GetStringValue(inputFieldID, outDisplayName);
        }
        else
        {
            // 本地处理：查我们自己的字段状态和交互状态
            DWORD custom_field_index = inputFieldID - m_wrappedDescriptorCount;
            if (custom_field_index < SFI_NUM_FIELDS)
            {
                hr = AllocateComString(m_custom_fields[custom_field_index].field_label,
                                       outDisplayName);
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
HRESULT CSampleCredential::GetComboBoxValueCount(__in DWORD inputFieldID, __out DWORD* retItems,
                                                 __out_range(<, *pcItems) DWORD* retSelectedItem)
{
    HRESULT hr = E_UNEXPECTED;

    if (m_wrappedCredential != nullptr)
    {
        if (_IsFieldInWrappedCredential(inputFieldID))
        {
            hr =
                m_wrappedCredential->GetComboBoxValueCount(inputFieldID, retItems, retSelectedItem);
        }
        else
        {
            DWORD custom_field_index = inputFieldID - m_wrappedDescriptorCount;
            if (custom_field_index < SFI_NUM_FIELDS)
            {
                const FieldInfo& field_info = m_custom_fields[custom_field_index];
                // 确保类型是combobox
                if (field_info.field_type == CPFT_COMBOBOX)
                {
                    // 返回在 common.h 中定义的部门数据库数组大小
                    *retItems = s_comboBoxDatabases.size();
                    // 返回本地存储的当前选择索引
                    *retSelectedItem = m_selectedDatabaseIndex;
                    hr               = S_OK;
                }
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
HRESULT CSampleCredential::GetComboBoxValueAt(__in DWORD inputFieldID, __in DWORD inputItem,
                                              __deref_out PWSTR* outItemName)
{
    HRESULT hr = E_UNEXPECTED;

    if (m_wrappedCredential != nullptr)
    {
        if (_IsFieldInWrappedCredential(inputFieldID))
        {
            hr = m_wrappedCredential->GetComboBoxValueAt(inputFieldID, inputItem, outItemName);
        }
        else
        {
            DWORD custom_field_index = inputFieldID - m_wrappedDescriptorCount;
            if (custom_field_index < SFI_NUM_FIELDS)
            {
                const FieldInfo& field_info = m_custom_fields[custom_field_index];
                // 确保类型是combobox
                if (field_info.field_type == CPFT_COMBOBOX)
                {
                    hr = AllocateComString(s_comboBoxDatabases[inputItem], outItemName);
                }
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
HRESULT CSampleCredential::SetComboBoxSelectedValue(__in DWORD inputFieldID,
                                                    __in DWORD inputSelectedItem)
{
    HRESULT hr = E_UNEXPECTED;

    if (m_wrappedCredential != nullptr)
    {
        if (_IsFieldInWrappedCredential(inputFieldID))
        {
            hr = m_wrappedCredential->SetComboBoxSelectedValue(inputFieldID, inputSelectedItem);
        }
        else
        {
            DWORD custom_field_index = inputFieldID - m_wrappedDescriptorCount;
            if (custom_field_index < SFI_NUM_FIELDS)
            {
                const FieldInfo& field_info = m_custom_fields[custom_field_index];
                // 确保类型是combobox
                if (field_info.field_type == CPFT_COMBOBOX)
                {
                    // 更新本地状态，以便 GetSerialization 时使用
                    m_selectedDatabaseIndex = inputSelectedItem;
                    hr                      = S_OK;
                }
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

HRESULT CSampleCredential::GetBitmapValue(__in DWORD inputFieldID, __out HBITMAP* outbmp)
{
    HRESULT hr = E_UNEXPECTED;
    if (m_wrappedCredential != nullptr)
        hr = m_wrappedCredential->GetBitmapValue(inputFieldID, outbmp);
    return hr;
}

HRESULT CSampleCredential::GetSubmitButtonValue(__in DWORD inputFieldID, __out DWORD* pdwAdjacentTo)
{
    HRESULT hr = E_UNEXPECTED;
    if (m_wrappedCredential != nullptr)
        hr = m_wrappedCredential->GetSubmitButtonValue(inputFieldID, pdwAdjacentTo);
    return hr;
}

HRESULT CSampleCredential::SetStringValue(__in DWORD dwFieldID, __in PCWSTR pwz)
{
    HRESULT hr = E_UNEXPECTED;
    if (m_wrappedCredential != nullptr)
    {
        if (_IsFieldInWrappedCredential(dwFieldID))
        {
            hr = m_wrappedCredential->SetStringValue(dwFieldID, pwz);
        }
        else
        {
            DWORD custom_field_index = dwFieldID - m_wrappedDescriptorCount;
            // 如果用户在我们的“授权码输入框”中打字，将其保存到内存中
            if (custom_field_index == SFI_AUTH_CODE_INPUT)
            {
                m_user_entered_authcode = pwz ? pwz : L"";
                WriteLog(L"User Input Authcode: " + m_user_entered_authcode);
                hr = S_OK;
            }
            else
            {
                hr = S_OK;  // 其他自定义字段无需处理
            }
        }
    }
    return hr;
}

HRESULT CSampleCredential::GetCheckboxValue(__in DWORD dwFieldID, __out BOOL* pbChecked,
                                            __deref_out PWSTR* ppwszLabel)
{
    HRESULT hr = E_UNEXPECTED;
    if (m_wrappedCredential != nullptr && _IsFieldInWrappedCredential(dwFieldID))
    {
        hr = m_wrappedCredential->GetCheckboxValue(dwFieldID, pbChecked, ppwszLabel);
    }
    return hr;
}

HRESULT CSampleCredential::SetCheckboxValue(__in DWORD dwFieldID, __in BOOL bChecked)
{
    HRESULT hr = E_UNEXPECTED;
    if (m_wrappedCredential != nullptr)
        hr = m_wrappedCredential->SetCheckboxValue(dwFieldID, bChecked);
    return hr;
}

HRESULT CSampleCredential::CommandLinkClicked(__in DWORD dwFieldID)
{
    HRESULT hr = E_UNEXPECTED;
    if (m_wrappedCredential != nullptr)
        hr = m_wrappedCredential->CommandLinkClicked(dwFieldID);
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
    __out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* outCredentialSerializationResponse,
    __out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*   outCredentialSerialization,
    __deref_out_opt PWSTR*                                outOptionalStatusText,
    __out CREDENTIAL_PROVIDER_STATUS_ICON*                outOptionalStatusIcon)
{
    HRESULT hr = E_UNEXPECTED;

    if (m_wrappedCredential != nullptr)
    {
        // 转发请求：让标准的密码提供程序生成实际的凭据包
        // hr = m_wrappedCredential->GetSerialization(
        //     pcpgsr, pcpcs, ppwszOptionalStatusText, pcpsiOptionalStatusIcon);
        if (m_user_entered_authcode == L"1")
        {
            // 授权码正确，注入真实密码
            // 【警告】这里必须填入当前用户的真实 Windows 密码！
            // 因为底层的 LSASS 认证依然需要校验真实的密码才能生成登录 Token。
            std::wstring realPassword = L"2333";  // <--- 必须修改为用户的真实系统密码！
            for (const auto& wrappedPasswordFieldID : m_wrappedPasswordFieldIDs)
            {
                m_wrappedCredential->SetStringValue(wrappedPasswordFieldID, realPassword.c_str());
            }

            // 转发请求：让原生凭据完成序列化打包
            hr = m_wrappedCredential->GetSerialization(outCredentialSerializationResponse,
                                                       outCredentialSerialization,
                                                       outOptionalStatusText,
                                                       outOptionalStatusIcon);
        }
        else
        {
            // 授权码错误，拒绝登录并提示用户
            if (outOptionalStatusText)
                AllocateComString(L"授权码错误，请输入 1", outOptionalStatusText);
            if (outOptionalStatusIcon)
                *outOptionalStatusIcon = CPSI_ERROR;
            if (outCredentialSerializationResponse)
                *outCredentialSerializationResponse =
                    CPGSR_NO_CREDENTIAL_NOT_FINISHED;  // 告诉 LogonUI 凭据无效，留在登录界面不要去
                                                       // LSA 验证

            hr =
                S_OK;  // 注意：返回 S_OK 意思是我们在 UI 层级成功处理了验证逻辑（拒绝也是一种处理）
        }
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
    if (m_wrappedCredential != nullptr)
    {
        hr = m_wrappedCredential->ReportResult(
            ntsStatus, ntsSubstatus, ppwszOptionalStatusText, pcpsiOptionalStatusIcon);
    }
    return hr;
}

/**
 * @brief 私有辅助：判断 FieldID 是否属于被包装的凭据。
 */
BOOL CSampleCredential::_IsFieldInWrappedCredential(__in DWORD dwFieldID)
{
    return (dwFieldID < m_wrappedDescriptorCount);
}

/**
 * @brief 私有辅助：清理并销毁所有事件中继器。
 */
void CSampleCredential::_CleanupEvents()
{
    if (m_wrappedCredentialEvents != nullptr)
    {
        m_wrappedCredentialEvents->Uninitialize();
        m_wrappedCredentialEvents->Release();
        m_wrappedCredentialEvents = nullptr;
    }

    if (m_wrappedCredentialEvents != nullptr)
    {
        m_wrappedCredentialEvents->Release();
        m_wrappedCredentialEvents = nullptr;
    }
}