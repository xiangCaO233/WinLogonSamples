/**
 * @file Dll.cpp
 * @brief 标准 COM DLL 入口点与类工厂（Class Factory）实现。
 *
 * 逻辑流程：
 * 1. Windows 调用 DllGetClassObject。
 * 2. DLL 返回 CClassFactory 实例。
 * 3. Windows 调用 CClassFactory::CreateInstance 创建真正的凭据提供程序对象。
 */

#include <windows.h>
#include <unknwn.h>  // 定义 IUnknown, IClassFactory
#include "Dll.h"
#include "helpers.h"
#include "Utilities.h"

/** @brief DLL 全局引用计数。由 DllCanUnloadNow 检查。 */
static LONG g_cRef = 0;

/** @brief DLL 模块实例句柄。在 DllMain 中初始化。 */
HINSTANCE g_hinst = NULL;

/**
 * @brief 外部定义的构造函数。
 * @details 这是在其他文件中实现的函数，用于创建凭据提供程序的实例（通常名为 CSample）。
 */
extern HRESULT CSample_CreateInstance(__in REFIID riid, __deref_out void** ppv);

/** @brief 本组件的唯一类标识符 (CLSID)。 */
EXTERN_C GUID CLSID_CSample;

/**
 * @class CClassFactory
 * @brief COM 类工厂类。
 *
 * @details 它是 COM 的“工厂”，专门负责创建实际的工作对象（CSample）。
 * 每个 COM 组件都必须有一个类工厂。
 */
class CClassFactory : public IClassFactory
{
  public:
    /** @brief 构造函数。初始化本地引用计数。 */
    CClassFactory()
        : _cRef(1)
    {
    }

    // --- IUnknown 接口实现 ---

    /**
     * @brief 查询接口。
     * @param riid 请求的接口 ID。
     * @param ppv 接收接口指针的缓冲区。
     * @return HRESULT。
     */
    IFACEMETHODIMP QueryInterface(__in REFIID riid, __deref_out void** ppv)
    {
        WriteLog(L"DLL QueryInterface Called");
        // QITAB 表驱动的接口查询，使代码更简洁
        static const QITAB qit[] = {
            QITABENT(CClassFactory, IClassFactory),
            {0},
        };
        return QISearch(this, qit, riid, ppv);
    }

    /**
     * @brief 增加类工厂的引用计数。
     * @return 增加后的计数值。
     */
    IFACEMETHODIMP_(ULONG) AddRef()
    {
        return InterlockedIncrement(&_cRef);
    }

    /**
     * @brief 减少类工厂的引用计数。
     * @details 当计数归零时，删除类工厂实例。
     */
    IFACEMETHODIMP_(ULONG) Release()
    {
        LONG cRef = InterlockedDecrement(&_cRef);
        if (!cRef)
            delete this;
        return cRef;
    }

    // --- IClassFactory 接口实现 ---

    /**
     * @brief 创建实际的凭据提供程序对象。
     * @param pUnkOuter 用于 COM 聚合。凭据提供程序通常不支持聚合，故必须为 NULL。
     * @param riid 最终对象（CSample）需要的接口（通常是 ICredentialProvider）。
     * @param ppv 接收对象指针。
     */
    IFACEMETHODIMP CreateInstance(__in IUnknown* pUnkOuter, __in REFIID riid,
                                  __deref_out void** ppv)
    {
        WriteLog(L"DLL CreateInstance Called");
        HRESULT hr;
        if (!pUnkOuter)
        {
            // 调用外部定义的 CSample_CreateInstance 来创建实际对象
            hr = CSample_CreateInstance(riid, ppv);
        }
        else
        {
            *ppv = NULL;
            hr   = CLASS_E_NOAGGREGATION;  // 不支持 COM 聚合
        }
        return hr;
    }

    /**
     * @brief 锁定或解锁 DLL 服务器。
     * @param bLock TRUE 为锁定，FALSE 为解锁。
     * @details 锁定后，即便没有活跃对象，DLL 也不会从内存卸载。
     */
    IFACEMETHODIMP LockServer(__in BOOL bLock)
    {
        WriteLog(L"DLL LockServer Called");
        if (bLock)
        {
            DllAddRef();
        }
        else
        {
            DllRelease();
        }
        return S_OK;
    }

  private:
    /** @brief 私有析构函数，确保只能通过 Release 销毁。 */
    ~CClassFactory()
    {
    }

    /** @brief 类工厂自身的引用计数（非 DLL 全局计数）。 */
    long _cRef;
};

/**
 * @brief 内部辅助函数：创建类工厂实例。
 * @param rclsid 要创建的类的 CLSID。
 * @param riid 类工厂需要的接口。
 * @param ppv 接收地址。
 */
HRESULT CClassFactory_CreateInstance(__in REFCLSID rclsid, __in REFIID riid, __deref_out void** ppv)
{
    WriteLog(L"DLL CClassFactory_CreateInstance Called");
    *ppv = NULL;
    HRESULT hr;

    // 检查请求的 CLSID 是否是我们要提供的这个组件
    if (CLSID_CSample == rclsid)
    {
        CClassFactory* pcf = new CClassFactory();
        if (pcf)
        {
            hr = pcf->QueryInterface(riid, ppv);
            pcf->Release();  // 释放本地初始引用
        }
        else
        {
            hr = E_OUTOFMEMORY;
        }
    }
    else
    {
        hr = CLASS_E_CLASSNOTAVAILABLE;
    }
    return hr;
}

/**
 * @brief 线程安全地增加 DLL 全局计数。
 */
void DllAddRef()
{
    InterlockedIncrement(&g_cRef);
}

/**
 * @brief 线程安全地减少 DLL 全局计数。
 */
void DllRelease()
{
    InterlockedDecrement(&g_cRef);
}

/**
 * @brief COM 入口函数：系统询问本 DLL 是否可以卸载。
 * @return 如果没有活跃引用 (g_cRef == 0)，返回 S_OK，表示可以卸载。
 */
STDAPI DllCanUnloadNow()
{
    return (g_cRef > 1) ? S_FALSE : S_OK;
}

/**
 * @brief COM 入口函数：获取类工厂。
 * @details 当外部（如 LogonUI）尝试通过 CoCreateInstance 创建对象时，
 * 系统首先调用此函数获取类工厂。
 */
STDAPI DllGetClassObject(__in REFCLSID rclsid, __in REFIID riid, __deref_out void** ppv)
{
    WriteLog(L"DLL DllGetClassObject Called");
    return CClassFactory_CreateInstance(rclsid, riid, ppv);
}

/**
 * @brief DLL 模块入口点。
 * @param hinstDll DLL 模块句柄。
 * @param dwReason 调用原因（加载、卸载、线程操作）。
 */
STDAPI_(BOOL) DllMain(__in HINSTANCE hinstDll, __in DWORD dwReason, __in void*)
{
    WriteLog(L"DLL DllMain Called");
    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
        /**
         * @details 优化：由于本 DLL 不处理线程级的初始化，
         * 禁用 DLL_THREAD_ATTACH/DETACH 通知可以提高性能。
         */
        DisableThreadLibraryCalls(hinstDll);
        break;
    case DLL_PROCESS_DETACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }

    // 保存实例句柄，供后续资源加载使用
    g_hinst = hinstDll;
    return TRUE;
}