package io.github.jessire.xiaocanpurify;

import android.app.Activity;
import android.app.Application;
import android.os.Build;
import android.os.Bundle;
import android.util.Log;

import java.lang.reflect.Method;
import java.util.concurrent.atomic.AtomicBoolean;

import io.github.libxposed.api.XposedInterface;
import io.github.libxposed.api.XposedModule;
import io.github.libxposed.api.XposedModuleInterface;

public final class MainHook extends XposedModule {
    public static final String TARGET_PACKAGE = "com.realtech.xiaocan";
    public static final String LOG_TAG = "XiaoCanPurify";
    private static final AtomicBoolean HOOKED = new AtomicBoolean(false);
    private static volatile MainHook instance;

    // ==================== 功能模块独立开关 ====================
    // 如果启用后仍闪退，可将开关改为 false 进行二分法排查
    public static final boolean ENABLE_AD_BLOCKER = false;            
    public static final boolean ENABLE_POPUP_BLOCKER = false;         
    public static final boolean ENABLE_BOTTOM_BAR_PURIFIER = false;   
    public static final boolean ENABLE_HOME_PAGE_PURIFIER = false;    
    public static final boolean ENABLE_ORDER_PAGE_PURIFIER = false;
    public static final boolean ENABLE_DETAIL_PAGE_PURIFIER = false;  // <--- 补上这一行！详情页净化
    public static final boolean ENABLE_USER_PAGE_PURIFIER = false;    // 「我的」页面净化
    
    public static final boolean ENABLE_NETWORK_INTERCEPTOR = false;  // OkHttp 网络层广告拦截
    public static final boolean ENABLE_FLUTTER_GUARD = false;        // Flutter 插件广告通道拦截
    // ==========================================================

    @Override
    public void onModuleLoaded(XposedModuleInterface.ModuleLoadedParam param) {
        instance = this;
        log("XiaoCanPurify API 102 (Vector-Safe) module loaded.");
    }

    @Override
    public void onPackageReady(XposedModuleInterface.PackageReadyParam param) {
        if (!TARGET_PACKAGE.equals(param.getPackageName())) {
            return;
        }

        // 1. 过滤所有后台/推送子进程，仅在主进程执行，防止 Vector 多进程容器崩溃
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            String processName = Application.getProcessName();
            if (processName != null && !TARGET_PACKAGE.equals(processName)) {
                log("Skip sub-process in Vector: " + processName);
                return;
            }
        }

        instance = this;
        log("Target main process ready: " + param.getPackageName());

        // 2. 避开 onPackageReady 抢跑与 Aliyun Jiagu 解壳阶段，延迟到 Activity 阶段再挂载
        hookActivitySafe(this);
    }

    private static boolean canLoadTargetClasses(ClassLoader cl) {
        if (cl == null) return false;
        try {
            Class.forName("com.realtech.xiaocan.MainActivity", false, cl);
            return true;
        } catch (Throwable e) {
            return false;
        }
    }

    private void hookActivitySafe(XposedInterface xposed) {
        try {
            // 仅挂载 Activity.onCreate，避开 Vector 对 Application 生命周期的底层代理冲突
            Method actOnCreate = Activity.class.getDeclaredMethod("onCreate", Bundle.class);
            xposed.hook(actOnCreate).intercept(chain -> {
                if (!HOOKED.get()) {
                    Activity activity = (Activity) chain.getThisObject();
                    if (activity != null) {
                        ClassLoader cl = activity.getClassLoader();
                        if (canLoadTargetClasses(cl)) {
                            installAll(xposed, cl);
                        }
                    }
                }
                return chain.proceed();
            });
            log("Activity.onCreate lifecycle hook registered.");
        } catch (Throwable t) {
            log("Hook Activity.onCreate failed: " + Log.getStackTraceString(t));
        }
    }

    public static synchronized void installAll(XposedInterface xposed, ClassLoader classLoader) {
        if (!HOOKED.compareAndSet(false, true)) {
            return;
        }
        log("Target classes unlocked, installing purifier hooks with ClassLoader: " + classLoader);

        if (ENABLE_AD_BLOCKER) {
            try {
                AdBlocker.install(xposed, classLoader);
                log("AdBlocker installed.");
            } catch (Throwable t) {
                log("AdBlocker error: " + Log.getStackTraceString(t));
            }
        }

        if (ENABLE_POPUP_BLOCKER) {
            try {
                PopupBlocker.install(xposed, classLoader);
                log("PopupBlocker installed.");
            } catch (Throwable t) {
                log("PopupBlocker error: " + Log.getStackTraceString(t));
            }
        }

        if (ENABLE_BOTTOM_BAR_PURIFIER) {
            try {
                BottomBarPurifier.install(xposed, classLoader);
                log("BottomBarPurifier installed.");
            } catch (Throwable t) {
                log("BottomBarPurifier error: " + Log.getStackTraceString(t));
            }
        }

        if (ENABLE_HOME_PAGE_PURIFIER) {
            try {
                HomePagePurifier.install(xposed, classLoader);
                log("HomePagePurifier installed.");
            } catch (Throwable t) {
                log("HomePagePurifier error: " + Log.getStackTraceString(t));
            }
        }

        if (ENABLE_ORDER_PAGE_PURIFIER) {
            try {
                OrderPagePurifier.install(xposed, classLoader);
                log("OrderPagePurifier installed.");
            } catch (Throwable t) {
                log("OrderPagePurifier error: " + Log.getStackTraceString(t));
            }
        }

        if (ENABLE_DETAIL_PAGE_PURIFIER) {
            try {
                DetailPagePurifier.install(xposed, classLoader);
                log("DetailPagePurifier installed.");
            } catch (Throwable t) {
                log("DetailPagePurifier error: " + Log.getStackTraceString(t));
            }
        }

        if (ENABLE_USER_PAGE_PURIFIER) {
            try {
                UserPagePurifier.install(xposed, classLoader);
                log("UserPagePurifier installed.");
            } catch (Throwable t) {
                log("UserPagePurifier error: " + Log.getStackTraceString(t));
            }
        }

        if (ENABLE_NETWORK_INTERCEPTOR) {
            try {
                NetworkAdInterceptor.install(xposed, classLoader);
                log("NetworkAdInterceptor installed.");
            } catch (Throwable t) {
                log("NetworkAdInterceptor error: " + Log.getStackTraceString(t));
            }
        }

        if (ENABLE_FLUTTER_GUARD) {
            try {
                FlutterPageGuard.install(xposed, classLoader);
                log("FlutterPageGuard installed.");
            } catch (Throwable t) {
                log("FlutterPageGuard error: " + Log.getStackTraceString(t));
            }
        }

        log("XiaoCanPurify initialization finished!");
    }

    public static void log(String message) {
        MainHook hook = instance;
        if (hook != null) {
            try {
                hook.log(Log.INFO, LOG_TAG, message);
                return;
            } catch (Throwable ignored) {
            }
        }
        Log.i(LOG_TAG, message);
    }
}
