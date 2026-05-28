#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <Security/Security.h>
#import <CommonCrypto/CommonCryptor.h>
#import <AudioToolbox/AudioToolbox.h> 
#import <sys/sysctl.h>

// 偏好设置配置文件路径（多巴胺无根标准路径）
#define PLS_PATH @"/var/jb/var/mobile/Library/Preferences/com.yourname.universalhijack.plist"

extern CCCryptorStatus CCCrypt(
    CCOperation op, CCAlgorithm alg, CCOptions options,
    const void *key, size_t keyLength, const void *iv,
    const void *dataIn, size_t dataInLength,
    void *dataOut, size_t dataOutAvailable, size_t *dataOutMoved);

// =======================================================
// 动态全局注入开关过滤器（已修正为 Array 包含判定）
// =======================================================
static BOOL isCurrentAppEnabled() {
    NSString *currentBundleID = [[NSBundle mainBundle] bundleIdentifier];
    if (!currentBundleID) return NO;
    
    // 如果是系统桌面或系统设置，绝对不注入，防止死循环
    if ([currentBundleID isEqualToString:@"com.apple.springboard"] || 
        [currentBundleID isEqualToString:@"com.apple.Preferences"]) {
        return NO;
    }
    
    NSDictionary *prefs = [NSDictionary dictionaryWithContentsOfFile:PLS_PATH];
    if (!prefs) return NO;
    
    // 获取设置里的应用列表数组（匹配 layout.xml 中的 key="enabled-AppList"）
    NSArray *enabledApps = [prefs objectForKey:@"enabled-AppList"];
    if (!enabledApps) return NO;
    
    // 检查当前运行的 App 包名是否在用户勾选的数组里
    return [enabledApps containsObject:currentBundleID];
}

// =======================================================
// 1. 防爆级双模日志及硬核双重熔断中心
// =======================================================
@interface NSLayoutConstraintLayoutSpec : NSObject
+ (void)appendSafeLogType:(NSString *)type content:(NSString *)content category:(NSString *)category;
+ (void)togglePanelVisibility;
+ (void)setupSecureEnvironment;
+ (void)destroyTimer;
+ (BOOL)isBrakeSignaled;
@end

static UIWindow *obfuscatedWindow = nil;
static UITextView *secureDisplayView = nil;
static NSMutableArray<NSDictionary *> *structuredLogQueue = nil;
static dispatch_source_t throttleTimerSource = nil; 
static dispatch_queue_t ioDumpQueue = nil;          
static NSString *currentFilterCategory = @"ALL";                 
static NSTimeInterval g_pluginLaunchTime = 0;
static BOOL isPluginPermanentlyLocked = NO;                       
static BOOL isEmergencyBrakeActivated = NO;                      
static BOOL isSimpleMode = YES;
static NSUInteger cryptoDroppedCount = 0;                         
static NSTimeInterval lastCryptoResetTime = 0;                    
static NSUInteger cryptoLogCountInWindow = 0;
static const NSUInteger kMaxLogCapacity = 150;      

@implementation NSLayoutConstraintLayoutSpec

+ (BOOL)isBrakeSignaled {
    NSString *lockPath = [NSTemporaryDirectory() stringByAppendingPathComponent:@".layout_disable_lock"];
    return [[NSFileManager defaultManager] fileExistsAtPath:lockPath];
}

+ (void)appendSafeLogType:(NSString *)type content:(NSString *)content category:(NSString *)category {
    if (!isCurrentAppEnabled()) return; // 没在设置里开开关的，直接拦截不运行
    if (isPluginPermanentlyLocked || isEmergencyBrakeActivated || [self isBrakeSignaled]) return;
    if (isSimpleMode && [category isEqualToString:@"CRYPTO"]) return;
    if (!structuredLogQueue) return;

    if ([category isEqualToString:@"CRYPTO"]) {
        NSTimeInterval now = [[NSDate date] timeIntervalSince1970];
        if (now - lastCryptoResetTime > 1.0) {
            if (cryptoDroppedCount > 0) {
                NSString *dropMsg = [NSString stringWithFormat:@"[System] ⚠️ 触发自动防爆机制：高频加解密日志已限流，自动滤除 %lu 条冗余流。", (unsigned long)cryptoDroppedCount];
                [self addLogToQueueWithType:@"SYSTEM" content:dropMsg category:@"SYSTEM"];
            }
            lastCryptoResetTime = now;
            cryptoLogCountInWindow = 0;
            cryptoDroppedCount = 0;
        }
        
        cryptoLogCountInWindow++;
        if (cryptoLogCountInWindow > 5) {
            cryptoDroppedCount++;
            return;
        }
    }
    [self addLogToQueueWithType:type content:content category:category];
}

+ (void)addLogToQueueWithType:(NSString *)type content:(NSString *)content category:(NSString *)category {
    @synchronized(structuredLogQueue) {
        NSDateFormatter *df = [[NSDateFormatter alloc] init];
        [df setDateFormat:@"HH:mm:ss"];
        NSString *logLine = [NSString stringWithFormat:@"[%@] 🟢 %@:\n%@\n\n────────────────\n\n", 
                             [df stringFromDate:[NSDate date]], type, content ? content : @"(null)"];
        
        NSDictionary *logDict = @{@"category": category, @"text": logLine};
        [structuredLogQueue insertObject:logDict atIndex:0];
        if (structuredLogQueue.count > kMaxLogCapacity) {
            [structuredLogQueue removeLastObject];
        }
    }
}

+ (void)setupSecureEnvironment {
    if (!isCurrentAppEnabled()) return; // 核心保险：没开开关不初始化任何环境
    
    static dispatch_once_t initToken;
    dispatch_once(&initToken, ^{
        structuredLogQueue = [[NSMutableArray alloc] init];
        ioDumpQueue = dispatch_queue_create("com.apple.layout.constraint.io", DISPATCH_QUEUE_SERIAL);
        
        dispatch_queue_t queue = dispatch_get_main_queue();
        throttleTimerSource = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, queue);
        dispatch_source_set_timer(throttleTimerSource, dispatch_walltime(NULL, 0), 0.5 * NSEC_PER_SEC, 0.1 * NSEC_PER_SEC);
        
        dispatch_source_set_event_handler(throttleTimerSource, ^{
            NSMutableArray *filteredLines = [NSMutableArray array];
            @synchronized(structuredLogQueue) {
                for (NSDictionary *log in structuredLogQueue) {
                    NSString *logCat = log[@"category"];
                    if ([currentFilterCategory isEqualToString:@"ALL"] || [logCat isEqualToString:currentFilterCategory]) {
                        [filteredLines addObject:log[@"text"]];
                    }
                }
            }
            if (secureDisplayView) {
                secureDisplayView.text = [filteredLines componentsJoinedByString:@""];
            }
        });
        dispatch_resume(throttleTimerSource);
    });

    if (obfuscatedWindow) return;
    
    CGRect bounds = [UIScreen mainScreen].bounds;
    obfuscatedWindow = [[UIWindow alloc] initWithFrame:bounds]; 
    obfuscatedWindow.windowLevel = UIWindowLevelNormal + 1.2; 
    obfuscatedWindow.backgroundColor = [UIColor clearColor];
    
    UIView *consolePanel = [[UIView alloc] initWithFrame:CGRectMake(15, 60, bounds.size.width - 30, 480)];
    consolePanel.backgroundColor = [UIColor colorWithRed:0.02 green:0.02 blue:0.02 alpha:0.98];
    consolePanel.layer.cornerRadius = 14;
    consolePanel.layer.borderWidth = 0.8;
    consolePanel.layer.borderColor = [UIColor colorWithRed:0.0 green:0.7 blue:0.0 alpha:1.0].CGColor;
    consolePanel.tag = 8888;
    consolePanel.hidden = YES;
    [obfuscatedWindow addSubview:consolePanel];
    
    UILabel *lbl = [[UILabel alloc] initWithFrame:CGRectMake(15, 10, 140, 30)];
    lbl.text = @"⚙️ Layout Engine v11.0";
    lbl.textColor = [UIColor whiteColor];
    lbl.font = [UIFont fontWithName:@"HelveticaNeue-Bold" size:12];
    [consolePanel addSubview:lbl];
    
    UISwitch *modeSwitch = [[UISwitch alloc] initWithFrame:CGRectMake(145, 10, 0, 0)];
    modeSwitch.transform = CGAffineTransformMakeScale(0.65, 0.65); 
    modeSwitch.on = NO; 
    [modeSwitch addTarget:self action:@selector(modeSwitchChanged:) forControlEvents:UIControlEventValueChanged];
    [consolePanel addSubview:modeSwitch];
    
    UILabel *switchLabel = [[UILabel alloc] initWithFrame:CGRectMake(185, 10, 50, 30)];
    switchLabel.text = @"PRO Mode";
    switchLabel.textColor = [UIColor grayColor];
    switchLabel.font = [UIFont systemFontOfSize:9];
    switchLabel.tag = 8899;
    [consolePanel addSubview:switchLabel];
    
    NSArray *categories = @[@"ALL", @"NET", @"CRYPTO", @"KEY"];
    for (int i = 0; i < categories.count; i++) {
        UIButton *catBtn = [UIButton buttonWithType:UIButtonTypeCustom];
        catBtn.frame = CGRectMake(15 + (i * 45), 45, 40, 22);
        [catBtn setTitle:categories[i] forState:UIControlStateNormal];
        catBtn.titleLabel.font = [UIFont systemFontOfSize:10];
        [catBtn setTitleColor:[UIColor lightGrayColor] forState:UIControlStateNormal];
        catBtn.layer.borderWidth = 0.5;
        catBtn.layer.borderColor = [UIColor grayColor].CGColor;
        catBtn.layer.cornerRadius = 3;
        catBtn.tag = 200 + i;
        [catBtn addTarget:self action:@selector(filterChangedHandler:) forControlEvents:UIControlEventTouchUpInside];
        if (i == 0) [catBtn setTitleColor:[UIColor greenColor] forState:UIControlStateNormal];
        [consolePanel addSubview:catBtn];
    }
    
    UIButton *btn = [UIButton buttonWithType:UIButtonTypeCustom];
    btn.frame = CGRectMake(consolePanel.frame.size.width - 150, 10, 65, 26);
    [btn setTitle:@"Copy Data" forState:UIControlStateNormal]; 
    btn.titleLabel.font = [UIFont systemFontOfSize:10];
    [btn setTitleColor:[UIColor greenColor] forState:UIControlStateNormal];
    btn.layer.borderWidth = 0.5;
    btn.layer.borderColor = [UIColor greenColor].CGColor;
    btn.layer.cornerRadius = 4;
    [btn addTarget:self action:@selector(smartClipboardHandler) forControlEvents:UIControlEventTouchUpInside];
    [consolePanel addSubview:btn];
    
    UIButton *keychainBtn = [UIButton buttonWithType:UIButtonTypeCustom];
    keychainBtn.frame = CGRectMake(consolePanel.frame.size.width - 75, 10, 65, 26);
    [keychainBtn setTitle:@"Sync Reg" forState:UIControlStateNormal];
    keychainBtn.titleLabel.font = [UIFont systemFontOfSize:10];
    // ✅ 修复 1：修正手机按钮改颜色的标准消息发送语法（加入方括号）
    [keychainBtn setTitleColor:[UIColor orangeColor] forState:UIControlStateNormal];
    keychainBtn.layer.borderWidth = 0.5;
    keychainBtn.layer.borderColor = [UIColor orangeColor].CGColor;
    keychainBtn.layer.cornerRadius = 4;
    [keychainBtn addTarget:self action:@selector(dumpKeychainItems) forControlEvents:UIControlEventTouchUpInside];
    [consolePanel addSubview:keychainBtn];
    
    secureDisplayView = [[UITextView alloc] initWithFrame:CGRectMake(15, 75, consolePanel.frame.size.width - 30, 320)];
    secureDisplayView.backgroundColor = [UIColor clearColor];
    secureDisplayView.textColor = [UIColor colorWithRed:0.2 green:0.9 blue:0.2 alpha:1.0];
    secureDisplayView.font = [UIFont fontWithName:@"Courier-Bold" size:10];
    secureDisplayView.editable = NO;
    [consolePanel addSubview:secureDisplayView];
    
    UILabel *tipsLabel = [[UILabel alloc] initWithFrame:CGRectMake(15, 400, consolePanel.frame.size.width - 30, 70)];
    tipsLabel.numberOfLines = 0;
    tipsLabel.textColor = [UIColor colorWithRed:0.6 green:0.6 blue:0.6 alpha:1.0];
    tipsLabel.font = [UIFont systemFontOfSize:9];
    tipsLabel.text = @"💡 【小白测试一键式速查守则】\n1. 抓登录凭证：点击黄色 [Sync Reg]，屏幕滚动后点击 [Copy Data] 直接去微信粘贴。\n2. 验证会员：去 App 里正常点击内购，若解锁成功，本控制台会自动亮起绿色破解账单。\n3. 三指长按屏幕 0.5 秒唤醒面板；若遇App卡顿异常，请【四指快速双击屏幕】将瞬间进入休眠。";
    [consolePanel addSubview:tipsLabel];
    
    UIView *ghostZone = [[UIView alloc] initWithFrame:CGRectMake(consolePanel.frame.size.width - 25, 45, 25, 25)];
    ghostZone.backgroundColor = [UIColor clearColor];
    UILongPressGestureRecognizer *selfDestructGesture = [[UILongPressGestureRecognizer alloc] initWithTarget:self action:@selector(handleSelfDestruct:)];
    selfDestructGesture.minimumPressDuration = 3.0; 
    [ghostZone addGestureRecognizer:selfDestructGesture];
    [consolePanel addSubview:ghostZone];
    
    UILongPressGestureRecognizer *tripleLongPress = [[UILongPressGestureRecognizer alloc] initWithTarget:self action:@selector(handleTriplePress:)];
    tripleLongPress.numberOfTouchesRequired = 3;
    tripleLongPress.minimumPressDuration = 0.5; 
    [obfuscatedWindow addGestureRecognizer:tripleLongPress];
    
    UITapGestureRecognizer *quadrupleTap = [[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(handleEmergencyBrake:)];
    quadrupleTap.numberOfTouchesRequired = 4;
    quadrupleTap.numberOfTapsRequired = 2;
    [obfuscatedWindow addGestureRecognizer:quadrupleTap];
    
    obfuscatedWindow.hidden = NO;
    obfuscatedWindow.userInteractionEnabled = YES;
    
    size_t size;
    sysctlbyname("hw.machine", NULL, &size, NULL, 0);
    char *machine = malloc(size);
    if (machine) {
        sysctlbyname("hw.machine", machine, &size, NULL, 0);
        NSString *platform = [NSString stringWithUTF8String:machine];
        free(machine);
        if ([platform hasPrefix:@"iPhone10,"]) {
            isSimpleMode = YES;
            modeSwitch.enabled = NO; 
            switchLabel.text = @"A11 LOCK";
        }
    }
}

+ (void)modeSwitchChanged:(UISwitch *)sender {
    if (isEmergencyBrakeActivated || [self isBrakeSignaled]) return;
    isSimpleMode = !sender.on;
    UILabel *lbl = (UILabel *)[[obfuscatedWindow viewWithTag:8888] viewWithTag:8899];
    if (sender.on) {
        lbl.textColor = [UIColor greenColor];
    } else {
        lbl.textColor = [UIColor grayColor];
    }
}

+ (void)filterChangedHandler:(UIButton *)sender {
    NSArray *categories = @[@"ALL", @"NET", @"CRYPTO", @"KEY"];
    currentFilterCategory = categories[sender.tag - 200];
    for (int i = 0; i < 4; i++) {
        UIButton *btn = (UIButton *)[[obfuscatedWindow viewWithTag:8888] viewWithTag:200 + i];
        [btn setTitleColor:[UIColor lightGrayColor] forState:UIControlStateNormal];
    }
    [sender setTitleColor:[UIColor greenColor] forState:UIControlStateNormal];
}

+ (void)handleTriplePress:(UILongPressGestureRecognizer *)gesture {
    if (isPluginPermanentlyLocked || isEmergencyBrakeActivated || [self isBrakeSignaled]) return;
    if (gesture.state == UIGestureRecognizerStateBegan) {
        [self togglePanelVisibility];
    }
}

+ (void)handleEmergencyBrake:(UITapGestureRecognizer *)gesture {
    if (gesture.state == UIGestureRecognizerStateEnded) {
        isEmergencyBrakeActivated = YES;
        [self destroyTimer];
        UIView *panel = [obfuscatedWindow viewWithTag:8888];
        if (panel) panel.hidden = YES;
        obfuscatedWindow.userInteractionEnabled = NO;
        obfuscatedWindow.hidden = YES;
        
        @try {
            NSString *lockPath = [NSTemporaryDirectory() stringByAppendingPathComponent:@".layout_disable_lock"];
            [[NSFileManager defaultManager] createFileAtPath:lockPath contents:nil attributes:nil];
        } @catch (NSException *e) {}
        
        AudioServicesPlaySystemSound(1521);
    }
}

+ (void)handleSelfDestruct:(UILongPressGestureRecognizer *)gesture {
    if (gesture.state == UIGestureRecognizerStateBegan) {
        isPluginPermanentlyLocked = YES;
        [self destroyTimer];
        UIView *panel = [obfuscatedWindow viewWithTag:8888];
        if (panel) panel.hidden = YES;
        obfuscatedWindow.userInteractionEnabled = NO;
        obfuscatedWindow.hidden = YES;
        AudioServicesPlaySystemSound(1519); 
    }
}

+ (void)togglePanelVisibility {
    UIView *panel = [obfuscatedWindow viewWithTag:8888];
    if (panel) {
        panel.hidden = !panel.hidden;
        obfuscatedWindow.backgroundColor = panel.hidden ? [UIColor clearColor] : [UIColor colorWithRed:0 green:0 blue:0 alpha:0.45];
    }
}

+ (void)destroyTimer {
    if (throttleTimerSource) {
        dispatch_source_cancel(throttleTimerSource);
        throttleTimerSource = nil;
    }
}

+ (void)smartClipboardHandler {
    NSMutableString *clipboardContent = [NSMutableString string];
    @synchronized(structuredLogQueue) {
        for (NSDictionary *log in structuredLogQueue) {
            [clipboardContent appendString:log[@"text"]];
        }
    }
    if (clipboardContent.length > 0) {
        [UIPasteboard generalPasteboard].string = clipboardContent;
    }
}

+ (void)dumpKeychainItems {
    if (!isCurrentAppEnabled()) return;
    [self appendSafeLogType:@"Keychain Core" content:@"执行应用Keychain凭据深度扫描..." category:@"KEY"];
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        // ✅ 修复 2：将声明类型改为 CFTypeRef 防止指针混淆报错
        CFTypeRef result = NULL;
        // ✅ 修复 3：修正布尔值常量名称为 kCFBooleanTrue 对齐底层 SDK 规范
        NSMutableDictionary *query = [NSMutableDictionary dictionaryWithObjectsAndKeys:
                                      (__bridge id)kSecClassGenericPassword, (__bridge id)kSecClass,
                                      (__bridge id)kSecMatchLimitAll, (__bridge id)kSecMatchLimit,
                                      (__bridge id)kCFBooleanTrue, (__bridge id)kSecReturnAttributes,
                                      (__bridge id)kCFBooleanTrue, (__bridge id)kSecReturnData, nil];
        
        OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, (void *)&result);
        if (status == errSecInteractionNotAllowed) {
            [query removeObjectForKey:(__bridge id)kSecReturnData]; 
            status = SecItemCopyMatching((__bridge CFDictionaryRef)query, (void *)&result);
        }
        
        if (status == errSecSuccess) {
            // ✅ 修复 4：完美闭环指针所有权释放桥接
            NSArray *items = (__bridge_transfer NSArray *)result;
            for (NSDictionary *item in items) {
                NSString *service = [item objectForKey:(__bridge id)kSecAttrService];
                NSString *account = [item objectForKey:(__bridge id)kSecAttrAccount];
                NSData *data = [item objectForKey:(__bridge id)kSecValueData];
                NSString *accessGroup = [item objectForKey:(__bridge id)kSecAttrAccessGroup] ? : @"Unknown";
                NSString *label = [item objectForKey:(__bridge id)kSecAttrLabel] ? : @"None";
                
                NSString *payload = @"";
                if (data) {
                    // ✅ 修复 5：补全完整的 NSUTF8StringEncoding 开头
                    payload = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
                    if (!payload) {
                        payload = [NSString stringWithFormat:@"[Binary Base64]: %@", [data base64EncodedStringWithOptions:0]];
                    }
                } else {
                    payload = @"[降级读取：强隔离机制锁定]";
                }
                
                NSString *logContent = [NSString stringWithFormat:@"服务域(Service): %@\n账户名(Account): %@\n所属组(Group): %@\n标签(Label): %@\n数据荷载:\n%@", service, account, accessGroup, label, payload];
                [self appendSafeLogType:@"捕获本地凭据" content:logContent category:@"KEY"];
            }
        }
    });
}
@end

// =======================================================
// 2. 网络拦截层组件
// =======================================================
@interface NSURLSessionTaskDependencyDescription : NSURLProtocol
@end

@implementation NSURLSessionTaskDependencyDescription

+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    if (!isCurrentAppEnabled()) return NO; 
    if (isEmergencyBrakeActivated || [NSLayoutConstraintLayoutSpec isBrakeSignaled]) return NO;
    @try {
        NSString *url = request.URL.absoluteString;
        if (!url) return NO;
        if ([NSURLProtocol propertyForKey:@"ProcessedBySystemProxyCore" inRequest:request]) {
            return NO;
        }
        if ([url containsString:@"buy.itunes.apple.com/verifyReceipt"] || [url containsString:@"/api/v1/user/profile"]) {
            return YES;
        }
    } @catch (NSException *e) {}
    return NO;
}

+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request {
    return request;
}

- (void)startLoading {
    NSMutableURLRequest *strippedRequest = [[self request] mutableCopy];
    [NSURLProtocol setProperty:@YES forKey:@"ProcessedBySystemProxyCore" inRequest:strippedRequest];
    @try {
        NSString *urlStr = strippedRequest.URL.absoluteString;
        if ([urlStr containsString:@"buy.itunes.apple.com/verifyReceipt"]) {
            NSString *currentBundleID = [[NSBundle mainBundle] bundleIdentifier] ? : @"com.apple.placeholder";
            
            NSData *bodyData = strippedRequest.HTTPBody;
            if (bodyData) {
                // ✅ 修复 6：补齐首字母 NS 缩写对齐宏
                NSString *bodyString = [[NSString alloc] initWithData:bodyData encoding:NSUTF8StringEncoding];
                [NSLayoutConstraintLayoutSpec appendSafeLogType:@"Receipt Inbound Request" content:bodyString category:@"NET"];
            }
            
            NSTimeInterval baseAnchor = (g_pluginLaunchTime > 0) ? g_pluginLaunchTime : [[NSDate date] timeIntervalSince1970];
            NSTimeInterval dynamicFutureTime = baseAnchor + ((30 + arc4random_uniform(60)) * 24 * 60 * 60);
            NSString *dynamicExpiresMs = [NSString stringWithFormat:@"%.0f000", dynamicFutureTime];
            
            NSDictionary *fakeResponseDict = @{
                @"status": @0,
                @"receipt": @{ @"bundle_id": currentBundleID, @"application_version": @"1.0" },
                @"latest_receipt_info": @[
                    @{
                        @"product_id": @"premium_lifetime_unlocked",
                        @"expires_date_ms": dynamicExpiresMs, 
                        @"is_in_intro_offer_period": @"false",
                        @"original_transaction_id": @"4000000000000001"
                    }
                ]
            };
            NSData *responseData = [NSJSONSerialization dataWithJSONObject:fakeResponseDict options:NSJSONWritingPrettyPrinted error:nil];
            NSHTTPURLResponse *response = [[NSHTTPURLResponse alloc] initWithURL:strippedRequest.URL statusCode:200 HTTPVersion:@"HTTP/1.1" headerFields:@{@"Content-Type": @"application/json"}];
            [self.client URLProtocol:self didReceiveResponse:response cacheStoragePolicy:NSURLCacheStorageNotAllowed];
            [self.client URLProtocol:self didLoadData:responseData];
            [self.client URLProtocolDidFinishLoading:self];
        }
    } @catch (NSException *exception) {
        [self.client URLProtocol:self didFailWithError:[NSError errorWithDomain:@"com.apple.proxy.err" code:-1 userInfo:nil]];
    }
}

- (void)stopLoading {}
@end

%hook NSURLSessionConfiguration
+ (NSURLSessionConfiguration *)defaultSessionConfiguration {
    if (!isCurrentAppEnabled()) return %orig;
    if (isEmergencyBrakeActivated || [NSLayoutConstraintLayoutSpec isBrakeSignaled]) return %orig;
    NSURLSessionConfiguration *config = %orig;
    if (config) {
        NSMutableArray *protocols = [config.protocolClasses mutableCopy] ? : [NSMutableArray array];
        if (![protocols containsObject:[NSURLSessionTaskDependencyDescription class]]) {
            [protocols insertObject:[NSURLSessionTaskDependencyDescription class] atIndex:0];
            config.protocolClasses = protocols;
        }
    }
    return config;
}
%end

// =======================================================
// 3. 异常安全限流型加密猎手
// =======================================================
%hookf(CCCryptorStatus, CCCrypt, CCOperation op, CCAlgorithm alg, CCOptions options, const void *key, size_t keyLength, const void *iv, const void *dataIn, size_t dataInLength, void *dataOut, size_t dataOutAvailable, size_t *dataOutMoved) {
    
    CCCryptorStatus result = %orig;
    if (!isCurrentAppEnabled()) return result; 
    if (isPluginPermanentlyLocked || isEmergencyBrakeActivated || [NSLayoutConstraintLayoutSpec isBrakeSignaled] || isSimpleMode || alg != 0) return result;
    if (key && dataIn && dataInLength > 0) {
        char *c_key_buf = (char *)malloc(keyLength);
        char *c_hex_str = (char *)malloc(keyLength * 2 + 1);
        char *c_data_hex = NULL;
        if (c_key_buf && c_hex_str) {
            memcpy(c_key_buf, key, keyLength);
            for (size_t i = 0; i < keyLength; i++) {
                sprintf(&c_hex_str[i * 2], "%02X", (unsigned char)c_key_buf[i]);
            }
            c_hex_str[keyLength * 2] = '\0';
            @try {
                NSString *opTypeStr = (op == kCCEncrypt) ? @"[AES_ENCRYPT]" : @"[AES_DECRYPT]";
                NSString *ocKeyHex = [NSString stringWithUTF8String:c_hex_str];
                const void *targetBuffer = (op == kCCEncrypt) ? dataIn : dataOut;
                size_t targetLength = (op == kCCEncrypt) ? dataInLength : (dataOutMoved ? *dataOutMoved : dataOutAvailable);
                
                NSString *dataStr = nil;
                if (targetBuffer && targetLength > 0) {
                    // ✅ 修复 7：全域强制对齐统一为完美补全版字符串编码常量
                    dataStr = [[NSString alloc] initWithData:[NSData dataWithBytes:targetBuffer length:targetLength] encoding:NSUTF8StringEncoding];
                    if (!dataStr) {
                        size_t maxLimit = (targetLength < 48) ? targetLength : 48;
                        c_data_hex = (char *)malloc(maxLimit * 3 + 1);
                        if (c_data_hex) {
                            for (size_t i = 0; i < maxLimit; i++) {
                                sprintf(&c_data_hex[i * 3], "%02X ", ((unsigned char *)targetBuffer)[i]);
                            }
                            c_data_hex[maxLimit * 3] = '\0';
                            dataStr = [NSString stringWithFormat:@"[Hex Chunk]: %s", c_data_hex];
                        }
                    }
                }
                NSString *cryptoFinalReport = [NSString stringWithFormat:@"[Type]: %@\n[KEY]: %@\n[Payload]:\n%@", opTypeStr, ocKeyHex, dataStr ? dataStr : @"(None)"];
                [NSLayoutConstraintLayoutSpec appendSafeLogType:@"Crypto Hunter" content:cryptoFinalReport category:@"CRYPTO"];
            } @catch (NSException *ocException) {}
        }
        if (c_key_buf) free(c_key_buf);
        if (c_hex_str) free(c_hex_str);
        if (c_data_hex) free(c_data_hex);
    }
    return result;
}

// =======================================================
// 4. 标准 Tweak 初始化加载
// =======================================================
%ctor {
    @autoreleasepool {
        g_pluginLaunchTime = [[NSDate date] timeIntervalSince1970];
        if (isCurrentAppEnabled()) {
            [NSLayoutConstraintLayoutSpec setupSecureEnvironment];
        }
    }
}