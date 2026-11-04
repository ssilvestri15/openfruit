// OPENFRUIT preview agent. Linked into an application only by
// `openfruit build --preview`; ordinary builds and signed releases never
// contain it.
//
// It captures the application's key window, encodes it as H.264 with the
// device's hardware encoder and serves the stream to one client on a TCP port
// bound to the device's loopback interface. The host reaches that port through
// usbmux (`openfruit device preview`).
//
// Stream (all integers little-endian):
//   header  "OFPV" u32 version(1)
//   message u32 type, u32 length, payload
//     type 1 video: u64 presentation_us, u8 keyframe, u16 width, u16 height,
//                   Annex B H.264 access unit (parameter sets on keyframes)

#import <UIKit/UIKit.h>
#import <QuartzCore/QuartzCore.h>
#import <VideoToolbox/VideoToolbox.h>
#import <CoreMedia/CoreMedia.h>
#import <CoreVideo/CoreVideo.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

static const uint16_t kOFPreviewPort = 47101;
static const int kOFFramesPerSecond = 30;
static const int kOFMaxFramesInFlight = 2;

@interface OpenFruitPreviewAgent : NSObject
@property(nonatomic) int listener;
@property(nonatomic) int client;
@property(nonatomic, strong) dispatch_queue_t networkQueue;
@property(nonatomic, strong) CADisplayLink *displayLink;
@property(nonatomic) VTCompressionSessionRef session;
@property(nonatomic) CGSize encodedSize;
@property(nonatomic) int framesInFlight;
@property(nonatomic) BOOL forceKeyframe;
@end

static void OFWriteLE(NSMutableData *data, uint64_t value, size_t bytes) {
    for (size_t i = 0; i < bytes; ++i) {
        uint8_t byte = (uint8_t)(value >> (8 * i));
        [data appendBytes:&byte length:1];
    }
}

static void OFCompressionDone(void *refcon, void *frameRefcon, OSStatus status,
                              VTEncodeInfoFlags flags, CMSampleBufferRef sample);

@implementation OpenFruitPreviewAgent

+ (instancetype)shared {
    static OpenFruitPreviewAgent *agent;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ agent = [OpenFruitPreviewAgent new]; });
    return agent;
}

- (instancetype)init {
    if ((self = [super init])) {
        _listener = -1;
        _client = -1;
        _networkQueue = dispatch_queue_create("openfruit.preview.network", DISPATCH_QUEUE_SERIAL);
    }
    return self;
}

- (void)start {
    int listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener < 0) { NSLog(@"OPENFRUIT preview: socket failed (%d)", errno); return; }
    int yes = 1;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    struct sockaddr_in address = {0};
    address.sin_len = sizeof(address);
    address.sin_family = AF_INET;
    address.sin_port = htons(kOFPreviewPort);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0 || listen(listener, 1) != 0) {
        NSLog(@"OPENFRUIT preview: cannot listen on 127.0.0.1:%u (%d)", kOFPreviewPort, errno);
        close(listener);
        return;
    }
    self.listener = listener;
    NSLog(@"OPENFRUIT preview: listening on 127.0.0.1:%u", kOFPreviewPort);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{ [self acceptLoop]; });
}

- (void)acceptLoop {
    for (;;) {
        int client = accept(self.listener, NULL, NULL);
        if (client < 0) { if (errno == EINTR) continue; return; }
        int yes = 1;
        setsockopt(client, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));
        setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, &yes, sizeof(yes));
        dispatch_async(dispatch_get_main_queue(), ^{ [self attachClient:client]; });
    }
}

- (void)attachClient:(int)client {
    [self detachClient];
    self.client = client;
    NSMutableData *header = [NSMutableData dataWithBytes:"OFPV" length:4];
    OFWriteLE(header, 1, 4);
    [self send:header];
    self.forceKeyframe = YES;
    self.displayLink = [CADisplayLink displayLinkWithTarget:self selector:@selector(tick:)];
    self.displayLink.preferredFramesPerSecond = kOFFramesPerSecond;
    [self.displayLink addToRunLoop:[NSRunLoop mainRunLoop] forMode:NSRunLoopCommonModes];
}

- (void)detachClient {
    [self.displayLink invalidate];
    self.displayLink = nil;
    int client = self.client;
    self.client = -1;
    if (client >= 0) dispatch_async(self.networkQueue, ^{ close(client); });
}

- (void)send:(NSData *)data {
    int client = self.client;
    dispatch_async(self.networkQueue, ^{
        const uint8_t *bytes = data.bytes;
        size_t remaining = data.length;
        while (remaining > 0) {
            ssize_t written = write(client, bytes, remaining);
            if (written <= 0) {
                if (written < 0 && errno == EINTR) continue;
                dispatch_async(dispatch_get_main_queue(), ^{ if (self.client == client) [self detachClient]; });
                return;
            }
            bytes += written;
            remaining -= (size_t)written;
        }
    });
}

- (UIWindow *)keyWindow {
    for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
        if (![scene isKindOfClass:UIWindowScene.class] || scene.activationState != UISceneActivationStateForegroundActive) continue;
        for (UIWindow *window in ((UIWindowScene *)scene).windows) if (window.isKeyWindow) return window;
    }
    return nil;
}

- (BOOL)prepareSessionForSize:(CGSize)size {
    if (self.session && CGSizeEqualToSize(size, self.encodedSize)) return YES;
    if (self.session) {
        VTCompressionSessionInvalidate(self.session);
        CFRelease(self.session);
        self.session = NULL;
    }
    VTCompressionSessionRef session = NULL;
    NSDictionary *source = @{
        (id)kCVPixelBufferPixelFormatTypeKey: @(kCVPixelFormatType_32BGRA),
        (id)kCVPixelBufferIOSurfacePropertiesKey: @{},
        (id)kCVPixelBufferCGBitmapContextCompatibilityKey: @YES,
    };
    OSStatus status = VTCompressionSessionCreate(NULL, (int32_t)size.width, (int32_t)size.height,
        kCMVideoCodecType_H264, NULL, (__bridge CFDictionaryRef)source, NULL,
        OFCompressionDone, (__bridge void *)self, &session);
    if (status != noErr) { NSLog(@"OPENFRUIT preview: encoder unavailable (%d)", (int)status); return NO; }
    VTSessionSetProperty(session, kVTCompressionPropertyKey_RealTime, kCFBooleanTrue);
    VTSessionSetProperty(session, kVTCompressionPropertyKey_AllowFrameReordering, kCFBooleanFalse);
    VTSessionSetProperty(session, kVTCompressionPropertyKey_ProfileLevel, kVTProfileLevel_H264_Main_AutoLevel);
    VTSessionSetProperty(session, kVTCompressionPropertyKey_MaxKeyFrameInterval, (__bridge CFTypeRef)@(kOFFramesPerSecond * 2));
    VTSessionSetProperty(session, kVTCompressionPropertyKey_AverageBitRate, (__bridge CFTypeRef)@(6000000));
    VTCompressionSessionPrepareToEncodeFrames(session);
    self.session = session;
    self.encodedSize = size;
    self.forceKeyframe = YES;
    return YES;
}

- (void)tick:(CADisplayLink *)link {
    if (self.client < 0 || self.framesInFlight >= kOFMaxFramesInFlight) return;
    UIWindow *window = [self keyWindow];
    if (!window) return;
    const CGSize points = window.bounds.size;
    const CGFloat scale = MIN(window.screen.scale, 2.0);
    // H.264 needs even dimensions.
    const CGSize size = CGSizeMake(floor(points.width * scale / 2) * 2, floor(points.height * scale / 2) * 2);
    if (size.width < 16 || size.height < 16 || ![self prepareSessionForSize:size]) return;

    CVPixelBufferPoolRef pool = VTCompressionSessionGetPixelBufferPool(self.session);
    CVPixelBufferRef buffer = NULL;
    if (!pool || CVPixelBufferPoolCreatePixelBuffer(NULL, pool, &buffer) != kCVReturnSuccess) return;
    CVPixelBufferLockBaseAddress(buffer, 0);
    CGColorSpaceRef space = CGColorSpaceCreateDeviceRGB();
    CGContextRef context = CGBitmapContextCreate(CVPixelBufferGetBaseAddress(buffer), size.width, size.height, 8,
        CVPixelBufferGetBytesPerRow(buffer), space, kCGImageAlphaPremultipliedFirst | kCGBitmapByteOrder32Little);
    CGColorSpaceRelease(space);
    if (context) {
        CGContextTranslateCTM(context, 0, size.height);
        CGContextScaleCTM(context, size.width / points.width, -size.height / points.height);
        UIGraphicsPushContext(context);
        [window drawViewHierarchyInRect:window.bounds afterScreenUpdates:NO];
        UIGraphicsPopContext();
        CGContextRelease(context);
    }
    CVPixelBufferUnlockBaseAddress(buffer, 0);

    NSDictionary *options = self.forceKeyframe ? @{(id)kVTEncodeFrameOptionKey_ForceKeyFrame: @YES} : nil;
    self.forceKeyframe = NO;
    const CMTime time = CMTimeMakeWithSeconds(link.timestamp, 1000000);
    self.framesInFlight += 1;
    if (VTCompressionSessionEncodeFrame(self.session, buffer, time, kCMTimeInvalid,
            (__bridge CFDictionaryRef)options, NULL, NULL) != noErr) self.framesInFlight -= 1;
    CVPixelBufferRelease(buffer);
}

- (void)encoded:(CMSampleBufferRef)sample {
    dispatch_async(dispatch_get_main_queue(), ^{ self.framesInFlight = MAX(0, self.framesInFlight - 1); });
    if (!sample || !CMSampleBufferDataIsReady(sample) || self.client < 0) return;
    CFArrayRef attachments = CMSampleBufferGetSampleAttachmentsArray(sample, false);
    BOOL keyframe = YES;
    if (attachments && CFArrayGetCount(attachments) > 0) {
        CFDictionaryRef first = CFArrayGetValueAtIndex(attachments, 0);
        keyframe = !CFDictionaryContainsKey(first, kCMSampleAttachmentKey_NotSync);
    }
    static const uint8_t startCode[4] = {0, 0, 0, 1};
    NSMutableData *unit = [NSMutableData data];
    CMFormatDescriptionRef format = CMSampleBufferGetFormatDescription(sample);
    if (keyframe && format) {
        size_t count = 0;
        CMVideoFormatDescriptionGetH264ParameterSetAtIndex(format, 0, NULL, NULL, &count, NULL);
        for (size_t i = 0; i < count; ++i) {
            const uint8_t *set = NULL; size_t length = 0;
            if (CMVideoFormatDescriptionGetH264ParameterSetAtIndex(format, i, &set, &length, NULL, NULL) == noErr) {
                [unit appendBytes:startCode length:4];
                [unit appendBytes:set length:length];
            }
        }
    }
    // VideoToolbox emits AVCC (4-byte big-endian lengths); the stream is Annex B.
    CMBlockBufferRef block = CMSampleBufferGetDataBuffer(sample);
    size_t total = 0; char *pointer = NULL;
    if (!block || CMBlockBufferGetDataPointer(block, 0, NULL, &total, &pointer) != kCMBlockBufferNoErr) return;
    size_t offset = 0;
    while (offset + 4 <= total) {
        uint32_t length = 0;
        memcpy(&length, pointer + offset, 4);
        length = CFSwapInt32BigToHost(length);
        offset += 4;
        if (length > total - offset) break;
        [unit appendBytes:startCode length:4];
        [unit appendBytes:pointer + offset length:length];
        offset += length;
    }
    const CMTime time = CMSampleBufferGetPresentationTimeStamp(sample);
    NSMutableData *message = [NSMutableData data];
    OFWriteLE(message, 1, 4);
    OFWriteLE(message, 8 + 1 + 2 + 2 + unit.length, 4);
    OFWriteLE(message, (uint64_t)(CMTimeGetSeconds(time) * 1000000.0), 8);
    OFWriteLE(message, keyframe ? 1 : 0, 1);
    OFWriteLE(message, (uint64_t)self.encodedSize.width, 2);
    OFWriteLE(message, (uint64_t)self.encodedSize.height, 2);
    [message appendData:unit];
    [self send:message];
}

@end

static void OFCompressionDone(void *refcon, void *frameRefcon, OSStatus status,
                              VTEncodeInfoFlags flags, CMSampleBufferRef sample) {
    (void)frameRefcon; (void)flags;
    OpenFruitPreviewAgent *agent = (__bridge OpenFruitPreviewAgent *)refcon;
    [agent encoded:status == noErr ? sample : NULL];
}

__attribute__((constructor)) static void OFPreviewAgentLoad(void) {
    // Applications only: app extensions share the binary layout but not the UI.
    if (![NSBundle.mainBundle.bundlePath hasSuffix:@".app"]) return;
    __block id observer = [NSNotificationCenter.defaultCenter
        addObserverForName:UIApplicationDidFinishLaunchingNotification object:nil
                     queue:NSOperationQueue.mainQueue usingBlock:^(NSNotification *note) {
        (void)note;
        [NSNotificationCenter.defaultCenter removeObserver:observer];
        [[OpenFruitPreviewAgent shared] start];
    }];
}
