#import <Security/SecureTransport.h>

// Hook SSLSetSessionOption()
static OSStatus replaced_SSLSetSessionOption(
    SSLContextRef context, 
    SSLSessionOption option, 
    Boolean value) {

    // Remove the ability to modify the value of the kSSLSessionOptionBreakOnServerAuth option
    if (option == kSSLSessionOptionBreakOnServerAuth)
        return noErr;
    else
        return SSLSetSessionOption(context, option, value);
}


// Hook SSLCreateContext()
static SSLContextRef replaced_SSLCreateContext (
   CFAllocatorRef alloc,
   SSLProtocolSide protocolSide,
   SSLConnectionType connectionType
) {
    SSLContextRef sslContext = SSLCreateContext(alloc, protocolSide, connectionType);
    
    // Immediately set the kSSLSessionOptionBreakOnServerAuth option in order to disable cert validation
    SSLSetSessionOption(sslContext, kSSLSessionOptionBreakOnServerAuth, true);
    return sslContext;
}


// Hook SSLHandshake()
static OSStatus replaced_SSLHandshake(
    SSLContextRef context
) {
    OSStatus result = SSLHandshake(context);

    // Hijack the flow when breaking on server authentication
    if (result == errSSLServerAuthCompleted) {
        // Do not check the cert and call SSLHandshake() again
        return SSLHandshake(context);
    }
    else
        return result;
}

#define DYLD_INTERPOSE(_replacment,_replacee) \
   __attribute__((used)) static struct{ const void* replacment; const void* replacee; } _interpose_##_replacee \
            __attribute__ ((section ("__DATA,__interpose"))) = { (const void*)(unsigned long)&_replacment, (const void*)(unsigned         long)&_replacee };

DYLD_INTERPOSE(replaced_SSLSetSessionOption, SSLSetSessionOption)
DYLD_INTERPOSE(replaced_SSLCreateContext, SSLCreateContext)
DYLD_INTERPOSE(replaced_SSLHandshake, SSLHandshake)
