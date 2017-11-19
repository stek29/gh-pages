// frida -ql buros.js 'System Information'

function makeNSString(str) {
    return ObjC.classes.NSString.stringWithUTF8String_(Memory.allocUtf8String(str));
}

var view = ObjC.classes.NSApplication.sharedApplication().windows().objectAtIndex_(0).contentView();
var msgsend = new NativeFunction(Module.findExportByName(null, "objc_msgSend"), "pointer", ["pointer", "pointer"]);
var sel = ObjC.selector("_subtreeDescription");

var desc = ObjC.Object(msgsend(view, sel)).UTF8String();

var match = desc.match(/(0x[01-9a-fA-F]+) "macOS High Sierra"/);
var textview = ObjC.Object(ptr(match[1]));
textview.setStringValue_(makeNSString("BurOS High Ramenskoe"));

var matchimg = desc.match(/NSImageView (0x[\da-fA-F]+).*Name=SystemLogo/)
var imgview = ObjC.Object(ptr(matchimg[1]));

var burosurl = ObjC.classes.NSURL.URLWithString_(
    makeNSString("https://stek29.rocks/assets/buros/logo.png")
);

var burosimg = ObjC.classes.NSImage.alloc().initWithContentsOfURL_(burosurl);
imgview.performSelectorOnMainThread_withObject_waitUntilDone_(
    ObjC.selector("setImage:"),
    burosimg,
    true);

