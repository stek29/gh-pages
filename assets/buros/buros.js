// frida -ql buros.js 'System Information'

function makeNSString(str) {
    var char_p = Memory.allocUtf8String(str);
    ret = ObjC.classes.NSString.stringWithUTF8String_(char_p);
    return ObjC.Object(ret);
}

var view = ObjC.classes.NSApplication.sharedApplication().windows().objectAtIndex_(0).contentView();
var msgsend = new NativeFunction(Module.findExportByName(null, "objc_msgSend"), "pointer", ["pointer", "pointer"]);
var sel = ObjC.selector("_subtreeDescription");

var desc = ObjC.Object(msgsend(view, sel)).UTF8String();

const orig_os_major = "macOS";
const orig_os_minor = "High Sierra";

var match = desc.match('(0x[01-9a-fA-F]+) "' + orig_os_major + ' ' + orig_os_minor + '"');
var textfield = ObjC.Object(ptr(match[1]));

var orig = textfield.attributedStringValue();
mac_font = orig.attributesAtIndex_effectiveRange_(0, NULL).allObjects().objectAtIndex_(0);
high_font = orig.attributesAtIndex_effectiveRange_(orig_os_major.length + 2, NULL).allObjects().objectAtIndex_(0);

const os_major = "BurOS";
const os_minor = "High Ramenskoe";

var new_str = ObjC.classes.NSMutableAttributedString.alloc().initWithString_(makeNSString(os_major + " " + os_minor));
const NSDictionary = ObjC.classes.NSDictionary;
new_str.setAttributes_range_(
    NSDictionary.dictionaryWithObject_forKey_(
        mac_font, makeNSString("NSFont")
    ), [0, os_major.length]);

new_str.setAttributes_range_(
    NSDictionary.dictionaryWithObject_forKey_(
        high_font, makeNSString("NSFont")
    ), [os_major.length + 1, os_minor.length]);

textfield.setAttributedStringValue_(new_str);

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

