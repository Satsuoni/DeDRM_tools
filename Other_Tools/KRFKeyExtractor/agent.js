import Java from 'frida-java-bridge';

const byteToHex = [];

for (let n = 0; n <= 0xff; ++n)
{
    const hexOctet = n.toString(16).padStart(2, "0");
    byteToHex.push(hexOctet);
}

function hex(arrayBuffer)
{
    const buff = new Uint8Array(arrayBuffer);
    const hexOctets = []; // new Array(buff.length) is even faster (preallocates necessary array size), then use hexOctets[i] instead of .push()

    for (let i = 0; i < buff.length; ++i)
        hexOctets.push(byteToHex[buff[i]]);

    return hexOctets.join("");
}


function str(obj)
{
return obj.toString();
}
let mallocPtr = Module.getGlobalExportByName("malloc");
let freePtr = Module.getGlobalExportByName("free");
var cfile=null;
var clist=null;
var utils=null;
var krf = null;
var ArrayList =null;
var dsn=null;
var secrs=null;
Java.perform(function () {
  
 cfile=Java.use("java.io.File");
 clist=Java.use("java.io.File");
 utils=Java.use("com.amazon.kcp.util.Utils");
 krf = Java.use("com.amazon.krf.platform.KRF");
 ArrayList = Java.use("java.util.ArrayList");
 dsn=utils.getFactory().getKindleReaderSDK().getApplicationManager().getDeviceInformation().getDeviceSerialNumber()
var sp=utils.getFactory().getAccountSecretProvider();

 secrs=sp.getAccountSecrets();
 var jssecrets = [];
    var size = secrs.size();
    for (var i = 0; i < size; i++) {
        var item = secrs.get(i);
        // Use .toString() or specific field access if items are objects
        jssecrets.push(item.toString()); 
    }
    
   var ActivityThread = Java.use('android.app.ActivityThread');
   var currentApplication = ActivityThread.currentApplication();
   var context = currentApplication.getApplicationContext();
   console.log("App Context: " + context);
    
    console.log(context.getApplicationInfo().nativeLibraryDir);
    var liblist=ArrayList.$new();
    liblist.add(context.getApplicationInfo().nativeLibraryDir.value);
    krf.initKRF(liblist);
  send({msg:"ready",dsn:dsn,secrets:jssecrets});
})


function openBook(bookMessage)
{

Java.perform(function () {
 const allocations={};
 var bkfl=cfile.$new("/storage/emulated/0/Android/data/com.amazon.kindle/files/"+bookMessage.bookFile);///B08XZRCSWS/CR!2ZWXQ3N96S5QQ3WH9418AC6DE9MZ.kfx")
 var emptyList=ArrayList.$new();
var voucherList=ArrayList.$new();
bookMessage.vouchers.forEach((voucher) => 
{
var bkvch=cfile.$new("/storage/emulated/0/Android/data/com.amazon.kindle/files/"+voucher);//B08XZRCSWS/amzn1.drm-voucher.v1.5fe7146c-e3b1-4841-ab4c-3c305bcaa77a.ast")
  voucherList.add(bkvch);
}
);

//openBook(file, secrets, dsn, vouchers, containers);
var allocListener=Interceptor.attach(mallocPtr, 
{
onEnter (args) {
this.sz=parseInt(args[0],16);
},
onLeave(retval) {
  if (this.sz==16)
     allocations[str(retval)]=this.sz;
}
});

var freeListener=Interceptor.attach(freePtr, 
{
  onEnter (args) {
    if(args[0]!==0)
    {
    let addr=str(args[0]);
    if (addr in allocations) {
        
        let ln=allocations[addr];
        if (ln===16) 
       {
         let p=new NativePointer(addr);
         let arr=p.readByteArray(ln);
       //console.log(hex(arr));
        send("mem",arr);
        }
        delete allocations[addr];
        }
    }
  }
})

var book=krf.openBook(bkfl,secrs ,dsn,voucherList,emptyList);

//console.log("meh");
//console.log(book.class);

//console.log(Object.keys(allocations).length);
Object.keys(allocations).forEach(key => {
  //console.log(key, allocations[key]);
  if (allocations[key]==16)
  {
    let p=new NativePointer(key);
    let arr=p.readByteArray(16);
    send("mem",arr);
  }
});
freeListener.detach();
allocListener.detach();
send("done");
}); 
recv('book', openBook);
}
recv('book', openBook);
