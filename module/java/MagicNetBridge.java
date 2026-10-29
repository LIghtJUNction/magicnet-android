import java.lang.reflect.*;
import java.util.*;

/** Reflection keeps build tools independent of an Android SDK. All privileged
 * writes are invoked only by the Go controller after durable candidate checks. */
public final class MagicNetBridge {
  static Object call(Object o,String n,Object... args) throws Exception {
    for(Method m:o.getClass().getMethods()) if(m.getName().equals(n)&&m.getParameterCount()==args.length) {
      try {m.setAccessible(true);return m.invoke(o,args);} catch(IllegalArgumentException e){}
    }
    throw new NoSuchMethodException(n);
  }
  static Object service() throws Exception {
    Class<?> sm=Class.forName("android.os.ServiceManager");
    Object binder=sm.getMethod("getService",String.class).invoke(null,"netpolicy");
    if(binder==null)throw new IllegalStateException("provider_missing");
    Class<?> stub=Class.forName("android.net.INetworkPolicyManager$Stub");
    return stub.getMethod("asInterface",Class.forName("android.os.IBinder")).invoke(null,binder);
  }
  static Object context() throws Exception {
    Class<?> at=Class.forName("android.app.ActivityThread");
    Object thread=at.getMethod("systemMain").invoke(null);
    return at.getMethod("getSystemContext").invoke(thread);
  }
  static Object pm()throws Exception{return call(context(),"getPackageManager");}
  static String quote(String s){StringBuilder b=new StringBuilder("\"");for(char c:s.toCharArray()){if(c=='"'||c=='\\')b.append('\\').append(c);else if(c<32)b.append(String.format("\\u%04x",(int)c));else b.append(c);}return b.append('"').toString();}
  static String packages(Object manager,int uid)throws Exception {
    String[] p=(String[])call(manager,"getPackagesForUid",uid);if(p==null)p=new String[0];Arrays.sort(p);StringJoiner j=new StringJoiner(",","[","]");for(String s:p)j.add(quote(s));return j.toString();
  }
  static String catalog()throws Exception {
    Object manager=pm();Object list=call(manager,"getInstalledApplications",0);if(!(list instanceof List))throw new IllegalStateException("catalog_invalid");
    StringJoiner rows=new StringJoiner(",","[","]");int count=0;for(Object app:(List<?>)list){if(++count>4096)throw new IllegalStateException("catalog_limit");String name=(String)app.getClass().getField("packageName").get(app);int uid=app.getClass().getField("uid").getInt(app);if(uid>=100000)continue;String label=name;try{Object x=call(app,"loadLabel",manager);if(x!=null)label=x.toString();}catch(Exception e){}rows.add("{\"packageName\":"+quote(name)+",\"appLabel\":"+quote(label)+"}");}
    return "{\"schema\":1,\"scope\":\"owner_user\",\"packages\":"+rows+"}";
  }
  public static void main(String[] args){try{
    String output;if(args.length==1&&args[0].equals("catalog")){output=catalog();}
    else {Object provider=service();if(args.length==1&&args[0].equals("network-inspect")){
      Object manager=pm();Set<Integer> ids=new TreeSet<>();for(int mask:new int[]{1}){int[] x=(int[])call(provider,"getUidsWithPolicy",mask);for(int uid:x)ids.add(uid);}
      if(ids.size()>128)throw new IllegalStateException("identity_limit");StringJoiner rows=new StringJoiner(",","[","]");for(int uid:ids){int policy=((Number)call(provider,"getUidPolicy",uid)).intValue();if((policy&1)==0)continue;rows.add("{\"uid\":"+uid+",\"user\":"+(uid/100000)+",\"policy\":"+policy+",\"packages\":"+packages(manager,uid)+"}");}output="{\"provider\":\"aosp\",\"records\":"+rows+"}";
    }else if(args.length==2&&args[0].equals("network-get")){int uid=Integer.parseInt(args[1]);int policy=((Number)call(provider,"getUidPolicy",uid)).intValue();output="{\"uid\":"+uid+",\"user\":"+(uid/100000)+",\"policy\":"+policy+",\"packages\":"+packages(pm(),uid)+"}";
    }else if(args.length==3&&args[0].equals("network-set")){int uid=Integer.parseInt(args[1]),policy=Integer.parseInt(args[2]);if(uid<0||policy<0)throw new IllegalArgumentException();call(provider,"setUidPolicy",uid,policy);output="{\"written\":true}";
    }else throw new IllegalArgumentException();}
    String result="{\"ok\":true,\"data\":"+output+"}";if(result.getBytes("UTF-8").length>524288)throw new IllegalStateException("output_limit");System.out.println(result);
  }catch(Throwable e){System.out.println("{\"ok\":false,\"error\":\"provider_unavailable\"}");System.exit(1);}}
}
