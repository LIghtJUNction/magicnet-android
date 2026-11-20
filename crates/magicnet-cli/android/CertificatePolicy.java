package io.github.magicnet;

import java.io.*;
import java.nio.channels.*;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.util.*;

/** Local root script backend; no private keys, network requests or CA injection. */
public final class CertificatePolicy {
    private final Path module, store, removed, journal, config;
    CertificatePolicy(Path module, Path store, Path removed) throws Exception {
        this.module=module; this.store=store; this.removed=removed;
        journal=module.resolve(".state/certificate-policy/owned");
        config=module.resolve(".config/magicnet/certificate-policy");
        for(Path p:Arrays.asList(module.resolve(".state"),module.resolve(".state/certificate-policy"),journal,
                module.resolve(".config"),module.resolve(".config/magicnet"),config,removed)) {
            if(Files.isSymbolicLink(p)) throw new IOException("unsafe policy directory");
        }
        Files.createDirectories(journal); Files.createDirectories(config);
    }
    static byte[] read(Path p) throws Exception {
        if (Files.isSymbolicLink(p) || !Files.isRegularFile(p, LinkOption.NOFOLLOW_LINKS))
            throw new IOException("unsafe certificate file");
        if (Files.size(p)>65536) throw new IOException("oversized certificate file");
        return Files.readAllBytes(p);
    }
    static void atomic(Path p, byte[] bytes) throws Exception {
        if (Files.isSymbolicLink(p)) throw new IOException("unsafe destination");
        Path temp=Files.createTempFile(p.getParent(), ".certificate-", ".tmp");
        try {
            try (FileOutputStream f=new FileOutputStream(temp.toFile())) {
                f.write(bytes); f.getFD().sync();
                if(!temp.toFile().setReadable(true,false)) throw new IOException("certificate permissions");
            }
            Files.move(temp,p,StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);
        } finally { Files.deleteIfExists(temp); }
    }
    static String fingerprint(X509Certificate c) throws Exception {
        StringBuilder s=new StringBuilder();
        for(byte b:MessageDigest.getInstance("SHA-256").digest(c.getEncoded()))
            s.append(String.format(Locale.ROOT,"%02x",b&255));
        return s.toString();
    }
    static List<String> lines(Path p) throws Exception {
        List<String> result=new ArrayList<>();
        if (!Files.exists(p)) return result;
        for(String line:new String(read(p),"UTF-8").split("\\r?\\n")) {
            line=line.trim(); if(!line.isEmpty()&&!line.startsWith("#")) result.add(line);
        }
        return result;
    }
    static boolean matches(String subject,String sha,List<String> rules) throws Exception {
        for(String rule:rules) {
            int i=rule.indexOf('='); if(i<1) throw new IOException("invalid match rule");
            String kind=rule.substring(0,i),value=rule.substring(i+1).trim();
            if(value.isEmpty()) throw new IOException("empty match rule");
            if(kind.equals("sha256")) {
                value=value.replace(":","").toLowerCase(Locale.ROOT);
                if(!value.matches("[0-9a-f]{64}")) throw new IOException("invalid fingerprint");
                if(value.equals(sha)) return true;
            } else if(kind.equals("subject")) {
                if(subject.equals(value)) return true;
            } else if(kind.equals("keyword")) {
                if(subject.toLowerCase(Locale.ROOT).contains(value.toLowerCase(Locale.ROOT))) return true;
            } else throw new IOException("unknown match rule");
        }
        return false;
    }
    void publish(String phase,int matched,int owned) throws Exception {
        Path dir=module.resolve(".state/machines"); Files.createDirectories(dir);
        atomic(dir.resolve("certificate-policy.state"),("schema=1\nphase="+phase+
            "\nmatched="+matched+"\nowned="+owned+"\n").getBytes("UTF-8"));
    }
    void run(String action) throws Exception {
        if(!Arrays.asList("apply","disable","restore","status","preview").contains(action))
            throw new IOException("usage: certificate-policy apply|disable|restore|status|preview");
        Path intent=config.resolve("enabled");
        if(action.equals("restore")) atomic(intent,"false\n".getBytes("UTF-8"));
        if(action.equals("disable")) atomic(intent,"true\n".getBytes("UTF-8"));
        String value=Files.exists(intent)?new String(read(intent),"UTF-8").trim():"false";
        if(!value.equals("true")&&!value.equals("false")) throw new IOException("invalid enabled intent");
        boolean enabled=value.equals("true");
        if(action.equals("status")) {
            System.out.println("configured="+enabled);
            Path state=module.resolve(".state/machines/certificate-policy.state");
            if(Files.exists(state)) System.out.print(new String(read(state),"UTF-8"));
            else System.out.println("phase=unknown");
            return;
        }
        List<String> rules=lines(config.resolve("rules"));
        if(enabled&&rules.isEmpty()) throw new IOException("missing certificate rules");
        for(String rule:rules) matches("", "", Collections.singletonList(rule));
        // Parse the complete store before modifying any trust state.
        Map<String,byte[]> targets=new TreeMap<>();
        CertificateFactory factory=CertificateFactory.getInstance("X.509");
        if(enabled || action.equals("preview")) try(DirectoryStream<Path> files=Files.newDirectoryStream(store)) {
            for(Path p:files) {
                String name=p.getFileName().toString(); if(!name.matches("[0-9a-f]{8}\\.[0-9]+")) continue;
                byte[] bytes=read(p);
                X509Certificate cert=(X509Certificate)factory.generateCertificate(new ByteArrayInputStream(bytes));
                String subject=cert.getSubjectX500Principal().getName("RFC2253"),sha=fingerprint(cert);
                if(matches(subject,sha,rules)) {
                    targets.put(name,bytes);
                    if(action.equals("preview")) System.out.println(name+" sha256="+sha+" subject="+subject);
                }
            }
        }
        if(action.equals("preview")) {System.out.println("matched="+targets.size());return;}
        publish("pending",targets.size(),0);
        Files.createDirectories(removed);
        // A write-ahead copy establishes ownership before the disabled marker is created.
        try(DirectoryStream<Path> files=Files.newDirectoryStream(journal)) {
            for(Path p:files) {
                String name=p.getFileName().toString();
                if(!name.matches("[0-9a-f]{8}\\.[0-9]+")) continue;
                byte[] owned=read(p); Path dest=removed.resolve(name);
                if(enabled&&targets.containsKey(name)&&Arrays.equals(owned,targets.get(name))) continue;
                if(Files.exists(dest,LinkOption.NOFOLLOW_LINKS)) {
                    if(!Arrays.equals(read(dest),owned)) throw new IOException("disabled marker changed; recovery retained");
                    Files.delete(dest);
                }
                Files.delete(p);
            }
        }
        int count=0;
        if(enabled) for(Map.Entry<String,byte[]> e:targets.entrySet()) {
            Path dest=removed.resolve(e.getKey()),owner=journal.resolve(e.getKey());
            if(Files.exists(dest,LinkOption.NOFOLLOW_LINKS)) {
                if(!Arrays.equals(read(dest),e.getValue())) throw new IOException("conflicting disabled certificate");
                if(Files.exists(owner)) count++;
                continue; // Preserve pre-existing user disables without claiming ownership.
            }
            atomic(owner,e.getValue()); atomic(dest,e.getValue()); count++;
        }
        publish(enabled?"disabled":"restored",targets.size(),count);
        System.out.println("phase="+(enabled?"disabled":"restored")+" matched="+targets.size()+" owned="+count);
    }
    public static void main(String[] args) throws Exception {
        if(args.length!=4) throw new IOException("expected module store removed action");
        CertificatePolicy p=new CertificatePolicy(Paths.get(args[0]),Paths.get(args[1]),Paths.get(args[2]));
        try(RandomAccessFile f=new RandomAccessFile(p.journal.getParent().resolve("lock").toFile(),"rw");
            FileChannel ch=f.getChannel(); FileLock lock=ch.tryLock()) {
            if(lock==null) throw new IOException("certificate policy busy");
            p.run(args[3]);
        }
    }
}
